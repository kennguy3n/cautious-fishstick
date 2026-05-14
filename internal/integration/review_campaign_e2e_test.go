package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// alwaysCertifyAutomator is a deterministic ReviewAutomator that
// certifies every decision presented to it. Used in the E2E test
// below to drive the auto-certification leg of the lifecycle
// without needing the AI agent.
type alwaysCertifyAutomator struct{}

func (alwaysCertifyAutomator) AutomateReview(_ context.Context, _ aiclient.ReviewAutomationPayload) (string, string, bool) {
	return "certify", "automated approval (E2E test)", true
}

// TestReviewCampaign_E2E_FullLifecycle exercises the campaign
// lifecycle through the real Gin router and a real
// AccessReviewService + AccessProvisioningService:
//
//   POST /access/reviews → StartCampaign (auto-cert enabled)
//   AutomateReview runs against the supplied automator → some rows
//     end up auto-certified
//   POST /access/reviews/:id/decisions → SubmitDecision (revoke)
//   POST /access/reviews/:id/auto-revoke → revoke any remaining
//     pending decisions and call connector.RevokeAccess
//   GET  /access/reviews/:id/metrics → CampaignMetrics
//   POST /access/reviews/:id/close → CloseCampaign
//
// The MockAccessConnector is the only mock; the automator is a
// real deterministic implementation.
func TestReviewCampaign_E2E_FullLifecycle(t *testing.T) {
	const provider = "test_provider_e2e_review_campaign"
	const workspaceID = "01H000000000000000WORKSPACE0"
	connectorID := "01HCONN0E2E0REVIEWCAMPAIGN001"
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)

	mock := stubAccessConnector()
	var revokeCalls int
	mock.FuncRevokeAccess = func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error {
		revokeCalls++
		return nil
	}
	access.SwapConnector(t, provider, mock)

	if err := db.Create(&models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   workspaceID,
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}

	// Seed three active grants. Two will be auto-certified by the
	// always-certify automator; the third we revoke manually.
	grants := []*models.AccessGrant{
		{ID: "01H000000000RVWE2EGRANT0001", WorkspaceID: workspaceID, UserID: "u1", ConnectorID: connectorID, ResourceExternalID: "host-a", Role: "viewer", GrantedAt: time.Now().UTC()},
		{ID: "01H000000000RVWE2EGRANT0002", WorkspaceID: workspaceID, UserID: "u2", ConnectorID: connectorID, ResourceExternalID: "host-b", Role: "viewer", GrantedAt: time.Now().UTC()},
		{ID: "01H000000000RVWE2EGRANT0003", WorkspaceID: workspaceID, UserID: "u3", ConnectorID: connectorID, ResourceExternalID: "host-c", Role: "admin", GrantedAt: time.Now().UTC()},
	}
	for _, g := range grants {
		if err := db.Create(g).Error; err != nil {
			t.Fatalf("seed grant: %v", err)
		}
	}

	provSvc := access.NewAccessProvisioningService(db)
	reviewSvc := access.NewAccessReviewService(db, provSvc)
	reviewSvc.SetReviewAutomator(alwaysCertifyAutomator{})

	router := handlers.Router(handlers.Dependencies{
		AccessReviewService: reviewSvc,
	})

	// --- Step 1: POST /access/reviews ---
	scope, _ := json.Marshal(map[string]string{"connector_id": connectorID})
	status, body := doJSON(t, router, http.MethodPost, "/access/reviews", map[string]any{
		"workspace_id":         workspaceID,
		"name":                 "Q4 Engineering Review",
		"due_at":               time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		"scope_filter":         json.RawMessage(scope),
		"auto_certify_enabled": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /access/reviews: status=%d body=%+v", status, body)
	}
	reviewObj, _ := body["review"].(map[string]any)
	reviewID, _ := reviewObj["id"].(string)
	if reviewID == "" {
		t.Fatalf("expected review.id in response: %+v", body)
	}
	decisions, _ := body["decisions"].([]any)
	if len(decisions) != 3 {
		t.Fatalf("expected 3 decisions enrolled, got %d", len(decisions))
	}

	// Auto-certification fires synchronously inside StartCampaign so
	// the DB rows for the auto-certified decisions are already updated
	// by the time the HTTP call returns.
	var autoCertified int64
	if err := db.Model(&models.AccessReviewDecision{}).
		Where("review_id = ? AND auto_certified = ?", reviewID, true).
		Count(&autoCertified).Error; err != nil {
		t.Fatalf("count auto_certified: %v", err)
	}
	if autoCertified != 3 {
		t.Fatalf("auto_certified = %d; want 3 (every row certified by always-certify automator)", autoCertified)
	}

	// --- Step 2: POST /access/reviews/:id/decisions (revoke u3's admin grant) ---
	status, _ = doJSON(t, router, http.MethodPost, "/access/reviews/"+reviewID+"/decisions", map[string]any{
		"grant_id":   grants[2].ID,
		"decision":   "revoke",
		"decided_by": "01HACTOR0REVIEWER000000001",
		"reason":     "no longer needs admin",
	})
	if status != http.StatusOK {
		t.Fatalf("SubmitDecision: status=%d", status)
	}

	// --- Step 3: POST /access/reviews/:id/auto-revoke ---
	// Drains the "revoke" decisions through AccessProvisioningService.Revoke,
	// which calls MockAccessConnector.RevokeAccess and stamps RevokedAt.
	status, _ = doJSON(t, router, http.MethodPost, "/access/reviews/"+reviewID+"/auto-revoke", nil)
	if status != http.StatusOK {
		t.Fatalf("AutoRevoke: status=%d", status)
	}
	if revokeCalls == 0 {
		t.Fatalf("connector.RevokeAccess was not called during AutoRevoke")
	}
	var revoked models.AccessGrant
	if err := db.Where("id = ?", grants[2].ID).First(&revoked).Error; err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatalf("grants[2].RevokedAt not set after AutoRevoke")
	}

	// --- Step 4: GET /access/reviews/:id/metrics ---
	status, body = doJSON(t, router, http.MethodGet, "/access/reviews/"+reviewID+"/metrics", nil)
	if status != http.StatusOK {
		t.Fatalf("metrics: status=%d body=%+v", status, body)
	}
	if total, _ := body["total_decisions"].(float64); total != 3 {
		t.Fatalf("total_decisions = %v; want 3", body["total_decisions"])
	}

	// --- Step 5: POST /access/reviews/:id/close ---
	status, _ = doJSON(t, router, http.MethodPost, "/access/reviews/"+reviewID+"/close", nil)
	if status != http.StatusOK {
		t.Fatalf("close: status=%d", status)
	}
	var closed models.AccessReview
	if err := db.Where("id = ?", reviewID).First(&closed).Error; err != nil {
		t.Fatalf("reload review: %v", err)
	}
	if closed.State != models.ReviewStateClosed {
		t.Fatalf("review.State = %q; want closed", closed.State)
	}
}

// TestReviewCampaign_E2E_SubmitDecisionOnClosedReviewFails covers the
// failure path: once a campaign is closed, SubmitDecision should
// return an error (ErrReviewClosed → 5xx) instead of silently
// mutating the decision row.
func TestReviewCampaign_E2E_SubmitDecisionOnClosedReviewFails(t *testing.T) {
	const provider = "test_provider_e2e_review_closed"
	const workspaceID = "01H000000000000000WORKSPACE0"
	connectorID := "01HCONN0E2E0REVIEWCLOSED00001"
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)
	mock := stubAccessConnector()
	access.SwapConnector(t, provider, mock)

	if err := db.Create(&models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   workspaceID,
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	if err := db.Create(&models.AccessGrant{
		ID: "01H000000000RVWCLOSED0GRANT0", WorkspaceID: workspaceID, UserID: "u1",
		ConnectorID: connectorID, ResourceExternalID: "host-a", Role: "viewer", GrantedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	provSvc := access.NewAccessProvisioningService(db)
	reviewSvc := access.NewAccessReviewService(db, provSvc)
	router := handlers.Router(handlers.Dependencies{AccessReviewService: reviewSvc})

	scope, _ := json.Marshal(map[string]string{"connector_id": connectorID})
	status, body := doJSON(t, router, http.MethodPost, "/access/reviews", map[string]any{
		"workspace_id":         workspaceID,
		"name":                 "Closed review",
		"due_at":               time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"scope_filter":         json.RawMessage(scope),
		"auto_certify_enabled": false,
	})
	if status != http.StatusCreated {
		t.Fatalf("StartCampaign: status=%d body=%+v", status, body)
	}
	reviewObj, _ := body["review"].(map[string]any)
	reviewID, _ := reviewObj["id"].(string)

	// Close it first.
	if status, _ = doJSON(t, router, http.MethodPost, "/access/reviews/"+reviewID+"/close", nil); status != http.StatusOK {
		t.Fatalf("close: status=%d", status)
	}

	// Submitting against a closed review must fail.
	status, _ = doJSON(t, router, http.MethodPost, "/access/reviews/"+reviewID+"/decisions", map[string]any{
		"grant_id":   "01H000000000RVWCLOSED0GRANT0",
		"decision":   "certify",
		"decided_by": "01HACTOR0REVIEWER000000001",
	})
	if status < 400 {
		t.Fatalf("expected 4xx/5xx on closed review, got %d", status)
	}
}
