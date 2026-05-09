package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newReviewTestDB returns a fresh in-memory SQLite DB with the Phase 2
// tables required by AccessReviewService (access_grants for the
// scope-filter expansion, access_connectors for the provisioning
// lookupProvider call) plus the Phase 5 tables themselves.
//
// Tests reuse newProvisioningTestDB's set and append Phase 5 because
// AutoRevoke and SubmitDecision-with-revoke compose
// AccessProvisioningService end-to-end.
func newReviewTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
		&models.AccessReview{},
		&models.AccessReviewDecision{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// seedActiveGrant inserts an access_grants row in active (RevokedAt
// IS NULL) state for the supplied tuple. Used by review tests that
// need to enroll grants into a campaign.
func seedActiveGrant(t *testing.T, db *gorm.DB, id, workspaceID, userID, connectorID, role, resourceExtID string) *models.AccessGrant {
	t.Helper()
	g := &models.AccessGrant{
		ID:                 id,
		WorkspaceID:        workspaceID,
		UserID:             userID,
		ConnectorID:        connectorID,
		ResourceExternalID: resourceExtID,
		Role:               role,
		GrantedAt:          time.Now().UTC(),
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed access_grant: %v", err)
	}
	return g
}

// scopeJSON marshals a flat string-keyed map into a json.RawMessage
// suitable for StartCampaignInput.ScopeFilter. Mirrors rawJSON in
// policy_service_test.go but lives next to its callers for clarity.
func scopeJSON(t *testing.T, m map[string]string) json.RawMessage {
	t.Helper()
	if m == nil {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal scope: %v", err)
	}
	return b
}

// TestStartCampaign_HappyPath asserts that StartCampaign creates the
// access_reviews row, enumerates every active grant in the workspace
// matching the scope filter, and creates a pending decision per grant.
func TestStartCampaign_HappyPath(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"

	// Two in-scope grants, one out-of-scope (different connector),
	// one already-revoked (filtered out).
	seedActiveGrant(t, db, "01H000000000000000GRANT0001", ws, "u1", conn, "admin", "host-a")
	seedActiveGrant(t, db, "01H000000000000000GRANT0002", ws, "u2", conn, "admin", "host-b")
	seedActiveGrant(t, db, "01H000000000000000GRANT0003", ws, "u3", "01H000000000000000OTHERCONN", "admin", "host-c")
	revoked := seedActiveGrant(t, db, "01H000000000000000GRANT0004", ws, "u4", conn, "admin", "host-d")
	now := time.Now().UTC()
	if err := db.Model(&models.AccessGrant{}).Where("id = ?", revoked.ID).
		Updates(map[string]interface{}{"revoked_at": now, "updated_at": now}).Error; err != nil {
		t.Fatalf("seed revoked: %v", err)
	}

	svc := NewAccessReviewService(db, nil)
	in := StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "Q1 SSH review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: true,
	}
	review, decisions, err := svc.StartCampaign(context.Background(), in)
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if review.ID == "" {
		t.Error("review.ID is empty")
	}
	if review.State != models.ReviewStateOpen {
		t.Errorf("review.State = %q; want %q", review.State, models.ReviewStateOpen)
	}
	if !review.AutoCertifyEnabled {
		t.Error("AutoCertifyEnabled = false; want true")
	}
	if len(decisions) != 2 {
		t.Fatalf("len(decisions) = %d; want 2", len(decisions))
	}
	for _, d := range decisions {
		if d.Decision != models.DecisionPending {
			t.Errorf("decision %s: got %q; want %q", d.GrantID, d.Decision, models.DecisionPending)
		}
		if d.AutoCertified {
			t.Errorf("decision %s: AutoCertified=true; want false at start", d.GrantID)
		}
		if d.DecidedAt != nil {
			t.Errorf("decision %s: DecidedAt=%v; want nil", d.GrantID, d.DecidedAt)
		}
	}
}

// TestStartCampaign_PersistsAutoCertifyDisabled is a regression test
// for the GORM zero-value pitfall: the access_reviews.auto_certify_enabled
// column carries default:true, so a struct-mode Create would skip an
// explicit false from the caller and the DB would silently flip the
// row to true. StartCampaign must persist the caller's value verbatim
// so operators who disable auto-certification get a campaign that the
// AI agent will not auto-certify.
func TestStartCampaign_PersistsAutoCertifyDisabled(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANT0010", ws, "u1", conn, "admin", "host-a")

	svc := NewAccessReviewService(db, nil)
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "Manual-only review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: false,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if review.AutoCertifyEnabled {
		t.Error("returned review.AutoCertifyEnabled = true; want false")
	}

	var got models.AccessReview
	if err := db.Where("id = ?", review.ID).First(&got).Error; err != nil {
		t.Fatalf("reload review: %v", err)
	}
	if got.AutoCertifyEnabled {
		t.Errorf("persisted auto_certify_enabled = true; want false (column default:true must not override explicit false)")
	}
}

// TestStartCampaign_ValidationFailures exercises the validation
// paths so the API layer can rely on ErrValidation as a 4xx signal.
func TestStartCampaign_ValidationFailures(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)

	cases := []struct {
		name string
		in   StartCampaignInput
	}{
		{"missing workspace", StartCampaignInput{Name: "n", DueAt: time.Now().Add(time.Hour)}},
		{"missing name", StartCampaignInput{WorkspaceID: "ws", DueAt: time.Now().Add(time.Hour)}},
		{"missing due", StartCampaignInput{WorkspaceID: "ws", Name: "n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.StartCampaign(context.Background(), tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Errorf("err = %v; want errors.Is(_, ErrValidation)", err)
			}
		})
	}
}

// TestSubmitDecision_Certify exercises the no-side-effect happy path.
// A reviewer flips a pending row to certify; no provisioning call is
// expected.
func TestSubmitDecision_Certify(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	g := seedActiveGrant(t, db, "01H000000000000000GRANT0001", ws, "u1", conn, "admin", "host-a")

	svc := NewAccessReviewService(db, nil)
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "review",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}

	if err := svc.SubmitDecision(context.Background(), review.ID, g.ID, models.DecisionCertify, "01H000000000000000REVIEWER1", "looks good"); err != nil {
		t.Fatalf("SubmitDecision: %v", err)
	}

	var d models.AccessReviewDecision
	if err := db.Where("review_id = ? AND grant_id = ?", review.ID, g.ID).First(&d).Error; err != nil {
		t.Fatalf("read decision: %v", err)
	}
	if d.Decision != models.DecisionCertify {
		t.Errorf("Decision = %q; want %q", d.Decision, models.DecisionCertify)
	}
	if d.DecidedBy != "01H000000000000000REVIEWER1" {
		t.Errorf("DecidedBy = %q; want reviewer1", d.DecidedBy)
	}
	if d.DecidedAt == nil {
		t.Errorf("DecidedAt = nil; want non-nil")
	}
}

// TestSubmitDecision_RevokeCallsProvisioning is the integration test
// for the "revoke decision actually revokes the grant" flow. We wire
// a MockAccessConnector through SwapConnector and assert RevokeAccess
// fires exactly once and the grant row gets RevokedAt stamped.
func TestSubmitDecision_RevokeCallsProvisioning(t *testing.T) {
	const provider = "mock_review_revoke"
	db := newReviewTestDB(t)
	conn := seedConnector(t, db, provider)
	g := seedActiveGrant(t, db, "01H000000000000000GRANT0001", conn.WorkspaceID, "u1", conn.ID, "admin", "host-a")
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	svc := NewAccessReviewService(db, provSvc)
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: conn.WorkspaceID,
		Name:        "revoke review",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn.ID}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}

	if err := svc.SubmitDecision(context.Background(), review.ID, g.ID, models.DecisionRevoke, "01H000000000000000REVIEWER1", "off-team"); err != nil {
		t.Fatalf("SubmitDecision: %v", err)
	}
	if mock.RevokeAccessCalls != 1 {
		t.Errorf("RevokeAccessCalls = %d; want 1", mock.RevokeAccessCalls)
	}

	var stored models.AccessGrant
	if err := db.Where("id = ?", g.ID).First(&stored).Error; err != nil {
		t.Fatalf("read grant: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Errorf("RevokedAt = nil; want non-nil after revoke")
	}
}

// TestSubmitDecision_OnClosedReviewReturnsErrReviewClosed asserts
// reviewers cannot submit on closed campaigns.
func TestSubmitDecision_OnClosedReviewReturnsErrReviewClosed(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	g := seedActiveGrant(t, db, "01H000000000000000GRANT0001", ws, "u1", conn, "admin", "host-a")

	svc := NewAccessReviewService(db, nil)
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "review",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if err := svc.CloseCampaign(context.Background(), review.ID); err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}

	err = svc.SubmitDecision(context.Background(), review.ID, g.ID, models.DecisionCertify, "01H000000000000000REVIEWER1", "")
	if !errors.Is(err, ErrReviewClosed) {
		t.Errorf("err = %v; want errors.Is(_, ErrReviewClosed)", err)
	}
}

// TestSubmitDecision_InvalidDecisionStringReturnsErr asserts the
// decision string is allow-listed at submit time so reviewers cannot
// regress to "pending" or invent new states.
func TestSubmitDecision_InvalidDecisionStringReturnsErr(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)
	err := svc.SubmitDecision(context.Background(), "01H000000000000000REVIEW01", "01H000000000000000GRANT0001", "garbage", "u", "")
	if !errors.Is(err, ErrInvalidDecision) {
		t.Errorf("err = %v; want errors.Is(_, ErrInvalidDecision)", err)
	}
}

// TestSubmitDecision_RevokeRequiresProvisioningSvc asserts the
// service refuses to submit a revoke when constructed without a
// provisioning service. This is the hard-coded safety check that
// callers wire the dependency.
func TestSubmitDecision_RevokeRequiresProvisioningSvc(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	g := seedActiveGrant(t, db, "01H000000000000000GRANT0001", ws, "u1", conn, "admin", "host-a")
	svc := NewAccessReviewService(db, nil)
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "review",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	err = svc.SubmitDecision(context.Background(), review.ID, g.ID, models.DecisionRevoke, "u", "")
	if !errors.Is(err, ErrProvisioningUnavailable) {
		t.Errorf("err = %v; want errors.Is(_, ErrProvisioningUnavailable)", err)
	}
}

// TestCloseCampaign_HappyPath asserts a campaign with all-decided
// rows transitions to closed cleanly.
func TestCloseCampaign_HappyPath(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	g := seedActiveGrant(t, db, "01H000000000000000GRANT0001", ws, "u1", conn, "admin", "host-a")

	svc := NewAccessReviewService(db, nil)
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "review",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if err := svc.SubmitDecision(context.Background(), review.ID, g.ID, models.DecisionCertify, "u", "ok"); err != nil {
		t.Fatalf("SubmitDecision: %v", err)
	}

	if err := svc.CloseCampaign(context.Background(), review.ID); err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}
	var stored models.AccessReview
	if err := db.Where("id = ?", review.ID).First(&stored).Error; err != nil {
		t.Fatalf("read review: %v", err)
	}
	if stored.State != models.ReviewStateClosed {
		t.Errorf("State = %q; want %q", stored.State, models.ReviewStateClosed)
	}
}

// TestCloseCampaign_PendingDecisionsAutoEscalate asserts that closing
// a campaign with still-pending decisions flips them to "escalate"
// rather than leaving them in pending.
func TestCloseCampaign_PendingDecisionsAutoEscalate(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANT0001", ws, "u1", conn, "admin", "host-a")

	svc := NewAccessReviewService(db, nil)
	review, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "review",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("len(decisions) = %d; want 1", len(decisions))
	}

	if err := svc.CloseCampaign(context.Background(), review.ID); err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}
	var d models.AccessReviewDecision
	if err := db.Where("id = ?", decisions[0].ID).First(&d).Error; err != nil {
		t.Fatalf("read decision: %v", err)
	}
	if d.Decision != models.DecisionEscalate {
		t.Errorf("Decision = %q; want %q (auto-escalated on close)", d.Decision, models.DecisionEscalate)
	}
	if d.DecidedAt == nil {
		t.Error("DecidedAt = nil; want non-nil after auto-escalate")
	}
}

// TestCloseCampaign_NonOpenReturnsErr asserts double-close is rejected
// (ErrReviewClosed). Non-existent IDs return ErrReviewNotFound.
func TestCloseCampaign_NonOpenReturnsErr(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)

	err := svc.CloseCampaign(context.Background(), "01H000000000000000NONEXIST01")
	if !errors.Is(err, ErrReviewNotFound) {
		t.Errorf("missing review: err = %v; want errors.Is(_, ErrReviewNotFound)", err)
	}

	const ws = "01H000000000000000WORKSPACE"
	svc2 := NewAccessReviewService(db, nil)
	review, _, err := svc2.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "review",
		DueAt:       time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if err := svc2.CloseCampaign(context.Background(), review.ID); err != nil {
		t.Fatalf("first close: %v", err)
	}
	err = svc2.CloseCampaign(context.Background(), review.ID)
	if !errors.Is(err, ErrReviewClosed) {
		t.Errorf("double close: err = %v; want errors.Is(_, ErrReviewClosed)", err)
	}
}

// TestAutoRevoke_HappyPath asserts that AutoRevoke walks every revoke
// decision and executes the upstream side-effect via the provisioning
// service. Already-revoked grants are silently skipped (idempotent).
func TestAutoRevoke_HappyPath(t *testing.T) {
	const provider = "mock_review_autorevoke"
	db := newReviewTestDB(t)
	conn := seedConnector(t, db, provider)
	g1 := seedActiveGrant(t, db, "01H000000000000000GRANT0001", conn.WorkspaceID, "u1", conn.ID, "admin", "host-a")
	g2 := seedActiveGrant(t, db, "01H000000000000000GRANT0002", conn.WorkspaceID, "u2", conn.ID, "admin", "host-b")
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	svc := NewAccessReviewService(db, provSvc)

	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: conn.WorkspaceID,
		Name:        "auto",
		DueAt:       time.Now().Add(time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn.ID}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}

	// Mark both decisions as revoke without going through SubmitDecision
	// (so we exercise AutoRevoke's "do the side-effect later" path).
	now := time.Now().UTC()
	if err := db.Model(&models.AccessReviewDecision{}).
		Where("review_id = ?", review.ID).
		Updates(map[string]interface{}{"decision": models.DecisionRevoke, "decided_at": now, "updated_at": now}).Error; err != nil {
		t.Fatalf("seed revoke decisions: %v", err)
	}

	if err := svc.AutoRevoke(context.Background(), review.ID); err != nil {
		t.Fatalf("AutoRevoke: %v", err)
	}
	if mock.RevokeAccessCalls != 2 {
		t.Errorf("RevokeAccessCalls = %d; want 2", mock.RevokeAccessCalls)
	}

	var stored1, stored2 models.AccessGrant
	if err := db.Where("id = ?", g1.ID).First(&stored1).Error; err != nil {
		t.Fatalf("read grant 1: %v", err)
	}
	if err := db.Where("id = ?", g2.ID).First(&stored2).Error; err != nil {
		t.Fatalf("read grant 2: %v", err)
	}
	if stored1.RevokedAt == nil || stored2.RevokedAt == nil {
		t.Error("expected both grants to be revoked")
	}

	// Run AutoRevoke again — should be a no-op (already-revoked
	// grants are skipped).
	mock.RevokeAccessCalls = 0
	if err := svc.AutoRevoke(context.Background(), review.ID); err != nil {
		t.Fatalf("AutoRevoke (second run): %v", err)
	}
	if mock.RevokeAccessCalls != 0 {
		t.Errorf("second AutoRevoke RevokeAccessCalls = %d; want 0 (idempotent)", mock.RevokeAccessCalls)
	}
}

// TestAutoRevoke_RequiresProvisioningSvc asserts AutoRevoke refuses
// to run when the service was constructed without a provisioning
// dependency.
func TestAutoRevoke_RequiresProvisioningSvc(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)
	err := svc.AutoRevoke(context.Background(), "01H000000000000000REVIEW01")
	if !errors.Is(err, ErrProvisioningUnavailable) {
		t.Errorf("err = %v; want errors.Is(_, ErrProvisioningUnavailable)", err)
	}
}

// TestAutoRevoke_NonExistentReturnsErr asserts ErrReviewNotFound is
// returned for a missing review.
func TestAutoRevoke_NonExistentReturnsErr(t *testing.T) {
	db := newReviewTestDB(t)
	provSvc := NewAccessProvisioningService(db)
	svc := NewAccessReviewService(db, provSvc)
	err := svc.AutoRevoke(context.Background(), "01H000000000000000NONEXIST01")
	if !errors.Is(err, ErrReviewNotFound) {
		t.Errorf("err = %v; want errors.Is(_, ErrReviewNotFound)", err)
	}
}
