package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// deterministicRiskAssessor is a real (not mock) RiskAssessor with
// fixed rules so the E2E test gets deterministic risk_score columns
// without depending on the Phase 4 AIClient. Lives alongside the
// service-layer copy in request_lifecycle_integration_test.go — the
// duplication is intentional so this package has no test-time link
// against access internals.
type deterministicRiskAssessor struct{}

func (deterministicRiskAssessor) AssessRequestRisk(_ context.Context, payload interface{}) (string, []string, bool) {
	// The payload is access.riskAssessmentPayload — an unexported
	// struct. Use the public fmt.Sprintf form to extract the
	// justification + role for keyword matching.
	s := stringifyPayload(payload)
	if strings.Contains(strings.ToLower(s), "emergency") {
		return "high", []string{"keyword:emergency"}, true
	}
	if strings.Contains(strings.ToLower(s), "admin") {
		return "medium", []string{"role:admin"}, true
	}
	return "low", nil, true
}

func stringifyPayload(p interface{}) string {
	// fmt.Sprintf %+v prints exported AND unexported fields of the
	// access.riskAssessmentPayload struct, which is what we need to
	// keyword-match Justification and Role without depending on the
	// package-private struct definition.
	return strings.ToLower(fmt.Sprintf("%+v", p))
}

// TestRequest_E2E_FullLifecycle covers all three risk buckets in one
// table-driven test, then drives the lifecycle from POST → approve →
// Provision → Revoke. The MockAccessConnector is the only mock;
// every other layer (router, request service, provisioning service)
// is the real production type.
func TestRequest_E2E_FullLifecycle(t *testing.T) {
	const provider = "test_provider_e2e_request_lifecycle"
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)

	mock := stubAccessConnector()
	var provisionCalls, revokeCalls int
	mock.FuncProvisionAccess = func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error {
		provisionCalls++
		return nil
	}
	mock.FuncRevokeAccess = func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error {
		revokeCalls++
		return nil
	}
	access.SwapConnector(t, provider, mock)

	// Seed an access_connectors row so request → grant → connector
	// lookups all resolve. We build it directly rather than POSTing
	// through the connector handler because the connector lifecycle
	// is covered separately by connector_lifecycle_e2e_test.go.
	connectorID := "01HCONN0E2EREQUEST0LIFECYCLE0"
	workspaceID := "01H000000000000000WORKSPACE0"
	if err := db.Create(&models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   workspaceID,
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}

	reqSvc := access.NewAccessRequestService(db)
	reqSvc.SetRiskAssessor(deterministicRiskAssessor{})
	provSvc := access.NewAccessProvisioningService(db)

	router := handlers.Router(handlers.Dependencies{
		AccessRequestService: reqSvc,
	})

	cases := []struct {
		name          string
		justification string
		role          string
		wantRisk      string
	}{
		{"emergency_high", "emergency: prod outage", "viewer", "high"},
		{"admin_medium", "quarterly review", "admin", "medium"},
		{"viewer_low", "weekly access", "viewer", "low"},
	}

	for i, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// --- Step 1: POST /access/requests ---
			status, body := doJSON(t, router, http.MethodPost, "/access/requests", map[string]any{
				"workspace_id":         workspaceID,
				"requester_user_id":    "01HREQUESTER000000000000" + fmt.Sprintf("%02d", i),
				"target_user_id":       "01HTARGETUSER0000000000" + fmt.Sprintf("%02d", i),
				"connector_id":         connectorID,
				"resource_external_id": "projects/foo",
				"role":                 tc.role,
				"justification":        tc.justification,
			})
			if status != http.StatusCreated {
				t.Fatalf("POST /access/requests: status=%d body=%+v", status, body)
			}
			requestID, _ := body["id"].(string)
			if requestID == "" {
				t.Fatalf("expected request id in response: %+v", body)
			}
			if got, _ := body["risk_score"].(string); got != tc.wantRisk {
				t.Fatalf("body.risk_score = %q; want %q", got, tc.wantRisk)
			}

			// --- Step 2: verify risk_score actually persisted ---
			var persisted models.AccessRequest
			if err := db.Where("id = ?", requestID).First(&persisted).Error; err != nil {
				t.Fatalf("reload request: %v", err)
			}
			if persisted.RiskScore != tc.wantRisk {
				t.Fatalf("persisted RiskScore=%q; want %q", persisted.RiskScore, tc.wantRisk)
			}

			// --- Step 3: POST /access/requests/:id/approve ---
			status, _ = doJSON(t, router, http.MethodPost, "/access/requests/"+requestID+"/approve", map[string]any{
				"actor_user_id": "01HACTOR000000000000000001",
				"reason":        "manager OK",
			})
			if status != http.StatusOK {
				t.Fatalf("approve: status=%d", status)
			}

			// --- Step 4: drive provisioning (no HTTP handler — the
			// workflow engine triggers Provision in prod; here we
			// invoke the service directly) ---
			var approved models.AccessRequest
			if err := db.Where("id = ?", requestID).First(&approved).Error; err != nil {
				t.Fatalf("reload approved: %v", err)
			}
			beforeProvision := provisionCalls
			if err := provSvc.Provision(context.Background(), &approved, nil, nil); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if provisionCalls != beforeProvision+1 {
				t.Fatalf("connector.ProvisionAccess was not called")
			}

			var provisioned models.AccessRequest
			if err := db.Where("id = ?", requestID).First(&provisioned).Error; err != nil {
				t.Fatalf("reload provisioned: %v", err)
			}
			if provisioned.State != models.RequestStateProvisioned {
				t.Fatalf("state = %q; want provisioned", provisioned.State)
			}

			var grant models.AccessGrant
			if err := db.Where("request_id = ?", requestID).First(&grant).Error; err != nil {
				t.Fatalf("expected access_grants row for request: %v", err)
			}
			if grant.RevokedAt != nil {
				t.Fatalf("grant should not be revoked yet, got %+v", grant.RevokedAt)
			}

			// --- Step 5: revoke the grant via AccessProvisioningService ---
			beforeRevoke := revokeCalls
			if err := provSvc.Revoke(context.Background(), &grant, nil, nil); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if revokeCalls != beforeRevoke+1 {
				t.Fatalf("connector.RevokeAccess was not called")
			}

			var revoked models.AccessGrant
			if err := db.Where("id = ?", grant.ID).First(&revoked).Error; err != nil {
				t.Fatalf("reload grant: %v", err)
			}
			if revoked.RevokedAt == nil {
				t.Fatalf("grant.RevokedAt not set after Revoke")
			}
		})
	}
}

// TestRequest_E2E_ValidationFailure covers the failure path: POST
// without required fields returns a 4xx/5xx without ever creating
// a row.
func TestRequest_E2E_ValidationFailure(t *testing.T) {
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)
	reqSvc := access.NewAccessRequestService(db)
	router := handlers.Router(handlers.Dependencies{
		AccessRequestService: reqSvc,
	})

	status, _ := doJSON(t, router, http.MethodPost, "/access/requests", map[string]any{
		"workspace_id": "ws-1",
		// requester_user_id intentionally missing → validation should fail.
	})
	if status < 400 {
		t.Fatalf("expected 4xx/5xx for invalid payload, got %d", status)
	}

	var count int64
	if err := db.Model(&models.AccessRequest{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected zero rows after validation failure, got %d", count)
	}
}
