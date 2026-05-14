package integration_test

import (
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestPolicy_E2E_FullLifecycle drives the policy lifecycle through
// the real Gin router:
//
//   POST /workspace/policy → 201 (draft persisted)
//   POST /workspace/policy/:id/simulate → 200 (impact report computed)
//   POST /workspace/policy/:id/promote → 200 (is_draft = false)
//
// The PolicyService is the real production type backed by an
// in-memory SQLite DB; no mocks are required because Simulate /
// Promote do not depend on the access connectors.
func TestPolicy_E2E_FullLifecycle(t *testing.T) {
	const workspaceID = "01H000000000000000WORKSPACE0"
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)
	policySvc := access.NewPolicyService(db)
	router := handlers.Router(handlers.Dependencies{
		PolicyService: policySvc,
	})

	// --- Step 1: POST /workspace/policy ---
	status, body := doJSON(t, router, http.MethodPost, "/workspace/policy", map[string]any{
		"workspace_id":        workspaceID,
		"name":                "Engineering read-only",
		"description":         "E2E draft policy",
		"attributes_selector": map[string]any{"role": "engineer"},
		"resource_selector":   map[string]any{"resource_type": "repo"},
		"action":              "allow",
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /workspace/policy: status=%d body=%+v", status, body)
	}
	policyID, _ := body["id"].(string)
	if policyID == "" {
		t.Fatalf("expected policy id in response: %+v", body)
	}
	if got, _ := body["is_draft"].(bool); !got {
		t.Fatalf("freshly-created policy should be a draft, got is_draft=%v", body["is_draft"])
	}

	// --- Step 2: POST /workspace/policy/:id/simulate ---
	status, body = doJSON(t, router, http.MethodPost, "/workspace/policy/"+policyID+"/simulate", map[string]any{
		"workspace_id": workspaceID,
	})
	if status != http.StatusOK {
		t.Fatalf("simulate: status=%d body=%+v", status, body)
	}
	// The ImpactReport contains "policy_id" + the impact totals. The
	// exact totals are zero on an empty DB but the report must still
	// be a structured object, not an error envelope.
	if _, hasError := body["error"]; hasError {
		t.Fatalf("simulate returned error envelope: %+v", body)
	}
	// Verify draft_impact was actually persisted on the row.
	var simulated models.Policy
	if err := db.Where("id = ?", policyID).First(&simulated).Error; err != nil {
		t.Fatalf("reload simulated: %v", err)
	}
	if len(simulated.DraftImpact) == 0 {
		t.Fatalf("draft_impact not persisted after simulate")
	}

	// --- Step 3: POST /workspace/policy/:id/promote ---
	status, body = doJSON(t, router, http.MethodPost, "/workspace/policy/"+policyID+"/promote", map[string]any{
		"workspace_id":  workspaceID,
		"actor_user_id": "01HACTOR000000000000000001",
	})
	if status != http.StatusOK {
		t.Fatalf("promote: status=%d body=%+v", status, body)
	}
	if got, _ := body["is_draft"].(bool); got {
		t.Fatalf("body.is_draft = true after promote; want false")
	}

	var promoted models.Policy
	if err := db.Where("id = ?", policyID).First(&promoted).Error; err != nil {
		t.Fatalf("reload promoted: %v", err)
	}
	if promoted.IsDraft {
		t.Fatalf("persisted IsDraft = true after promote")
	}
}

// TestPolicy_E2E_PromoteBeforeSimulateFails verifies the failure
// path: promote of a draft that has never been simulated should
// fail (ErrPolicyNotSimulated → 5xx) and leave is_draft unchanged.
func TestPolicy_E2E_PromoteBeforeSimulateFails(t *testing.T) {
	const workspaceID = "01H000000000000000WORKSPACE0"
	cleanup := silenceLogs(t)
	defer cleanup()

	db := newE2EDB(t)
	policySvc := access.NewPolicyService(db)
	router := handlers.Router(handlers.Dependencies{
		PolicyService: policySvc,
	})

	status, body := doJSON(t, router, http.MethodPost, "/workspace/policy", map[string]any{
		"workspace_id":        workspaceID,
		"name":                "Unsimulated draft",
		"attributes_selector": map[string]any{"role": "intern"},
		"resource_selector":   map[string]any{"resource_type": "repo"},
		"action":              "allow",
	})
	if status != http.StatusCreated {
		t.Fatalf("create draft: status=%d body=%+v", status, body)
	}
	policyID, _ := body["id"].(string)

	status, _ = doJSON(t, router, http.MethodPost, "/workspace/policy/"+policyID+"/promote", map[string]any{
		"workspace_id":  workspaceID,
		"actor_user_id": "01HACTOR000000000000000001",
	})
	if status < 400 {
		t.Fatalf("expected 4xx/5xx for un-simulated promote, got %d", status)
	}

	var unchanged models.Policy
	if err := db.Where("id = ?", policyID).First(&unchanged).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !unchanged.IsDraft {
		t.Fatalf("policy should remain a draft after failed promote")
	}
}
