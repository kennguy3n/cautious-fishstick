package handlers

import (
	"net/http"
	"testing"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// newPAMPolicyEngine wires a router with only the PAMPolicyAdapter
// dependency bound. The handler under test (POST
// /pam/policy/evaluate) is the gateway-facing surface that
// pam-gateway calls over HTTP to evaluate operator commands.
//
// Returns the router, the underlying DB (so tests can seed
// pam_command_policies rows directly), the policy service (so
// tests can invalidate the cache after seeding), the seeded
// session, and the seeded asset.
func newPAMPolicyEngine(t *testing.T) (http.Handler, *gorm.DB, *pam.PAMCommandPolicyService, models.PAMSession, models.PAMAsset) {
	t.Helper()
	db := newTestDB(t)
	svc, err := pam.NewPAMCommandPolicyService(db)
	if err != nil {
		t.Fatalf("NewPAMCommandPolicyService: %v", err)
	}
	asset := models.PAMAsset{
		ID:          "ast-pph-1",
		WorkspaceID: "ws-pph",
		Name:        "prod-db",
		Protocol:    "postgres",
		Host:        "10.0.0.5",
		Port:        5432,
		Criticality: "high",
		Status:      models.PAMAssetStatusActive,
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	started := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	session := models.PAMSession{
		ID:          "ses-pph-1",
		WorkspaceID: "ws-pph",
		UserID:      "usr-pph-1",
		AssetID:     asset.ID,
		AccountID:   "acc-pph-1",
		Protocol:    "postgres",
		State:       models.PAMSessionStateActive,
		StartedAt:   &started,
		CreatedAt:   started,
		UpdatedAt:   started,
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	adapter := pam.NewSessionPolicyAdapter(db, svc)
	r := Router(Dependencies{PAMPolicyAdapter: adapter, DisableRateLimiter: true})
	return r, db, svc, session, asset
}

func TestPAMPolicyHandler_Evaluate_AllowsWhenNoPolicies(t *testing.T) {
	r, _, _, session, _ := newPAMPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": session.WorkspaceID,
		"session_id":   session.ID,
		"input":        "select 1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	decodeJSON(t, w, &resp)
	if resp.Action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow", resp.Action)
	}
}

func TestPAMPolicyHandler_Evaluate_DeniesOnMatchingPolicy(t *testing.T) {
	r, db, svc, session, _ := newPAMPolicyEngine(t)
	if err := db.Create(&models.PAMCommandPolicy{
		ID:          "pcp-drop",
		WorkspaceID: session.WorkspaceID,
		Pattern:     `(?i)^drop\b`,
		Action:      models.PAMCommandActionDeny,
		Priority:    1,
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	svc.Invalidate(session.WorkspaceID)

	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": session.WorkspaceID,
		"session_id":   session.ID,
		"input":        "DROP TABLE users",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	decodeJSON(t, w, &resp)
	if resp.Action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny (body=%s)", resp.Action, w.Body.String())
	}
	if resp.Reason == "" {
		t.Fatalf("expected non-empty reason for deny")
	}
}

func TestPAMPolicyHandler_Evaluate_StepUpOnMatchingPolicy(t *testing.T) {
	r, db, svc, session, _ := newPAMPolicyEngine(t)
	if err := db.Create(&models.PAMCommandPolicy{
		ID:          "pcp-sudo",
		WorkspaceID: session.WorkspaceID,
		Pattern:     "^sudo",
		Action:      models.PAMCommandActionStepUp,
		Priority:    1,
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	svc.Invalidate(session.WorkspaceID)

	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": session.WorkspaceID,
		"session_id":   session.ID,
		"input":        "sudo -i",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Action string `json:"action"`
	}
	decodeJSON(t, w, &resp)
	if resp.Action != models.PAMCommandActionStepUp {
		t.Fatalf("action = %q; want step_up", resp.Action)
	}
}

func TestPAMPolicyHandler_Evaluate_RejectsEmptyWorkspaceID(t *testing.T) {
	r, _, _, session, _ := newPAMPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": "",
		"session_id":   session.ID,
		"input":        "ls",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMPolicyHandler_Evaluate_RejectsEmptySessionID(t *testing.T) {
	r, _, _, _, _ := newPAMPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": "ws-pph",
		"session_id":   "",
		"input":        "ls",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMPolicyHandler_Evaluate_RejectsMalformedJSON(t *testing.T) {
	r, _, _, _, _ := newPAMPolicyEngine(t)
	// Pass a non-marshallable type to trip ShouldBindJSON's
	// content-type validation. The simplest version: an empty body
	// against ShouldBindJSON yields a 400.
	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMPolicyHandler_Evaluate_ReturnsErrorWhenSessionMissing(t *testing.T) {
	r, _, _, _, _ := newPAMPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": "ws-pph",
		"session_id":   "ses-not-real",
		"input":        "ls",
	})
	if w.Code < 400 || w.Code >= 600 {
		t.Fatalf("status = %d; want 4xx/5xx", w.Code)
	}
}

func TestPAMPolicyHandler_Evaluate_AssetSelectorMatches(t *testing.T) {
	r, db, svc, session, asset := newPAMPolicyEngine(t)
	if err := db.Create(&models.PAMCommandPolicy{
		ID:            "pcp-asset",
		WorkspaceID:   session.WorkspaceID,
		Pattern:       "^select\\b",
		Action:        models.PAMCommandActionAllow,
		Priority:      1,
		AssetSelector: datatypes.JSON([]byte(`{"id":"` + asset.ID + `"}`)),
		CreatedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	svc.Invalidate(session.WorkspaceID)

	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": session.WorkspaceID,
		"session_id":   session.ID,
		"input":        "select 1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Action string `json:"action"`
	}
	decodeJSON(t, w, &resp)
	if resp.Action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow", resp.Action)
	}
}

func TestPAMPolicyHandler_NotRegisteredWhenAdapterNil(t *testing.T) {
	// When the adapter dependency is absent, the route MUST NOT
	// be registered — dev binaries without a DB should stay
	// healthy.
	r := Router(Dependencies{DisableRateLimiter: true})
	w := doJSON(t, r, http.MethodPost, "/pam/policy/evaluate", map[string]string{
		"workspace_id": "ws",
		"session_id":   "ses",
		"input":        "ls",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404 when adapter is nil", w.Code)
	}
}
