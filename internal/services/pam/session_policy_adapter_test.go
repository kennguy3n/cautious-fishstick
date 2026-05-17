package pam

import (
	"context"
	"strings"
	"testing"
	"time"

	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newSessionPolicyAdapterFixture wires an in-memory PAM DB, seeds a
// canonical session + asset row, and returns the adapter plus its
// backing PAMCommandPolicyService so tests can layer policies on
// top.
func newSessionPolicyAdapterFixture(t *testing.T) (*SessionPolicyAdapter, *PAMCommandPolicyService, models.PAMSession, models.PAMAsset) {
	t.Helper()
	db := newPAMDB(t)
	svc, err := NewPAMCommandPolicyService(db)
	if err != nil {
		t.Fatalf("NewPAMCommandPolicyService: %v", err)
	}
	asset := models.PAMAsset{
		ID:          "ast-spa-1",
		WorkspaceID: "ws-spa",
		Name:        "prod-bastion",
		Protocol:    "ssh",
		Host:        "10.0.0.1",
		Port:        22,
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
		ID:          "ses-spa-1",
		WorkspaceID: "ws-spa",
		UserID:      "usr-spa-1",
		AssetID:     asset.ID,
		AccountID:   "acc-spa-1",
		Protocol:    "ssh",
		State:       models.PAMSessionStateActive,
		StartedAt:   &started,
		CreatedAt:   started,
		UpdatedAt:   started,
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	a := NewSessionPolicyAdapter(db, svc)
	return a, svc, session, asset
}

func TestSessionPolicyAdapter_NilReceiverAllowsEverything(t *testing.T) {
	var a *SessionPolicyAdapter
	action, reason, err := a.EvaluateCommand(context.Background(), "ws", "ses", "rm -rf /")
	if err != nil {
		t.Fatalf("nil receiver returned err: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("nil receiver action = %q; want allow", action)
	}
	if reason != "" {
		t.Fatalf("nil receiver reason = %q; want empty", reason)
	}
}

func TestSessionPolicyAdapter_NilPolicyServiceAllowsEverything(t *testing.T) {
	a := NewSessionPolicyAdapter(newPAMDB(t), nil)
	action, _, err := a.EvaluateCommand(context.Background(), "ws", "ses", "rm -rf /")
	if err != nil {
		t.Fatalf("nil policy svc returned err: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("nil policy svc action = %q; want allow", action)
	}
}

func TestSessionPolicyAdapter_EmptyWorkspaceIDRejected(t *testing.T) {
	a, _, _, _ := newSessionPolicyAdapterFixture(t)
	_, _, err := a.EvaluateCommand(context.Background(), "  ", "ses", "ls")
	if err == nil {
		t.Fatalf("expected error on empty workspace_id")
	}
	if !strings.Contains(err.Error(), "workspace_id") {
		t.Fatalf("err = %v; want 'workspace_id is required'", err)
	}
}

func TestSessionPolicyAdapter_EmptySessionIDRejected(t *testing.T) {
	a, _, _, _ := newSessionPolicyAdapterFixture(t)
	_, _, err := a.EvaluateCommand(context.Background(), "ws-spa", " ", "ls")
	if err == nil {
		t.Fatalf("expected error on empty session_id")
	}
	if !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("err = %v; want 'session_id is required'", err)
	}
}

func TestSessionPolicyAdapter_UnknownSessionReturnsError(t *testing.T) {
	a, _, _, _ := newSessionPolicyAdapterFixture(t)
	_, _, err := a.EvaluateCommand(context.Background(), "ws-spa", "ses-missing", "ls")
	if err == nil {
		t.Fatalf("expected error on unknown session_id")
	}
	if !strings.Contains(err.Error(), "session ses-missing not found") {
		t.Fatalf("err = %v; want 'not found'", err)
	}
}

func TestSessionPolicyAdapter_WrongWorkspaceReturnsError(t *testing.T) {
	a, _, session, _ := newSessionPolicyAdapterFixture(t)
	_, _, err := a.EvaluateCommand(context.Background(), "ws-other", session.ID, "ls")
	if err == nil {
		t.Fatalf("expected error when session is in a different workspace")
	}
}

func TestSessionPolicyAdapter_AllowsWhenNoPoliciesMatch(t *testing.T) {
	a, _, session, _ := newSessionPolicyAdapterFixture(t)
	action, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls -la")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow", action)
	}
}

func TestSessionPolicyAdapter_DenyMatchesByAssetID(t *testing.T) {
	a, svc, session, asset := newSessionPolicyAdapterFixture(t)
	selector := datatypes.JSON([]byte(`{"id": "` + asset.ID + `"}`))
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID:            "pcp-deny-rm",
		WorkspaceID:   session.WorkspaceID,
		Pattern:       "^rm",
		Action:        models.PAMCommandActionDeny,
		Priority:      1,
		AssetSelector: selector,
	})
	action, reason, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "rm -rf /")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny", action)
	}
	if reason == "" {
		t.Fatalf("expected non-empty reason")
	}
}

func TestSessionPolicyAdapter_DenyMatchesByAssetCriticality(t *testing.T) {
	a, svc, session, _ := newSessionPolicyAdapterFixture(t)
	selector := datatypes.JSON([]byte(`{"criticality": "high"}`))
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID:            "pcp-deny-high",
		WorkspaceID:   session.WorkspaceID,
		Pattern:       "^drop\\b",
		Action:        models.PAMCommandActionDeny,
		Priority:      1,
		AssetSelector: selector,
	})
	action, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "drop database foo")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny", action)
	}
}

func TestSessionPolicyAdapter_StepUpMatches(t *testing.T) {
	a, svc, session, _ := newSessionPolicyAdapterFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID:          "pcp-stepup",
		WorkspaceID: session.WorkspaceID,
		Pattern:     "^sudo\\b",
		Action:      models.PAMCommandActionStepUp,
		Priority:    5,
	})
	action, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "sudo -i")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionStepUp {
		t.Fatalf("action = %q; want step_up", action)
	}
}

func TestSessionPolicyAdapter_AccountSelectorMatches(t *testing.T) {
	a, svc, session, _ := newSessionPolicyAdapterFixture(t)
	selector := datatypes.JSON([]byte(`{"id": "` + session.AccountID + `"}`))
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID:              "pcp-account",
		WorkspaceID:     session.WorkspaceID,
		Pattern:         "^drop\\b",
		Action:          models.PAMCommandActionDeny,
		Priority:        1,
		AccountSelector: selector,
	})
	action, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "drop table users")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny", action)
	}
}

func TestSessionPolicyAdapter_CachesResolvedContext(t *testing.T) {
	a, svc, session, _ := newSessionPolicyAdapterFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-allow", WorkspaceID: session.WorkspaceID,
		Pattern: "^ls", Action: models.PAMCommandActionAllow, Priority: 1,
	})
	// Drive one call to populate the cache.
	if _, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls"); err != nil {
		t.Fatalf("first EvaluateCommand: %v", err)
	}
	// Delete the session row from under the adapter. If the cache
	// is doing its job, the second call still works (no DB hit on
	// the resolve path).
	if err := a.db.Where("id = ?", session.ID).Delete(&models.PAMSession{}).Error; err != nil {
		t.Fatalf("delete session: %v", err)
	}
	action, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls -la")
	if err != nil {
		t.Fatalf("second EvaluateCommand after delete: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow", action)
	}
}

func TestSessionPolicyAdapter_InvalidateSessionForcesReload(t *testing.T) {
	a, _, session, _ := newSessionPolicyAdapterFixture(t)
	// Populate the cache.
	if _, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls"); err != nil {
		t.Fatalf("warmup EvaluateCommand: %v", err)
	}
	// Now delete the session AND invalidate the cache. The next
	// EvaluateCommand should hit the DB, miss, and error.
	if err := a.db.Where("id = ?", session.ID).Delete(&models.PAMSession{}).Error; err != nil {
		t.Fatalf("delete session: %v", err)
	}
	a.InvalidateSession(session.ID)
	_, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls")
	if err == nil {
		t.Fatalf("expected 'session not found' after invalidate; got nil")
	}
}

func TestSessionPolicyAdapter_CacheTTLExpiryReloads(t *testing.T) {
	a, _, session, _ := newSessionPolicyAdapterFixture(t)
	// Pin time so we can advance it explicitly.
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	a.SetNow(func() time.Time { return now })
	a.SetCacheTTL(time.Second)

	if _, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls"); err != nil {
		t.Fatalf("warmup EvaluateCommand: %v", err)
	}
	// Delete from under the cache, advance past TTL, expect reload.
	if err := a.db.Where("id = ?", session.ID).Delete(&models.PAMSession{}).Error; err != nil {
		t.Fatalf("delete session: %v", err)
	}
	now = now.Add(2 * time.Second)
	_, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "ls")
	if err == nil {
		t.Fatalf("expected 'session not found' after TTL expiry; got nil")
	}
}

func TestSessionPolicyAdapter_SetCacheTTLNonPositiveResetsToDefault(t *testing.T) {
	a, _, _, _ := newSessionPolicyAdapterFixture(t)
	a.SetCacheTTL(time.Minute)
	if a.cacheTTL != time.Minute {
		t.Fatalf("setup precondition broken")
	}
	a.SetCacheTTL(0)
	if a.cacheTTL != defaultSessionContextCacheTTL {
		t.Fatalf("zero TTL did not reset to default; got %s", a.cacheTTL)
	}
	a.SetCacheTTL(-1 * time.Second)
	if a.cacheTTL != defaultSessionContextCacheTTL {
		t.Fatalf("negative TTL did not reset to default; got %s", a.cacheTTL)
	}
}

func TestSessionPolicyAdapter_SetNowIgnoresNilSafely(t *testing.T) {
	var a *SessionPolicyAdapter
	a.SetNow(func() time.Time { return time.Now() }) // must not panic

	b, _, _, _ := newSessionPolicyAdapterFixture(t)
	b.SetNow(nil) // must not panic and must not clobber the existing fn
	if b.now == nil {
		t.Fatalf("SetNow(nil) clobbered the time source")
	}
}

func TestSessionPolicyAdapter_InvalidateSessionNilReceiver(t *testing.T) {
	var a *SessionPolicyAdapter
	a.InvalidateSession("anything") // must not panic
}

func TestSessionPolicyAdapter_AssetMetadataExposedToPolicy(t *testing.T) {
	// The adapter must expose the asset's protocol/criticality/host/name
	// to the policy engine so selectors can filter on them. Drive this
	// through a real policy whose selector matches "protocol=ssh"
	// (which is the seeded asset's protocol).
	a, svc, session, _ := newSessionPolicyAdapterFixture(t)
	selector := datatypes.JSON([]byte(`{"protocol": "ssh"}`))
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID:            "pcp-ssh-only",
		WorkspaceID:   session.WorkspaceID,
		Pattern:       "^shutdown\\b",
		Action:        models.PAMCommandActionDeny,
		Priority:      1,
		AssetSelector: selector,
	})
	action, _, err := a.EvaluateCommand(context.Background(), session.WorkspaceID, session.ID, "shutdown -h now")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny (asset metadata not exposed correctly)", action)
	}
}
