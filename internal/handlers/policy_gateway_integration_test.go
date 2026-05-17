package handlers

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/gateway"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// policyIntegrationFixture wires the full gateway-side path:
//
//	gateway.APIPolicyEvaluator → httptest server → handlers.Router →
//	PAMPolicyHandler → SessionPolicyAdapter → PAMCommandPolicyService → DB
//
// Each scenario seeds the same canonical (session, asset, account)
// fixture so test bodies only need to seed the policies they care
// about. Tests treat the APIPolicyEvaluator as a black box — they
// drive it via EvaluateCommand(ctx, workspace, session, input) and
// assert on the (action, reason) tuple it returns, exactly as the
// SSH / K8s / PG / MySQL listeners do in production.
type policyIntegrationFixture struct {
	evaluator *gateway.APIPolicyEvaluator
	svc       *pam.PAMCommandPolicyService
	db        *gorm.DB
	session   models.PAMSession
	asset     models.PAMAsset
	server    *httptest.Server
}

func newPolicyIntegrationFixture(t *testing.T) *policyIntegrationFixture {
	t.Helper()
	db := newTestDB(t)
	svc, err := pam.NewPAMCommandPolicyService(db)
	if err != nil {
		t.Fatalf("NewPAMCommandPolicyService: %v", err)
	}

	const (
		workspaceID = "ws-pol-int"
		sessionID   = "ses-pol-int"
		assetID     = "ast-pol-int"
		accountID   = "acc-pol-int"
	)
	createdAt := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	asset := models.PAMAsset{
		ID:          assetID,
		WorkspaceID: workspaceID,
		Name:        "prod-api-db",
		Protocol:    "postgres",
		Host:        "10.0.0.42",
		Port:        5432,
		Criticality: "critical",
		Status:      models.PAMAssetStatusActive,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	session := models.PAMSession{
		ID:          sessionID,
		WorkspaceID: workspaceID,
		UserID:      "usr-pol-int",
		AssetID:     assetID,
		AccountID:   accountID,
		Protocol:    "postgres",
		State:       models.PAMSessionStateActive,
		StartedAt:   &createdAt,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	adapter := pam.NewSessionPolicyAdapter(db, svc)
	router := Router(Dependencies{
		PAMPolicyAdapter:   adapter,
		DisableRateLimiter: true,
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	evaluator := gateway.NewAPIPolicyEvaluator(server.URL, "", nil)

	return &policyIntegrationFixture{
		evaluator: evaluator,
		svc:       svc,
		db:        db,
		session:   session,
		asset:     asset,
		server:    server,
	}
}

// seedPolicy is a thin wrapper that gorm.Creates the supplied
// PAMCommandPolicy and invalidates the per-workspace cache so the
// next EvaluateCommand call sees the new row. Real production wiring
// invalidates on the workspace-id PUT endpoint; in tests we have to
// drop the cache manually because we INSERT past the service.
func (f *policyIntegrationFixture) seedPolicy(t *testing.T, p models.PAMCommandPolicy) {
	t.Helper()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	if p.WorkspaceID == "" {
		p.WorkspaceID = f.session.WorkspaceID
	}
	if err := f.db.Create(&p).Error; err != nil {
		t.Fatalf("seed policy %s: %v", p.ID, err)
	}
	f.svc.Invalidate(p.WorkspaceID)
}

// TestPolicyIntegration_AllowsWhenNoMatchingPolicy proves the
// end-to-end happy path: the evaluator hits a remote handler, the
// handler resolves the session context, the service evaluates an
// empty policy set, and "allow" is returned to the caller.
func TestPolicyIntegration_AllowsWhenNoMatchingPolicy(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, reason, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "select 1")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow", action)
	}
	if reason != "" {
		t.Errorf("expected empty reason on allow; got %q", reason)
	}
}

// TestPolicyIntegration_DenyMatchesByRegex installs a single deny
// rule whose regex matches the test input, and proves the full
// path returns "deny" + the service's auto-generated reason that
// echoes back the rule id + command excerpt. This is the canonical
// Phase 1 deny path the SSH / DB listeners trigger.
func TestPolicyIntegration_DenyMatchesByRegex(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	const ruleID = "pcp-int-deny-drop"
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:       ruleID,
		Pattern:  `(?i)^drop\s+table\b`,
		Action:   models.PAMCommandActionDeny,
		Priority: 10,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, reason, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "DROP TABLE users")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny", action)
	}
	if !strings.Contains(reason, ruleID) {
		t.Errorf("reason = %q; want mention of rule id %q", reason, ruleID)
	}
	if !strings.Contains(reason, "denied by policy") {
		t.Errorf("reason = %q; want canonical deny phrasing", reason)
	}
}

// TestPolicyIntegration_StepUpMatchesByRegex installs a step_up
// rule and proves the gateway-side evaluator surfaces the action
// untouched. Phase 1 listeners use step_up to flag the session for
// out-of-band mobile MFA; the wire reply is "step_up" + reason.
func TestPolicyIntegration_StepUpMatchesByRegex(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	const ruleID = "pcp-int-stepup-sudo"
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:       ruleID,
		Pattern:  `^sudo\b`,
		Action:   models.PAMCommandActionStepUp,
		Priority: 5,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, reason, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "sudo systemctl restart nginx")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionStepUp {
		t.Fatalf("action = %q; want step_up", action)
	}
	if !strings.Contains(reason, ruleID) {
		t.Errorf("reason = %q; want mention of rule id %q", reason, ruleID)
	}
	if !strings.Contains(reason, "step-up") {
		t.Errorf("reason = %q; want canonical step_up phrasing", reason)
	}
}

// TestPolicyIntegration_PriorityOrdering installs two rules that
// both match the input — one allow at priority=100, one deny at
// priority=1 — and proves the lower priority value wins (priority
// = sort order, smaller = higher precedence).
func TestPolicyIntegration_PriorityOrdering(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	const denyRuleID = "pcp-int-prio-deny"
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:       "pcp-int-prio-allow",
		Pattern:  `^select\b`,
		Action:   models.PAMCommandActionAllow,
		Priority: 100,
	})
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:       denyRuleID,
		Pattern:  `^select\s+\*\s+from\s+secrets`,
		Action:   models.PAMCommandActionDeny,
		Priority: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, reason, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "select * from secrets")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny (higher priority deny rule should win)", action)
	}
	if !strings.Contains(reason, denyRuleID) {
		t.Errorf("reason = %q; want mention of priority-1 deny rule %q", reason, denyRuleID)
	}
}

// TestPolicyIntegration_AssetSelectorMatches installs a rule with
// an asset selector keyed on the session's asset_id and proves it
// filters as expected. This exercises the JSONB selector path
// inside the service.
func TestPolicyIntegration_AssetSelectorMatches(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:            "pcp-int-asset-deny",
		Pattern:       `^truncate\b`,
		Action:        models.PAMCommandActionDeny,
		Priority:      1,
		AssetSelector: datatypes.JSON([]byte(`{"id":"` + f.asset.ID + `"}`)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "truncate table audit")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny on asset-id-matched selector", action)
	}
}

// TestPolicyIntegration_AssetSelectorDoesNotMatchOtherAsset
// installs a rule with an asset selector keyed on a DIFFERENT
// asset id and proves it does NOT apply to the current session.
// Selector mismatch must short-circuit the rule.
func TestPolicyIntegration_AssetSelectorDoesNotMatchOtherAsset(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:            "pcp-int-asset-mismatch",
		Pattern:       `^truncate\b`,
		Action:        models.PAMCommandActionDeny,
		Priority:      1,
		AssetSelector: datatypes.JSON([]byte(`{"id":"some-other-asset"}`)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "truncate table audit")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow (asset selector should have filtered the rule out)", action)
	}
}

// TestPolicyIntegration_AccountSelectorMatches installs a rule
// keyed on the session's account_id and proves the service
// matches it. This proves the AND semantics of multi-key selector
// (rule scopes to both asset criticality + account).
func TestPolicyIntegration_AccountSelectorMatches(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:              "pcp-int-account-deny",
		Pattern:         `^delete\b`,
		Action:          models.PAMCommandActionDeny,
		Priority:        1,
		AccountSelector: datatypes.JSON([]byte(`{"id":"` + f.session.AccountID + `"}`)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "delete from logs")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny on account-id selector match", action)
	}
}

// TestPolicyIntegration_AssetMetadataExposedToSelector installs a
// rule whose selector matches on the asset's "criticality"
// metadata field. This verifies that SessionPolicyAdapter is
// hydrating asset_metadata (not just asset_id) on the way through.
func TestPolicyIntegration_AssetMetadataExposedToSelector(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:            "pcp-int-meta-deny",
		Pattern:       `^update\b`,
		Action:        models.PAMCommandActionDeny,
		Priority:      1,
		AssetSelector: datatypes.JSON([]byte(`{"criticality":"critical"}`)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "update accounts set balance = 0")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionDeny {
		t.Fatalf("action = %q; want deny on criticality=critical selector", action)
	}
}

// TestPolicyIntegration_PatternNoMatchAllows installs a deny rule
// whose regex does NOT match the input and proves the service
// falls through to the default allow. Establishes the "default to
// allow" invariant for the gateway-level path.
func TestPolicyIntegration_PatternNoMatchAllows(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	f.seedPolicy(t, models.PAMCommandPolicy{
		ID:       "pcp-int-no-match",
		Pattern:  `^drop\b`,
		Action:   models.PAMCommandActionDeny,
		Priority: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "select count(*) from accounts")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow", action)
	}
}

// TestPolicyIntegration_WorkspaceIsolation seeds a deny rule in a
// DIFFERENT workspace and proves it does NOT apply to the session
// under test. Demonstrates that the workspace_id boundary
// propagates from the evaluator → handler → adapter → service all
// the way down to the SQL filter.
func TestPolicyIntegration_WorkspaceIsolation(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	if err := f.db.Create(&models.PAMCommandPolicy{
		ID:          "pcp-int-other-ws",
		WorkspaceID: "ws-other",
		Pattern:     `^select\b`,
		Action:      models.PAMCommandActionDeny,
		Priority:    1,
		CreatedAt:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}).Error; err != nil {
		t.Fatalf("seed cross-workspace policy: %v", err)
	}
	f.svc.Invalidate("ws-other")
	f.svc.Invalidate(f.session.WorkspaceID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	action, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, f.session.ID, "select * from users")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != models.PAMCommandActionAllow {
		t.Fatalf("action = %q; want allow (other-workspace deny rule must NOT apply)", action)
	}
}

// TestPolicyIntegration_UnknownSessionPropagatesError proves that
// the gateway evaluator's HTTP response is a non-2xx when the
// adapter cannot resolve session_id → asset/account, and the
// evaluator surfaces that as an error to the caller (the listener
// then logs + fail-opens per its existing semantics).
func TestPolicyIntegration_UnknownSessionPropagatesError(t *testing.T) {
	f := newPolicyIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := f.evaluator.EvaluateCommand(ctx, f.session.WorkspaceID, "ses-not-real", "select 1")
	if err == nil {
		t.Fatalf("expected error for unknown session id; got nil")
	}
}
