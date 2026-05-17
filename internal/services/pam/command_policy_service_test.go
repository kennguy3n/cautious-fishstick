package pam

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// seedPolicy inserts one pam_command_policies row with the supplied
// fields. CreatedAt is pinned to a deterministic timestamp so the
// (priority asc, created_at asc) tiebreaker is reproducible across
// runs. Tests pass a non-empty CreatedAtOffset to control insertion
// order under the same priority.
func seedPolicy(t *testing.T, svc *PAMCommandPolicyService, p models.PAMCommandPolicy) models.PAMCommandPolicy {
	t.Helper()
	if p.ID == "" {
		t.Fatalf("seedPolicy: ID is required")
	}
	if p.WorkspaceID == "" {
		t.Fatalf("seedPolicy: WorkspaceID is required")
	}
	if p.Action == "" {
		p.Action = models.PAMCommandActionAllow
	}
	if p.Priority == 0 {
		p.Priority = 100
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	if err := svc.db.Create(&p).Error; err != nil {
		t.Fatalf("create policy %s: %v", p.ID, err)
	}
	// Drop any cached compiled rules so the next EvaluateCommand
	// re-fetches under the test's exact state.
	svc.Invalidate(p.WorkspaceID)
	return p
}

func newCommandPolicyFixture(t *testing.T) *PAMCommandPolicyService {
	t.Helper()
	svc, err := NewPAMCommandPolicyService(newPAMDB(t))
	if err != nil {
		t.Fatalf("NewPAMCommandPolicyService: %v", err)
	}
	return svc
}

func TestNewPAMCommandPolicyService_RequiresDB(t *testing.T) {
	if _, err := NewPAMCommandPolicyService(nil); !errors.Is(err, ErrPAMCommandPolicyMissingDB) {
		t.Fatalf("expected ErrPAMCommandPolicyMissingDB, got %v", err)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_WorkspaceRequired(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	_, err := svc.EvaluateCommand(context.Background(), "  ", CommandPolicyContext{}, "ls /etc")
	if err == nil {
		t.Fatalf("expected error on empty workspace_id")
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_EmptyInputAllowed(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-deny-everything", WorkspaceID: "ws-1",
		Pattern: ".*", Action: models.PAMCommandActionDeny, Priority: 1,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "   ")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("empty input must short-circuit allow, got %q", got.Action)
	}
	if got.MatchedPolicy != nil {
		t.Fatalf("MatchedPolicy should be nil for empty input, got %+v", got.MatchedPolicy)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_NoPoliciesAllows(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls /etc")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("Action = %q; want allow", got.Action)
	}
	if got.MatchedPolicy != nil {
		t.Fatalf("MatchedPolicy should be nil for no-match, got %+v", got.MatchedPolicy)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_DenyMatch(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	rule := seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-deny-rm", WorkspaceID: "ws-1",
		Pattern: `^rm\s+-rf\s+/`, Action: models.PAMCommandActionDeny, Priority: 10,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "rm -rf /var/log")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("Action = %q; want deny", got.Action)
	}
	if got.MatchedPolicy == nil || got.MatchedPolicy.ID != rule.ID {
		t.Fatalf("MatchedPolicy = %+v; want id=%s", got.MatchedPolicy, rule.ID)
	}
	if got.Reason == "" {
		t.Fatalf("Reason should not be empty for deny match")
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_StepUpMatch(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-stepup-sudo", WorkspaceID: "ws-1",
		Pattern: `(?i)^sudo\s`, Action: models.PAMCommandActionStepUp, Priority: 5,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "sudo systemctl restart nginx")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionStepUp {
		t.Fatalf("Action = %q; want step_up", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_AllowMatch(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-allow-ls", WorkspaceID: "ws-1",
		Pattern: `^ls\b`, Action: models.PAMCommandActionAllow, Priority: 10,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls /etc")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("Action = %q; want allow", got.Action)
	}
	// An explicit allow rule matched, so MatchedPolicy MUST be non-nil
	// — the gateway uses that to stamp the policy ID into the audit
	// trail.
	if got.MatchedPolicy == nil {
		t.Fatalf("MatchedPolicy should be non-nil for explicit allow")
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_PriorityOrdering(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	// Two rules that both match "rm -rf /". The lower priority value
	// (== higher priority) must win.
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-low-priority-deny", WorkspaceID: "ws-1",
		Pattern: `rm`, Action: models.PAMCommandActionDeny, Priority: 50,
	})
	winner := seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-high-priority-stepup", WorkspaceID: "ws-1",
		Pattern: `rm`, Action: models.PAMCommandActionStepUp, Priority: 10,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionStepUp {
		t.Fatalf("Action = %q; want step_up (winner)", got.Action)
	}
	if got.MatchedPolicy == nil || got.MatchedPolicy.ID != winner.ID {
		t.Fatalf("MatchedPolicy = %+v; want id=%s", got.MatchedPolicy, winner.ID)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_CreatedAtTiebreaker(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	// Same priority — older row wins.
	winner := seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-older", WorkspaceID: "ws-1",
		Pattern: `^touch\b`, Action: models.PAMCommandActionAllow, Priority: 50,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-newer", WorkspaceID: "ws-1",
		Pattern: `^touch\b`, Action: models.PAMCommandActionDeny, Priority: 50,
		CreatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "touch /tmp/x")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.MatchedPolicy == nil || got.MatchedPolicy.ID != winner.ID {
		t.Fatalf("MatchedPolicy = %+v; want id=%s (older row wins)", got.MatchedPolicy, winner.ID)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_WorkspaceIsolation(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-ws-1-deny", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 1,
	})
	// Commands inside ws-2 must not pick up the ws-1 deny rule.
	got, err := svc.EvaluateCommand(context.Background(), "ws-2", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("Action = %q; want allow (cross-workspace)", got.Action)
	}
	if got.MatchedPolicy != nil {
		t.Fatalf("MatchedPolicy should be nil for cross-workspace, got %+v", got.MatchedPolicy)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_AssetSelectorByID(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-asset-deny", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 10,
		AssetSelector: datatypes.JSON([]byte(`{"id": "asset-prod"}`)),
	})
	// Wrong asset → no match.
	got, err := svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AssetID: "asset-dev"}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("wrong asset must not match: Action = %q", got.Action)
	}
	// Right asset → match.
	got, err = svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AssetID: "asset-prod"}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("right asset must match: Action = %q", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_AssetSelectorByCriticality(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-crit-deny", WorkspaceID: "ws-1",
		Pattern: `^drop\s+database`, Action: models.PAMCommandActionDeny, Priority: 10,
		AssetSelector: datatypes.JSON([]byte(`{"criticality": "critical"}`)),
	})
	// medium asset → allow.
	got, err := svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AssetID: "asset-1", AssetMetadata: map[string]string{"criticality": "medium"}},
		"drop database app")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("medium-criticality asset must not match critical rule: %q", got.Action)
	}
	// critical asset → deny.
	got, err = svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AssetID: "asset-2", AssetMetadata: map[string]string{"criticality": "critical"}},
		"drop database app")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("critical asset must match: %q", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_AccountSelector(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-account-deny", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 10,
		AccountSelector: datatypes.JSON([]byte(`{"id": "account-root"}`)),
	})
	// Non-root account → allow.
	got, err := svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AccountID: "account-readonly"}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("non-root account must not match: %q", got.Action)
	}
	// Root account → deny.
	got, err = svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AccountID: "account-root"}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("root account must match: %q", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_MultiKeySelectorAND(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-multi-deny", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 10,
		AssetSelector: datatypes.JSON([]byte(`{"criticality": "critical", "env": "prod"}`)),
	})
	// Only criticality matches → no match (AND semantics).
	got, err := svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AssetMetadata: map[string]string{"criticality": "critical", "env": "dev"}},
		"ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("partial-match must not deny: %q", got.Action)
	}
	// Both match → deny.
	got, err = svc.EvaluateCommand(context.Background(), "ws-1",
		CommandPolicyContext{AssetMetadata: map[string]string{"criticality": "critical", "env": "prod"}},
		"ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("full match must deny: %q", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_EmptySelectorMatchesEverything(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-universal", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 10,
		// AssetSelector & AccountSelector intentionally empty.
	})
	cases := []CommandPolicyContext{
		{},
		{AssetID: "anything"},
		{AccountID: "anyone", AccountMetadata: map[string]string{"role": "ops"}},
	}
	for _, c := range cases {
		got, err := svc.EvaluateCommand(context.Background(), "ws-1", c, "anything")
		if err != nil {
			t.Fatalf("EvaluateCommand: %v", err)
		}
		if got.Action != models.PAMCommandActionDeny {
			t.Fatalf("empty selector must match context %+v, got %q", c, got.Action)
		}
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_SkipsInvalidRegex(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	// First rule has a broken regex — loadCompiled drops it with a
	// log warning and continues with the next rule.
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-broken", WorkspaceID: "ws-1",
		Pattern: `[invalid`, Action: models.PAMCommandActionDeny, Priority: 1,
	})
	winner := seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-good", WorkspaceID: "ws-1",
		Pattern: `^rm\b`, Action: models.PAMCommandActionDeny, Priority: 50,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "rm foo")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.MatchedPolicy == nil || got.MatchedPolicy.ID != winner.ID {
		t.Fatalf("broken-regex rule must be skipped; MatchedPolicy = %+v", got.MatchedPolicy)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_SkipsInvalidAction(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-bad-action", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: "lol-no", Priority: 1,
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("invalid-action rule must be skipped: %q", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_SoftDeletedRulesIgnored(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	rule := seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-deleted", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 1,
	})
	// Soft-delete via gorm — the DeletedAt index causes the row to
	// disappear from Find queries, which is the contract we rely on
	// in loadCompiled.
	if err := svc.db.Delete(&models.PAMCommandPolicy{}, "id = ?", rule.ID).Error; err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	svc.Invalidate("ws-1")
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("soft-deleted rule must not match: %q", got.Action)
	}
}

func TestPAMCommandPolicyService_EvaluateCommand_CacheReloadsAfterTTL(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	// Pin "now" so we can advance time without sleeping.
	fakeNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNow(func() time.Time { return fakeNow })
	svc.SetCacheTTL(1 * time.Minute)

	// Initial load — no rules.
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("Action = %q; want allow", got.Action)
	}

	// Add a deny rule but DO NOT invalidate the cache. Within the
	// TTL the rule is invisible.
	if err := svc.db.Create(&models.PAMCommandPolicy{
		ID: "pcp-late", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 1,
		CreatedAt: fakeNow, UpdatedAt: fakeNow,
	}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err = svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("rule must not be visible within TTL: %q", got.Action)
	}

	// Advance past the TTL — next EvaluateCommand re-loads.
	fakeNow = fakeNow.Add(2 * time.Minute)
	got, err = svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("rule must be visible after TTL: %q", got.Action)
	}
}

func TestPAMCommandPolicyService_Invalidate_ForcesReload(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	svc.SetCacheTTL(10 * time.Minute)

	// Warm the cache with no rules.
	if _, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls"); err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}

	// Insert a rule + invalidate — next call must re-fetch.
	if err := svc.db.Create(&models.PAMCommandPolicy{
		ID: "pcp-after-invalidate", WorkspaceID: "ws-1",
		Pattern: `.*`, Action: models.PAMCommandActionDeny, Priority: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	svc.Invalidate("ws-1")

	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.Action != models.PAMCommandActionDeny {
		t.Fatalf("Invalidate must force reload; got %q", got.Action)
	}

	// Empty-string invalidate drops every workspace.
	svc.Invalidate("")
	svc.mu.RLock()
	if len(svc.cache) != 0 {
		svc.mu.RUnlock()
		t.Fatalf("Invalidate(\"\") must drop every entry, got %d remaining", len(svc.cache))
	}
	svc.mu.RUnlock()
}

func TestPAMCommandPolicyService_EvaluateCommand_FirstRuleWins(t *testing.T) {
	svc := newCommandPolicyFixture(t)
	// Two priority-1 rules — both match "ls". The first-inserted
	// wins thanks to the created_at tiebreaker.
	winner := seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-first", WorkspaceID: "ws-1",
		Pattern: `^ls\b`, Action: models.PAMCommandActionStepUp, Priority: 1,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	seedPolicy(t, svc, models.PAMCommandPolicy{
		ID: "pcp-second", WorkspaceID: "ws-1",
		Pattern: `^ls\b`, Action: models.PAMCommandActionDeny, Priority: 1,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
	})
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "ls /etc")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if got.MatchedPolicy == nil || got.MatchedPolicy.ID != winner.ID {
		t.Fatalf("first-rule-wins broken: MatchedPolicy = %+v", got.MatchedPolicy)
	}
}

func TestPAMCommandPolicyService_NilReceiver_AllowsEverything(t *testing.T) {
	var svc *PAMCommandPolicyService
	got, err := svc.EvaluateCommand(context.Background(), "ws-1", CommandPolicyContext{}, "anything")
	if err != nil {
		t.Fatalf("nil-receiver must not error, got %v", err)
	}
	if got.Action != models.PAMCommandActionAllow {
		t.Fatalf("nil-receiver must allow, got %q", got.Action)
	}
}

func TestDecodeSelector_VariousShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{name: "empty bytes", raw: "", want: nil},
		{name: "explicit empty object", raw: "{}", want: nil},
		{name: "null literal", raw: "null", want: nil},
		{name: "string value", raw: `{"id": "asset-1"}`, want: map[string]string{"id": "asset-1"}},
		{name: "bool true", raw: `{"emergency": true}`, want: map[string]string{"emergency": "true"}},
		{name: "bool false", raw: `{"emergency": false}`, want: map[string]string{"emergency": "false"}},
		{name: "integer", raw: `{"priority": 100}`, want: map[string]string{"priority": "100"}},
		{name: "float", raw: `{"factor": 1.5}`, want: map[string]string{"factor": "1.5"}},
		{name: "null value dropped", raw: `{"a": null, "b": "x"}`, want: map[string]string{"b": "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSelector([]byte(tc.raw))
			if err != nil {
				t.Fatalf("decodeSelector: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d; want %d (got %+v want %+v)", len(got), len(tc.want), got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("key %q = %q; want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestDecodeSelector_MalformedJSONErrors(t *testing.T) {
	if _, err := decodeSelector([]byte(`{not-json`)); err == nil {
		t.Fatalf("expected error on malformed JSON")
	}
}

func TestSelectorMatches_NilSelectorAlwaysMatches(t *testing.T) {
	if !selectorMatches(nil, "asset-1", nil) {
		t.Fatalf("nil selector must match")
	}
	if !selectorMatches(nil, "", map[string]string{"k": "v"}) {
		t.Fatalf("nil selector must match even with non-empty metadata")
	}
}

func TestSelectorMatches_MissingMetadataKeyMisses(t *testing.T) {
	sel := map[string]string{"criticality": "critical"}
	if selectorMatches(sel, "asset-1", nil) {
		t.Fatalf("missing metadata key must miss")
	}
	if selectorMatches(sel, "asset-1", map[string]string{"env": "prod"}) {
		t.Fatalf("metadata without selector key must miss")
	}
}

func TestDecisionReasonFor_TruncatesLongInput(t *testing.T) {
	row := &models.PAMCommandPolicy{ID: "pcp-1", Action: models.PAMCommandActionDeny}
	long := ""
	for range [200]int{} {
		long += "x"
	}
	got := decisionReasonFor(row, long)
	if len(got) == 0 {
		t.Fatalf("reason should not be empty")
	}
	// The truncated form must be a strict prefix of the full input
	// plus the ellipsis marker.
	if !contains(got, "...") {
		t.Fatalf("long input should be truncated with ellipsis, got %q", got)
	}
}

// contains is a tiny strings.Contains stand-in so the test file
// doesn't need to import strings just for one assertion.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
