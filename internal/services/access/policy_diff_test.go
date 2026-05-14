package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestPolicyService_DiffPolicy_HappyPath: create a draft, simulate
// it, then diff it. Asserts the report carries the draft policy,
// the before/after states with the correct AppliesDraft flag, and
// the delta block.
func TestPolicyService_DiffPolicy_HappyPath(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}

	report, err := svc.DiffPolicy(context.Background(), ws, draft.ID)
	if err != nil {
		t.Fatalf("DiffPolicy: %v", err)
	}
	if report == nil {
		t.Fatal("DiffPolicy returned nil report")
	}
	if report.Policy == nil || report.Policy.ID != draft.ID {
		t.Fatalf("Policy.ID = %v; want %q", report.Policy, draft.ID)
	}
	if report.Before.AppliesDraft {
		t.Fatal("Before.AppliesDraft = true; want false")
	}
	if !report.After.AppliesDraft {
		t.Fatal("After.AppliesDraft = false; want true")
	}
	if report.Before.Action != models.PolicyActionAllow || report.After.Action != models.PolicyActionAllow {
		t.Fatalf("actions = (%q, %q); want both %q", report.Before.Action, report.After.Action, models.PolicyActionAllow)
	}
	if report.Delta == nil {
		t.Fatal("Delta = nil; want non-nil ImpactReport from Simulate")
	}
	// Allow-action: After is a superset of Before.
	if !isSuperset(report.After.Members, report.Before.Members) {
		t.Fatalf("After.Members %v is not a superset of Before.Members %v", report.After.Members, report.Before.Members)
	}
	if !isSuperset(report.After.Resources, report.Before.Resources) {
		t.Fatalf("After.Resources %v is not a superset of Before.Resources %v", report.After.Resources, report.Before.Resources)
	}
	// The draft's AffectedMembers (alice) must appear in After.Members.
	if !diffTestContains(report.After.Members, "user-alice") {
		t.Fatalf("After.Members %v missing the draft's affected member 'user-alice'", report.After.Members)
	}
}

// TestPolicyService_DiffPolicy_RequiresSimulate: a draft that has not
// been simulated cannot be diffed. The service returns
// ErrPolicyNotSimulated so the handler can map to 409 Conflict.
func TestPolicyService_DiffPolicy_RequiresSimulate(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	_, err = svc.DiffPolicy(context.Background(), ws, draft.ID)
	if err == nil {
		t.Fatal("DiffPolicy on un-simulated draft returned nil; want ErrPolicyNotSimulated")
	}
	if !errors.Is(err, ErrPolicyNotSimulated) {
		t.Fatalf("DiffPolicy err = %v; want ErrPolicyNotSimulated", err)
	}
}

// TestPolicyService_DiffPolicy_RejectsLivePolicy asserts a live
// policy cannot be diffed: the before/after is degenerate (both
// sides are identical) so the endpoint refuses with
// ErrPolicyNotDraft.
func TestPolicyService_DiffPolicy_RejectsLivePolicy(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if _, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ACTORUSR"); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	_, err = svc.DiffPolicy(context.Background(), ws, draft.ID)
	if err == nil {
		t.Fatal("DiffPolicy on live policy returned nil; want ErrPolicyNotDraft")
	}
	if !errors.Is(err, ErrPolicyNotDraft) {
		t.Fatalf("DiffPolicy err = %v; want ErrPolicyNotDraft", err)
	}
}

// TestPolicyService_DiffPolicy_DenyShrinksScope verifies the deny
// path: a deny-action draft removes members/resources from the
// baseline. We seed a live allow-policy with the same scope so the
// baseline Before has something to remove from, then deny the same
// scope on a draft.
func TestPolicyService_DiffPolicy_DenyShrinksScope(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)

	// Seed a live allow policy targeting engineers + ssh hosts so
	// the baseline Before includes user-alice + prod-db-01.
	liveDraft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("create live draft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, liveDraft.ID); err != nil {
		t.Fatalf("simulate live: %v", err)
	}
	if _, err := svc.Promote(context.Background(), ws, liveDraft.ID, "01H000000000000000ACTORUSR"); err != nil {
		t.Fatalf("promote live: %v", err)
	}

	denyInput := validDraftInput(t)
	denyInput.Name = "engineering ssh deny"
	denyInput.Action = models.PolicyActionDeny
	denyDraft, err := svc.CreateDraft(context.Background(), denyInput)
	if err != nil {
		t.Fatalf("CreateDraft deny: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, denyDraft.ID); err != nil {
		t.Fatalf("Simulate deny: %v", err)
	}

	report, err := svc.DiffPolicy(context.Background(), ws, denyDraft.ID)
	if err != nil {
		t.Fatalf("DiffPolicy deny: %v", err)
	}
	if !diffTestContains(report.Before.Members, "user-alice") {
		t.Fatalf("Before.Members %v should contain user-alice from the live allow policy", report.Before.Members)
	}
	if diffTestContains(report.After.Members, "user-alice") {
		t.Fatalf("After.Members %v should NOT contain user-alice after the deny is projected", report.After.Members)
	}
}

// TestPolicyService_DiffPolicy_ExcludesInactiveLivePolicies verifies
// that a disabled (is_active=false) live policy is NOT counted in the
// Before baseline. An operator paused a live policy precisely so its
// effects no longer apply — including it in the diff baseline would
// inflate the Before column and mislead the Admin UI reviewer.
func TestPolicyService_DiffPolicy_ExcludesInactiveLivePolicies(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)

	// Promote a live allow policy that grants engineers SSH access...
	liveDraft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("create live draft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, liveDraft.ID); err != nil {
		t.Fatalf("simulate live: %v", err)
	}
	if _, err := svc.Promote(context.Background(), ws, liveDraft.ID, "01H000000000000000ACTORUSR"); err != nil {
		t.Fatalf("promote live: %v", err)
	}
	// ...then disable it.
	if err := db.Model(&models.Policy{}).
		Where("id = ?", liveDraft.ID).
		UpdateColumn("is_active", false).Error; err != nil {
		t.Fatalf("disable live policy: %v", err)
	}

	// Diff a deny draft that overlaps the disabled policy's scope.
	denyInput := validDraftInput(t)
	denyInput.Name = "engineering ssh deny"
	denyInput.Action = models.PolicyActionDeny
	denyDraft, err := svc.CreateDraft(context.Background(), denyInput)
	if err != nil {
		t.Fatalf("CreateDraft deny: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, denyDraft.ID); err != nil {
		t.Fatalf("Simulate deny: %v", err)
	}

	report, err := svc.DiffPolicy(context.Background(), ws, denyDraft.ID)
	if err != nil {
		t.Fatalf("DiffPolicy: %v", err)
	}
	if diffTestContains(report.Before.Members, "user-alice") {
		t.Fatalf("Before.Members %v must NOT include user-alice (the only live policy granting access is disabled)", report.Before.Members)
	}
}

// TestPolicyService_DiffPolicy_MalformedDraftImpactReturnsError seeds
// a draft whose draft_impact column is corrupt JSON. The service must
// surface the decode error rather than silently returning a blank
// diff (otherwise the Admin UI would render a misleading "no
// changes" diff).
func TestPolicyService_DiffPolicy_MalformedDraftImpactReturnsError(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"

	svc := NewPolicyService(db)
	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	// Stamp invalid JSON directly via the DB.
	if err := db.Model(&models.Policy{}).
		Where("id = ?", draft.ID).
		UpdateColumn("draft_impact", []byte("{not-json")).Error; err != nil {
		t.Fatalf("inject malformed draft_impact: %v", err)
	}
	if _, err := svc.DiffPolicy(context.Background(), ws, draft.ID); err == nil {
		t.Fatal("DiffPolicy on malformed draft_impact returned nil error; want decode error")
	}
}

func diffTestContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func isSuperset(super, sub []string) bool {
	for _, v := range sub {
		if !diffTestContains(super, v) {
			return false
		}
	}
	return true
}

// rawImpactJSON is referenced from a future test in the same package
// to confirm json.Unmarshal-based ImpactReport decoding stays
// stable. Keeping the helper here avoids re-importing encoding/json
// in policy_diff_test.go variants.
var _ = json.Unmarshal
