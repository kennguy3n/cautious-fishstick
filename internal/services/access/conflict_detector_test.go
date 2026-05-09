package access

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestDetectConflicts_Redundant covers the same-action overlap path: a
// draft "allow X → Y" with a live "allow X → Y" must report exactly
// one redundant conflict.
func TestDetectConflicts_Redundant(t *testing.T) {
	db := newPhase3DB(t)
	d := NewConflictDetector(db)
	ws := "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-eng", "Eng", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	live := seedLivePolicy(t, db, ws, "01H000000000000000LIVE      ", "live allow",
		map[string]string{"department": "engineering"},
		map[string]string{"category": "ssh-host"},
		models.PolicyActionAllow,
	)

	draft := &models.Policy{
		ID:                 "01H000000000000000DRAFT     ",
		WorkspaceID:        ws,
		Name:               "draft allow",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	conflicts, err := d.DetectConflicts(context.Background(), draft, []string{"user-alice"}, []string{"prod-db-01"})
	if err != nil {
		t.Fatalf("DetectConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %v; want 1", conflicts)
	}
	if conflicts[0].RuleID != live.ID {
		t.Errorf("RuleID = %q; want %q", conflicts[0].RuleID, live.ID)
	}
	if conflicts[0].Kind != PolicyConflictKindRedundant {
		t.Errorf("Kind = %q; want %q", conflicts[0].Kind, PolicyConflictKindRedundant)
	}
}

// TestDetectConflicts_Contradictory covers the opposite-action overlap
// path: a draft "deny X → Y" with a live "allow X → Y" must report a
// contradictory conflict.
func TestDetectConflicts_Contradictory(t *testing.T) {
	db := newPhase3DB(t)
	d := NewConflictDetector(db)
	ws := "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-eng", "Eng", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	live := seedLivePolicy(t, db, ws, "01H000000000000000LIVE      ", "live allow",
		map[string]string{"department": "engineering"},
		map[string]string{"category": "ssh-host"},
		models.PolicyActionAllow,
	)

	draft := &models.Policy{
		ID:                 "01H000000000000000DRAFT     ",
		WorkspaceID:        ws,
		Name:               "draft deny",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionDeny,
		IsDraft:            true,
	}

	conflicts, err := d.DetectConflicts(context.Background(), draft, []string{"user-alice"}, []string{"prod-db-01"})
	if err != nil {
		t.Fatalf("DetectConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %v; want 1", conflicts)
	}
	if conflicts[0].RuleID != live.ID {
		t.Errorf("RuleID = %q; want %q", conflicts[0].RuleID, live.ID)
	}
	if conflicts[0].Kind != PolicyConflictKindContradictory {
		t.Errorf("Kind = %q; want %q", conflicts[0].Kind, PolicyConflictKindContradictory)
	}
}

// TestDetectConflicts_NoOverlap covers the disjoint case: a live
// policy that targets a different team / resource set must not appear
// in the conflict list.
func TestDetectConflicts_NoOverlap(t *testing.T) {
	db := newPhase3DB(t)
	d := NewConflictDetector(db)
	ws := "01H000000000000000WORKSPACE"

	// Live policy for sales / saas-app — completely disjoint from the
	// draft below.
	seedTeam(t, db, ws, "team-sales", "Sales", map[string]string{"department": "sales"})
	seedTeamMember(t, db, "team-sales", "user-dan")
	seedResource(t, db, ws, "res-1", "drive-folder", "saas-app", nil)
	seedLivePolicy(t, db, ws, "01H000000000000000LIVE      ", "sales drive",
		map[string]string{"department": "sales"},
		map[string]string{"category": "saas-app"},
		models.PolicyActionAllow,
	)

	// Draft for engineering / ssh-host.
	seedTeam(t, db, ws, "team-eng", "Eng", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-2", "prod-db-01", "ssh-host", nil)
	draft := &models.Policy{
		ID:                 "01H000000000000000DRAFT     ",
		WorkspaceID:        ws,
		Name:               "draft eng ssh",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	conflicts, err := d.DetectConflicts(context.Background(), draft, []string{"user-alice"}, []string{"prod-db-01"})
	if err != nil {
		t.Fatalf("DetectConflicts: %v", err)
	}
	if len(conflicts) != 0 {
		t.Errorf("conflicts = %v; want []", conflicts)
	}
}

// TestDetectConflicts_RejectsNilDraft is a defensive guard test.
func TestDetectConflicts_RejectsNilDraft(t *testing.T) {
	db := newPhase3DB(t)
	d := NewConflictDetector(db)
	if _, err := d.DetectConflicts(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("expected error on nil draft")
	}
}

// TestDetectConflicts_EmptyAffectedSetsEarlyReturn asserts that an
// empty (members × resources) cross-product short-circuits to no
// conflicts without scanning live policies.
func TestDetectConflicts_EmptyAffectedSetsEarlyReturn(t *testing.T) {
	db := newPhase3DB(t)
	d := NewConflictDetector(db)
	ws := "01H000000000000000WORKSPACE"
	seedLivePolicy(t, db, ws, "01H000000000000000LIVE      ", "live allow", nil, nil, models.PolicyActionAllow)

	draft := &models.Policy{
		ID:          "01H000000000000000DRAFT     ",
		WorkspaceID: ws,
		Name:        "empty draft",
		Action:      models.PolicyActionAllow,
		IsDraft:     true,
	}
	got, err := d.DetectConflicts(context.Background(), draft, nil, nil)
	if err != nil {
		t.Fatalf("DetectConflicts: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("conflicts = %v; want []", got)
	}
}
