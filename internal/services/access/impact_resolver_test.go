package access

import (
	"context"
	"testing"

	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestResolveImpact_HappyPath seeds two teams matching the same
// attribute selector, with overlapping members, plus a mix of matching
// and non-matching resources. The resolver must produce
// (deduped, sorted) member and resource lists.
func TestResolveImpact_HappyPath(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-eng-a", "Eng A", map[string]string{"department": "engineering"})
	seedTeam(t, db, ws, "team-eng-b", "Eng B", map[string]string{"department": "engineering", "team": "platform"})
	seedTeam(t, db, ws, "team-sales", "Sales", map[string]string{"department": "sales"})

	seedTeamMember(t, db, "team-eng-a", "user-alice")
	seedTeamMember(t, db, "team-eng-a", "user-bob")
	seedTeamMember(t, db, "team-eng-b", "user-bob") // duplicate user — must dedup
	seedTeamMember(t, db, "team-eng-b", "user-carol")
	seedTeamMember(t, db, "team-sales", "user-dan") // unrelated team

	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", nil)
	seedResource(t, db, ws, "res-b", "prod-db-02", "ssh-host", nil)
	seedResource(t, db, ws, "res-c", "drive-folder", "saas-app", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFT01   ",
		WorkspaceID:        ws,
		Name:               "engineers ssh",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedTeams) != 2 {
		t.Errorf("AffectedTeams = %v; want 2 (Eng A + Eng B)", report.AffectedTeams)
	}
	// Members deduped: {alice, bob, carol}; sales user excluded.
	if len(report.AffectedMembers) != 3 {
		t.Errorf("AffectedMembers = %v; want 3", report.AffectedMembers)
	}
	for _, want := range []string{"user-alice", "user-bob", "user-carol"} {
		found := false
		for _, got := range report.AffectedMembers {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing member %q in %v", want, report.AffectedMembers)
		}
	}
	if len(report.AffectedResources) != 2 {
		t.Errorf("AffectedResources = %v; want 2 (ssh-host only)", report.AffectedResources)
	}
	if report.MembersGainingAccess != 3 {
		t.Errorf("MembersGainingAccess = %d; want 3", report.MembersGainingAccess)
	}
	if report.NewResourcesGranted != 2 {
		t.Errorf("NewResourcesGranted = %d; want 2", report.NewResourcesGranted)
	}
	// Drafts don't carry conflicts in the bare resolver; conflict
	// detection runs separately via ConflictDetector.
	if len(report.ConflictsWithExisting) != 0 {
		t.Errorf("ConflictsWithExisting = %v; want []", report.ConflictsWithExisting)
	}
}

// TestResolveImpact_NoMatchingTeam returns a report with zero affected
// members and resources when nothing matches the selector.
func TestResolveImpact_NoMatchingTeam(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-sales", "Sales", map[string]string{"department": "sales"})
	seedTeamMember(t, db, "team-sales", "user-dan")
	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFT01   ",
		WorkspaceID:        ws,
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}
	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedTeams) != 0 || len(report.AffectedMembers) != 0 {
		t.Errorf("expected zero affected; got teams=%v members=%v", report.AffectedTeams, report.AffectedMembers)
	}
}

// TestResolveImpact_RejectsNilPolicy is a basic defensive guard test.
func TestResolveImpact_RejectsNilPolicy(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	if _, err := r.ResolveImpact(context.Background(), nil); err == nil {
		t.Fatal("expected error on nil policy")
	}
}

// TestResolveImpact_ResourceSelectorByExternalID verifies the
// "external_id" matcher key returns just the named resource.
func TestResolveImpact_ResourceSelectorByExternalID(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Eng", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", nil)
	seedResource(t, db, ws, "res-b", "prod-db-02", "ssh-host", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFT01   ",
		WorkspaceID:        ws,
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"external_id": "prod-db-02"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}
	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedResources) != 1 || report.AffectedResources[0] != "prod-db-02" {
		t.Errorf("AffectedResources = %v; want [prod-db-02]", report.AffectedResources)
	}
}

// TestResolveImpact_ResourceSelectorByTag verifies the tag-based
// matching path (any unrecognised key looks at Resource.Tags).
func TestResolveImpact_ResourceSelectorByTag(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Eng", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", map[string]string{"env": "prod"})
	seedResource(t, db, ws, "res-b", "stg-db-01", "ssh-host", map[string]string{"env": "staging"})

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFT01   ",
		WorkspaceID:        ws,
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"env": "prod"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}
	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedResources) != 1 || report.AffectedResources[0] != "prod-db-01" {
		t.Errorf("AffectedResources = %v; want [prod-db-01]", report.AffectedResources)
	}
}

// jsonObj is a small helper that returns datatypes.JSON ready for
// direct assignment to a *models.Policy field.
func jsonObj(t *testing.T, v map[string]string) datatypes.JSON {
	t.Helper()
	return datatypes.JSON(rawJSON(t, v))
}
