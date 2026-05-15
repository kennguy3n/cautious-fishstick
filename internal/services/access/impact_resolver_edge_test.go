package access

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestResolveImpact_EmptyTeam asserts the resolver behaves
// gracefully when a team matches the attribute selector but has no
// members — the team appears in AffectedTeams but contributes zero
// members and zero MembersGainingAccess.
func TestResolveImpact_EmptyTeam(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000EMPTYTEAM"

	seedTeam(t, db, ws, "team-empty", "Empty Team", map[string]string{"department": "engineering"})
	// no seedTeamMember calls — team is intentionally empty
	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFTEMPTY",
		WorkspaceID:        ws,
		Name:               "empty-team-rule",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedTeams) != 1 {
		t.Errorf("AffectedTeams = %v; want 1 (empty team still surfaces)", report.AffectedTeams)
	}
	if len(report.AffectedMembers) != 0 {
		t.Errorf("AffectedMembers = %v; want 0", report.AffectedMembers)
	}
	if report.MembersGainingAccess != 0 {
		t.Errorf("MembersGainingAccess = %d; want 0", report.MembersGainingAccess)
	}
	// NewResourcesGranted reflects the resource-selector match count
	// independently of team membership — operators want to know "this
	// rule would have granted N resources, but the team is empty so
	// nobody benefits". The two counts together signal the empty-team
	// case cleanly.
	if report.NewResourcesGranted != 1 {
		t.Errorf("NewResourcesGranted = %d; want 1 (selector matched, even if no members)", report.NewResourcesGranted)
	}
}

// TestResolveImpact_ZeroResourcesMatched asserts the resolver
// returns an empty AffectedResources list and zero grants when the
// resource selector matches nothing — even if the attribute
// selector matches a team with members.
func TestResolveImpact_ZeroResourcesMatched(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000NORESOURCE"

	seedTeam(t, db, ws, "team-eng", "Eng", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-a", "drive-folder", "saas-app", nil)
	seedResource(t, db, ws, "res-b", "ec2-instance", "compute", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFTNORES",
		WorkspaceID:        ws,
		Name:               "no-resources-rule",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedResources) != 0 {
		t.Errorf("AffectedResources = %v; want 0", report.AffectedResources)
	}
	if report.NewResourcesGranted != 0 {
		t.Errorf("NewResourcesGranted = %d; want 0", report.NewResourcesGranted)
	}
	// The team still surfaces in AffectedTeams because the attribute
	// selector matched — operators want to see "this rule selects
	// engineering but resolves to zero resources, did you forget to
	// tag them?".
	if len(report.AffectedTeams) != 1 {
		t.Errorf("AffectedTeams = %v; want 1", report.AffectedTeams)
	}
}

// TestResolveImpact_VeryLargeTeam asserts the resolver does not
// truncate or drop members when the team expansion is large.
// 200 members exercises the inner loop without making the test
// slow; the assertion is "every seeded user shows up" — not a
// pointless count tautology.
func TestResolveImpact_VeryLargeTeam(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000LARGETEAM0"

	seedTeam(t, db, ws, "team-massive", "Massive", map[string]string{"department": "engineering"})
	const N = 200
	want := make(map[string]bool, N)
	for i := 0; i < N; i++ {
		uid := fmt.Sprintf("user-%04d", i)
		seedTeamMember(t, db, "team-massive", uid)
		want[uid] = true
	}
	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFTLARGE",
		WorkspaceID:        ws,
		Name:               "massive-team-rule",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if len(report.AffectedMembers) != N {
		t.Errorf("AffectedMembers count = %d; want %d", len(report.AffectedMembers), N)
	}
	for _, got := range report.AffectedMembers {
		if !want[got] {
			t.Errorf("unexpected member in AffectedMembers: %q", got)
		}
	}
	// MembersGainingAccess must match the unique-members count; a
	// regression that double-counts members would show up here.
	if report.MembersGainingAccess != N {
		t.Errorf("MembersGainingAccess = %d; want %d", report.MembersGainingAccess, N)
	}
	// Surface that the affected-members slice is deterministic
	// (sorted) — admin UI relies on it for stable diff rendering.
	if !sort.StringsAreSorted(report.AffectedMembers) {
		t.Errorf("AffectedMembers not sorted: %v", report.AffectedMembers[:5])
	}
}

// TestResolveImpact_OverlappingTeamMembership asserts a user who
// belongs to multiple matching teams shows up exactly once in
// AffectedMembers — the classic "department=engineering AND
// team=platform" overlap that doubles up on members in a naive
// implementation. (The docs/architecture.md §6 contract says members
// are deduped across teams.) This is the closest practical
// regression test for "circular team membership" — Phase 11 teams
// have no parent_team_id column, so true circularity is structurally
// impossible at the schema layer. Overlapping membership is the
// real-world manifestation of the same bug class.
func TestResolveImpact_OverlappingTeamMembership(t *testing.T) {
	db := newPhase3DB(t)
	r := NewImpactResolver(db)
	ws := "01H000000000000000OVERLAP000"

	// Two teams that both match the selector. user-shared belongs to
	// both — the resolver must dedupe.
	seedTeam(t, db, ws, "team-eng-a", "Eng A", map[string]string{"department": "engineering"})
	seedTeam(t, db, ws, "team-eng-b", "Eng B", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng-a", "user-shared")
	seedTeamMember(t, db, "team-eng-b", "user-shared")
	seedTeamMember(t, db, "team-eng-a", "user-only-a")
	seedTeamMember(t, db, "team-eng-b", "user-only-b")
	seedResource(t, db, ws, "res-a", "prod-db-01", "ssh-host", nil)

	policy := &models.Policy{
		ID:                 "01H000000000000000DRAFTOVERLAP",
		WorkspaceID:        ws,
		Name:               "overlap-rule",
		AttributesSelector: jsonObj(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   jsonObj(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
		IsDraft:            true,
	}

	report, err := r.ResolveImpact(context.Background(), policy)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	// Expect 3 unique members: shared, only-a, only-b.
	if len(report.AffectedMembers) != 3 {
		t.Errorf("AffectedMembers = %v; want 3 unique", report.AffectedMembers)
	}
	seen := map[string]int{}
	for _, m := range report.AffectedMembers {
		seen[m]++
	}
	for m, count := range seen {
		if count != 1 {
			t.Errorf("member %q appears %d times; want 1", m, count)
		}
	}
}
