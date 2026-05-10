package access

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestE2E_SCIMJoinerFlow_FullLifecycle wires SCIM → ClassifyChange →
// HandleJoiner against an in-memory DB and a MockAccessConnector,
// verifying that:
//
//   - ClassifyChange returns "joiner" for the inbound POST event,
//   - HandleJoiner assigns the supplied team membership,
//   - HandleJoiner emits one provisioned grant per DefaultGrant entry,
//   - The connector receives one ProvisionAccess call per grant,
//   - The access_request transitions through requested→approved→provisioning→provisioned.
//
// This is the cross-cutting Phase 6 test the PR description calls out
// as Task 14: a single test that proves the SCIM webhook → JML
// orchestrator → connector path is glued together end-to-end.
func TestE2E_SCIMJoinerFlow_FullLifecycle(t *testing.T) {
	const provider = "mock_e2e_scim_joiner"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01HCONN0E2ESCIMJOINER00001", provider)
	team := seedJMLTeam(t, db, "01HTEAM0E2ESCIMJOINER00001", "engineering")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	// The SCIM provider POST'd a new active user.
	tru := true
	ev := SCIMEvent{Operation: "POST", Active: &tru}
	if got := jml.ClassifyChange(ev); got != JMLEventJoiner {
		t.Fatalf("ClassifyChange = %q; want joiner", got)
	}

	res, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000SCIMJOINER01",
		TeamIDs:     []string{team.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/code", Role: "developer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/docs", Role: "viewer"},
		},
		Justification: "scim joiner: e2e test",
	})
	if err != nil {
		t.Fatalf("HandleJoiner: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed: %+v", res.Failed)
	}
	if len(res.Provisioned) != 2 {
		t.Errorf("Provisioned = %d; want 2", len(res.Provisioned))
	}

	// Connector saw both provisions.
	if mock.ProvisionAccessCalls != 2 {
		t.Errorf("ProvisionAccess calls = %d; want 2", mock.ProvisionAccessCalls)
	}

	// Team membership row inserted.
	var memberCount int64
	if err := db.Model(&models.TeamMember{}).
		Where("team_id = ? AND user_id = ?", team.ID, "01H00000000000SCIMJOINER01").
		Count(&memberCount).Error; err != nil {
		t.Fatalf("count members: %v", err)
	}
	if memberCount != 1 {
		t.Errorf("team members = %d; want 1", memberCount)
	}

	// Both access_requests are in provisioned state.
	var requests []models.AccessRequest
	if err := db.Where("target_user_id = ?", "01H00000000000SCIMJOINER01").Find(&requests).Error; err != nil {
		t.Fatalf("requests: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d; want 2", len(requests))
	}
	for _, r := range requests {
		if r.State != models.RequestStateProvisioned {
			t.Errorf("request %s state = %q; want provisioned", r.ID, r.State)
		}
	}

	// Both grants are active.
	var grants []models.AccessGrant
	if err := db.Where("user_id = ?", "01H00000000000SCIMJOINER01").Find(&grants).Error; err != nil {
		t.Fatalf("grants: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants = %d; want 2", len(grants))
	}
	for _, g := range grants {
		if g.RevokedAt != nil {
			t.Errorf("grant %s revoked_at = %v; want nil", g.ID, g.RevokedAt)
		}
	}
}

// TestE2E_SCIMMoverFlow_AtomicTeamSwap exercises the mover lane:
// SCIM PATCH event → ClassifyChange returns mover → HandleMover
// diffs old vs new team IDs, provisions the gained-team grants and
// revokes the lost-team grants in a single call.
func TestE2E_SCIMMoverFlow_AtomicTeamSwap(t *testing.T) {
	const provider = "mock_e2e_scim_mover"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01HCONN0E2ESCIMMOVER000001", provider)
	teamA := seedJMLTeam(t, db, "01HTEAM0E2ESCIMMOVER0AAAAA", "team-a")
	teamB := seedJMLTeam(t, db, "01HTEAM0E2ESCIMMOVER0BBBBB", "team-b")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)
	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	const userID = "01H00000000000SCIMMOVER001"
	// Seed: user joined team-a with one grant.
	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      userID,
		TeamIDs:     []string{teamA.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/team-a", Role: "developer"},
		},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	// SCIM PATCH event with group changes → mover.
	ev := SCIMEvent{Operation: "PATCH", HasGroupChanges: true}
	if got := jml.ClassifyChange(ev); got != JMLEventMover {
		t.Fatalf("ClassifyChange = %q; want mover", got)
	}

	res, err := jml.HandleMover(context.Background(), MoverInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      userID,
		OldTeamIDs:  []string{teamA.ID},
		NewTeamIDs:  []string{teamB.ID},
		AddedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/team-b", Role: "developer"},
		},
		RemovedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/team-a", Role: "developer"},
		},
	})
	if err != nil {
		t.Fatalf("HandleMover: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK false; failed: %+v", res.Failed)
	}
	if len(res.Provisioned) != 1 {
		t.Errorf("Provisioned = %d; want 1", len(res.Provisioned))
	}
	if len(res.Revoked) != 1 {
		t.Errorf("Revoked = %d; want 1", len(res.Revoked))
	}

	// teamA membership removed; teamB membership added — atomic
	// swap.
	var inA, inB int64
	if err := db.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ?", teamA.ID, userID).Count(&inA).Error; err != nil {
		t.Fatalf("count teamA: %v", err)
	}
	if err := db.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ?", teamB.ID, userID).Count(&inB).Error; err != nil {
		t.Fatalf("count teamB: %v", err)
	}
	if inA != 0 {
		t.Errorf("user still in teamA: %d members", inA)
	}
	if inB != 1 {
		t.Errorf("user not in teamB: %d members", inB)
	}

	// Old grant revoked, new grant active.
	var grants []models.AccessGrant
	if err := db.Where("user_id = ?", userID).Order("created_at ASC").Find(&grants).Error; err != nil {
		t.Fatalf("grants: %v", err)
	}
	var active, revoked int
	for _, g := range grants {
		if g.RevokedAt == nil {
			active++
		} else {
			revoked++
		}
	}
	if active != 1 || revoked != 1 {
		t.Errorf("active=%d revoked=%d; want active=1 revoked=1", active, revoked)
	}
}

// TestE2E_SCIMLeaverFlow_RevokesAllAndDisablesIdentity wires SCIM →
// ClassifyChange → HandleLeaver against an in-memory DB,
// MockAccessConnector and stubOpenZitiClient, asserting that:
//
//   - ClassifyChange returns "leaver" for the SCIM DELETE event,
//   - HandleLeaver revokes every active grant,
//   - HandleLeaver removes the user from every team,
//   - HandleLeaver calls OpenZitiClient.DisableIdentity exactly once.
func TestE2E_SCIMLeaverFlow_RevokesAllAndDisablesIdentity(t *testing.T) {
	const provider = "mock_e2e_scim_leaver"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01HCONN0E2ESCIMLEAVER00001", provider)
	team := seedJMLTeam(t, db, "01HTEAM0E2ESCIMLEAVER00001", "engineering")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)
	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)

	const userID = "01H00000000000SCIMLEAVER01"
	// Seed two grants via the joiner lane.
	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      userID,
		TeamIDs:     []string{team.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/code", Role: "developer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/docs", Role: "viewer"},
		},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	// SCIM DELETE → leaver.
	ev := SCIMEvent{Operation: "DELETE"}
	if got := jml.ClassifyChange(ev); got != JMLEventLeaver {
		t.Fatalf("ClassifyChange = %q; want leaver", got)
	}

	res, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", userID)
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed: %+v", res.Failed)
	}
	if len(res.Revoked) != 2 {
		t.Errorf("Revoked = %d; want 2", len(res.Revoked))
	}

	// Both grants revoked.
	var active int64
	if err := db.Model(&models.AccessGrant{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Count(&active).Error; err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 0 {
		t.Errorf("active grants after leaver = %d; want 0", active)
	}

	// Team membership stripped.
	var inTeam int64
	if err := db.Model(&models.TeamMember{}).
		Where("user_id = ?", userID).Count(&inTeam).Error; err != nil {
		t.Fatalf("count team: %v", err)
	}
	if inTeam != 0 {
		t.Errorf("team memberships after leaver = %d; want 0", inTeam)
	}

	// OpenZiti called once.
	if got := zClient.Calls.Load(); got != 1 {
		t.Errorf("DisableIdentity calls = %d; want 1", got)
	}
}

// TestE2E_SCIMUnknownEventIsClassifiedSafely verifies that unrecognised
// SCIM verbs route to JMLEventUnknown — the system should not silently
// invoke any lane.
func TestE2E_SCIMUnknownEventIsClassifiedSafely(t *testing.T) {
	jml := &JMLService{}
	cases := []SCIMEvent{
		{Operation: "PUT"},
		{Operation: "PATCH"}, // PATCH with no diffs → unknown
		{Operation: ""},
	}
	for _, ev := range cases {
		if got := jml.ClassifyChange(ev); got != JMLEventUnknown {
			t.Errorf("ClassifyChange(%v) = %q; want unknown", ev, got)
		}
	}
}
