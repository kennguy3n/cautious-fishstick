package access

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestJMLLifecycle_JoinerMoverLeaver_Integration runs all three JML
// lanes in sequence against a single real DB, a single real
// JMLService, a real AccessProvisioningService, and a real
// MockAccessConnector. The stubOpenZitiClient is a real
// implementation of the OpenZitiClient interface with in-memory
// call tracking — it is NOT a mock, it is a real client.
//
// Lifecycle covered:
//
//  1. Joiner: user added with two default grants on the
//     engineering team.
//  2. Mover: user promoted to security team; engineering grants
//     revoked, security grants provisioned, team_members table
//     reflects the swap.
//  3. Leaver: every active grant revoked, every team membership
//     removed, OpenZitiClient.DisableIdentity called exactly once.
//
// Asserts on real DB state after every lane to prove no half-states.
func TestJMLLifecycle_JoinerMoverLeaver_Integration(t *testing.T) {
	const provider = "mock_jml_full_integration"
	const ws = "01H000000000000000WORKSPACE"
	const userID = "01H000000JMLINTEG0USER00001"

	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01HCONN0JMLINTEG00000000001", provider)
	engTeam := seedJMLTeam(t, db, "01HTEAMJMLINTEGENG000000001", "engineering")
	secTeam := seedJMLTeam(t, db, "01HTEAMJMLINTEGSEC000000001", "security")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)
	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)
	z := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(z)

	// --- Joiner ---
	joinerRes, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: ws,
		UserID:      userID,
		TeamIDs:     []string{engTeam.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/code", Role: "developer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/docs", Role: "viewer"},
		},
		Justification: "jml integration joiner",
	})
	if err != nil {
		t.Fatalf("HandleJoiner: %v", err)
	}
	if !joinerRes.AllOK() || len(joinerRes.Provisioned) != 2 {
		t.Fatalf("joiner result = %+v", joinerRes)
	}

	var active int64
	if err := db.Model(&models.AccessGrant{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Count(&active).Error; err != nil {
		t.Fatalf("count active after joiner: %v", err)
	}
	if active != 2 {
		t.Fatalf("active grants after joiner = %d; want 2", active)
	}

	// --- Mover: engineering → security ---
	moverRes, err := jml.HandleMover(context.Background(), MoverInput{
		WorkspaceID:   ws,
		UserID:        userID,
		OldTeamIDs:    []string{engTeam.ID},
		NewTeamIDs:    []string{secTeam.ID},
		RemovedGrants: []JMLAccessGrant{{ConnectorID: conn.ID, ResourceExternalID: "projects/code", Role: "developer"}},
		AddedGrants:   []JMLAccessGrant{{ConnectorID: conn.ID, ResourceExternalID: "projects/security", Role: "responder"}},
		Justification: "jml integration mover",
	})
	if err != nil {
		t.Fatalf("HandleMover: %v", err)
	}
	if !moverRes.AllOK() {
		t.Fatalf("mover result = %+v", moverRes)
	}

	// Engineering grant revoked, viewer grant + security grant active.
	if err := db.Model(&models.AccessGrant{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Count(&active).Error; err != nil {
		t.Fatalf("count active after mover: %v", err)
	}
	if active != 2 {
		t.Fatalf("active grants after mover = %d; want 2", active)
	}

	// Team membership: only on the security team now.
	var inEng, inSec int64
	if err := db.Model(&models.TeamMember{}).Where("user_id = ? AND team_id = ?", userID, engTeam.ID).Count(&inEng).Error; err != nil {
		t.Fatalf("count eng membership: %v", err)
	}
	if err := db.Model(&models.TeamMember{}).Where("user_id = ? AND team_id = ?", userID, secTeam.ID).Count(&inSec).Error; err != nil {
		t.Fatalf("count sec membership: %v", err)
	}
	if inEng != 0 {
		t.Fatalf("still in engineering team after mover")
	}
	if inSec != 1 {
		t.Fatalf("not in security team after mover")
	}

	// --- Leaver ---
	leaverRes, err := jml.HandleLeaver(context.Background(), ws, userID)
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if !leaverRes.AllOK() {
		t.Fatalf("leaver result = %+v", leaverRes)
	}

	if err := db.Model(&models.AccessGrant{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Count(&active).Error; err != nil {
		t.Fatalf("count active after leaver: %v", err)
	}
	if active != 0 {
		t.Fatalf("active grants after leaver = %d; want 0", active)
	}

	var anyTeam int64
	if err := db.Model(&models.TeamMember{}).Where("user_id = ?", userID).Count(&anyTeam).Error; err != nil {
		t.Fatalf("count team after leaver: %v", err)
	}
	if anyTeam != 0 {
		t.Fatalf("team memberships after leaver = %d; want 0", anyTeam)
	}

	if got := z.Calls.Load(); got != 1 {
		t.Fatalf("DisableIdentity calls = %d; want 1", got)
	}
}
