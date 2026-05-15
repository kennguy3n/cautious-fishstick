package access

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newJMLTestDB returns an in-memory SQLite DB with every table the
// JML service touches migrated. Each test gets its own DB so cases
// can run in parallel.
func newJMLTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
		&models.Team{},
		&models.TeamMember{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// seedConnectorWithID inserts an access_connectors row at the given
// ID. JML tests need multiple connectors per case so we cannot reuse
// the hard-coded ID in seedConnector.
func seedConnectorWithID(t *testing.T, db *gorm.DB, id, provider string) *models.AccessConnector {
	t.Helper()
	conn := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed access_connector %s: %v", id, err)
	}
	return conn
}

// seedJMLTeam inserts a teams row at the given ID. Named distinctly
// from the policy_service_test seedTeam (which takes attribute maps)
// so the two test files can co-exist in the same package.
func seedJMLTeam(t *testing.T, db *gorm.DB, id, name string) *models.Team {
	t.Helper()
	team := &models.Team{
		ID:          id,
		WorkspaceID: "01H000000000000000WORKSPACE",
		Name:        name,
	}
	if err := db.Create(team).Error; err != nil {
		t.Fatalf("seed team %s: %v", id, err)
	}
	return team
}

// TestClassifyChange_Routing checks the deterministic SCIM-event →
// JML-lane routing table.
func TestClassifyChange_Routing(t *testing.T) {
	t.Parallel()
	svc := &JMLService{}
	tru := true
	fal := false

	cases := []struct {
		name string
		ev   SCIMEvent
		want JMLEventKind
	}{
		{"post active=nil → joiner", SCIMEvent{Operation: "POST"}, JMLEventJoiner},
		{"post active=true → joiner", SCIMEvent{Operation: "POST", Active: &tru}, JMLEventJoiner},
		{"post active=false → leaver", SCIMEvent{Operation: "POST", Active: &fal}, JMLEventLeaver},
		{"delete → leaver", SCIMEvent{Operation: "DELETE"}, JMLEventLeaver},
		{"patch active=false → leaver", SCIMEvent{Operation: "PATCH", Active: &fal}, JMLEventLeaver},
		{"patch group change → mover", SCIMEvent{Operation: "PATCH", HasGroupChanges: true}, JMLEventMover},
		{"patch attr change → mover", SCIMEvent{Operation: "PATCH", HasAttributeChanges: true}, JMLEventMover},
		{"patch no changes → unknown", SCIMEvent{Operation: "PATCH"}, JMLEventUnknown},
		{"unknown verb → unknown", SCIMEvent{Operation: "PUT"}, JMLEventUnknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := svc.ClassifyChange(tc.ev); got != tc.want {
				t.Errorf("ClassifyChange(%v) = %q; want %q", tc.ev, got, tc.want)
			}
		})
	}
}

// TestHandleJoiner_HappyPath asserts the joiner flow assigns the
// requested teams, creates approved + provisioned access_requests,
// inserts access_grants rows, and reports each grant in
// JMLResult.Provisioned.
func TestHandleJoiner_HappyPath(t *testing.T) {
	const provider = "mock_jml_joiner_happy"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNJOIN", provider)
	team := seedJMLTeam(t, db, "01H00000000000000JMLTEAM01", "engineering")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	res, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER01",
		TeamIDs:     []string{team.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/foo", Role: "viewer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/bar", Role: "editor"},
		},
	})
	if err != nil {
		t.Fatalf("HandleJoiner: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed grants: %+v", res.Failed)
	}
	if got, want := len(res.Provisioned), 2; got != want {
		t.Errorf("Provisioned = %d; want %d", got, want)
	}
	if got, want := mock.ProvisionAccessCalls, 2; got != want {
		t.Errorf("ProvisionAccess calls = %d; want %d", got, want)
	}

	var members []models.TeamMember
	if err := db.Where("user_id = ? AND team_id = ?", "01H00000000000000JMLUSER01", team.ID).Find(&members).Error; err != nil {
		t.Fatalf("read team_members: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("team_members = %d; want 1", len(members))
	}

	var grants []models.AccessGrant
	if err := db.Where("user_id = ? AND revoked_at IS NULL", "01H00000000000000JMLUSER01").Find(&grants).Error; err != nil {
		t.Fatalf("read grants: %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("grants = %d; want 2", len(grants))
	}
}

// TestHandleJoiner_PartialFailureContinuesProvisioning asserts that a
// connector failure on grant N does NOT abort grants N+1..M; the
// failed grant is captured in JMLResult.Failed and the team
// membership is still applied.
func TestHandleJoiner_PartialFailureContinuesProvisioning(t *testing.T) {
	const provider = "mock_jml_joiner_partial"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNPART", provider)
	team := seedJMLTeam(t, db, "01H00000000000000JMLTEAM02", "platform")

	// Fail provision on the first call only.
	calls := 0
	mock := &MockAccessConnector{
		FuncProvisionAccess: func(_ context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
			calls++
			if calls == 1 {
				return fmt.Errorf("upstream 5xx")
			}
			return nil
		},
	}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	res, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER02",
		TeamIDs:     []string{team.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/red", Role: "viewer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/blue", Role: "viewer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/green", Role: "viewer"},
		},
	})
	if err != nil {
		t.Fatalf("HandleJoiner: %v", err)
	}
	if got, want := len(res.Failed), 1; got != want {
		t.Errorf("Failed = %d; want %d", got, want)
	}
	if got, want := len(res.Provisioned), 2; got != want {
		t.Errorf("Provisioned = %d; want %d", got, want)
	}
	if mock.ProvisionAccessCalls != 3 {
		t.Errorf("ProvisionAccess calls = %d; want 3 (one failure, two successes)", mock.ProvisionAccessCalls)
	}

	var members []models.TeamMember
	if err := db.Where("user_id = ?", "01H00000000000000JMLUSER02").Find(&members).Error; err != nil {
		t.Fatalf("read team_members: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("team_members = %d; want 1 (membership applied even on partial provision failure)", len(members))
	}
}

// TestHandleJoiner_ValidationErrors asserts that missing required
// fields return ErrValidation without touching the DB.
func TestHandleJoiner_ValidationErrors(t *testing.T) {
	t.Parallel()
	jml := NewJMLService(newJMLTestDB(t), nil)

	cases := []struct {
		name string
		in   JoinerInput
	}{
		{"missing workspace", JoinerInput{UserID: "u"}},
		{"missing user", JoinerInput{WorkspaceID: "w"}},
		{"no teams or grants", JoinerInput{WorkspaceID: "w", UserID: "u"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jml.HandleJoiner(context.Background(), tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Errorf("err = %v; want errors.Is(err, ErrValidation)", err)
			}
		})
	}
}

// TestHandleMover_GainsAndLosesTeams asserts a mover with one added
// team and one removed team runs both halves: the removed grant is
// revoked, the added grant is provisioned, and team_members reflects
// the diff.
func TestHandleMover_GainsAndLosesTeams(t *testing.T) {
	const provider = "mock_jml_mover_gain_lose"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNMVR1", provider)
	oldTeam := seedJMLTeam(t, db, "01H00000000000000JMLTEAMOLD1", "old-team")
	newTeam := seedJMLTeam(t, db, "01H00000000000000JMLTEAMNEW1", "new-team")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	// Pre-seed: user is in oldTeam and has an active grant from it.
	in := JoinerInput{
		WorkspaceID:   "01H000000000000000WORKSPACE",
		UserID:        "01H00000000000000JMLUSER03",
		TeamIDs:       []string{oldTeam.ID},
		DefaultGrants: []JMLAccessGrant{{ConnectorID: conn.ID, ResourceExternalID: "projects/old", Role: "viewer"}},
	}
	if _, err := jml.HandleJoiner(context.Background(), in); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}
	mock.ProvisionAccessCalls = 0

	res, err := jml.HandleMover(context.Background(), MoverInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER03",
		OldTeamIDs:  []string{oldTeam.ID},
		NewTeamIDs:  []string{newTeam.ID},
		AddedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/new", Role: "viewer"},
		},
		RemovedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/old", Role: "viewer"},
		},
	})
	if err != nil {
		t.Fatalf("HandleMover: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed: %+v", res.Failed)
	}
	if got, want := len(res.Revoked), 1; got != want {
		t.Errorf("Revoked = %d; want %d", got, want)
	}
	if got, want := len(res.Provisioned), 1; got != want {
		t.Errorf("Provisioned = %d; want %d", got, want)
	}
	if mock.RevokeAccessCalls != 1 {
		t.Errorf("RevokeAccess calls = %d; want 1", mock.RevokeAccessCalls)
	}
	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("ProvisionAccess calls = %d; want 1 (post-mover)", mock.ProvisionAccessCalls)
	}

	var oldMembers []models.TeamMember
	if err := db.Where("team_id = ? AND user_id = ?", oldTeam.ID, "01H00000000000000JMLUSER03").Find(&oldMembers).Error; err != nil {
		t.Fatalf("read old team_members: %v", err)
	}
	if len(oldMembers) != 0 {
		t.Errorf("old team_members = %d; want 0 (removed by diff)", len(oldMembers))
	}
	var newMembers []models.TeamMember
	if err := db.Where("team_id = ? AND user_id = ?", newTeam.ID, "01H00000000000000JMLUSER03").Find(&newMembers).Error; err != nil {
		t.Fatalf("read new team_members: %v", err)
	}
	if len(newMembers) != 1 {
		t.Errorf("new team_members = %d; want 1 (added by diff)", len(newMembers))
	}
}

// TestHandleMover_ProvisionsBeforeRevokes asserts the mover lane
// provisions the gained-team grants BEFORE revoking the lost-team
// grants. docs/architecture.md mandates "no partial-access window": doing
// the revoke first would leave the user with neither old nor new
// access for the duration of the connector round-trip; doing the
// provision first means the user briefly has both, which is the
// safer overshoot.
//
// Regression for the original implementation that ran the revoke
// loop first.
func TestHandleMover_ProvisionsBeforeRevokes(t *testing.T) {
	const provider = "mock_jml_mover_order"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNMVR3", provider)

	var ops []string
	mock := &MockAccessConnector{
		FuncProvisionAccess: func(_ context.Context, _, _ map[string]interface{}, g AccessGrant) error {
			ops = append(ops, "provision:"+g.ResourceExternalID)
			return nil
		},
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, g AccessGrant) error {
			ops = append(ops, "revoke:"+g.ResourceExternalID)
			return nil
		},
	}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	// Pre-seed: user has an active grant on projects/old.
	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID:   "01H000000000000000WORKSPACE",
		UserID:        "01H00000000000000JMLUSER0X",
		TeamIDs:       []string{"01H00000000000000JMLTEAMSTUB"},
		DefaultGrants: []JMLAccessGrant{{ConnectorID: conn.ID, ResourceExternalID: "projects/old", Role: "viewer"}},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}
	ops = nil // discard joiner ops, we only care about mover ordering

	if _, err := jml.HandleMover(context.Background(), MoverInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER0X",
		AddedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/new", Role: "viewer"},
		},
		RemovedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/old", Role: "viewer"},
		},
	}); err != nil {
		t.Fatalf("HandleMover: %v", err)
	}

	if len(ops) != 2 {
		t.Fatalf("ops = %v; want 2 ops (one provision, one revoke)", ops)
	}
	if ops[0] != "provision:projects/new" {
		t.Errorf("ops[0] = %q; want %q (mover MUST provision before revoking to honor 'no partial-access window')", ops[0], "provision:projects/new")
	}
	if ops[1] != "revoke:projects/old" {
		t.Errorf("ops[1] = %q; want %q", ops[1], "revoke:projects/old")
	}
}

// TestHandleMover_NoChangesIsNoop asserts a mover whose old and new
// team set match — and whose added/removed grants are empty —
// performs no DB writes and no connector calls.
func TestHandleMover_NoChangesIsNoop(t *testing.T) {
	const provider = "mock_jml_mover_noop"
	db := newJMLTestDB(t)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	res, err := jml.HandleMover(context.Background(), MoverInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER04",
		OldTeamIDs:  []string{"t1", "t2"},
		NewTeamIDs:  []string{"t1", "t2"},
	})
	if err != nil {
		t.Fatalf("HandleMover: %v", err)
	}
	if !res.AllOK() {
		t.Errorf("AllOK = false; want true")
	}
	if len(res.Provisioned) != 0 || len(res.Revoked) != 0 {
		t.Errorf("Provisioned=%d Revoked=%d; want both 0", len(res.Provisioned), len(res.Revoked))
	}
	if mock.ProvisionAccessCalls != 0 || mock.RevokeAccessCalls != 0 {
		t.Errorf("connector called on no-op mover (provision=%d, revoke=%d)", mock.ProvisionAccessCalls, mock.RevokeAccessCalls)
	}
}

// TestHandleMover_RevokeFailureSurfacesAndContinues asserts that a
// revoke failure on a removed-team grant lands in JMLResult.Failed
// and does not abort the gained-team provisioning.
func TestHandleMover_RevokeFailureSurfacesAndContinues(t *testing.T) {
	const provider = "mock_jml_mover_revoke_err"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNMVR2", provider)

	mock := &MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
			return fmt.Errorf("upstream 5xx on revoke")
		},
	}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	// Pre-seed an active grant we'll attempt to revoke.
	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID:   "01H000000000000000WORKSPACE",
		UserID:        "01H00000000000000JMLUSER05",
		TeamIDs:       []string{"01H00000000000000JMLTEAMSTUB"},
		DefaultGrants: []JMLAccessGrant{{ConnectorID: conn.ID, ResourceExternalID: "projects/x", Role: "viewer"}},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	res, err := jml.HandleMover(context.Background(), MoverInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER05",
		AddedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/y", Role: "viewer"},
		},
		RemovedGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/x", Role: "viewer"},
		},
	})
	if err != nil {
		t.Fatalf("HandleMover: %v", err)
	}
	if got, want := len(res.Failed), 1; got != want {
		t.Errorf("Failed = %d; want %d", got, want)
	}
	if got, want := len(res.Provisioned), 1; got != want {
		t.Errorf("Provisioned = %d; want %d (added grant must still provision)", got, want)
	}
}

// TestHandleLeaver_RevokesAllActiveGrantsAndPurgesTeams asserts the
// leaver flow revokes every active grant for the user across
// multiple connectors and purges every team_members row.
func TestHandleLeaver_RevokesAllActiveGrantsAndPurgesTeams(t *testing.T) {
	const providerA = "mock_jml_leaver_a"
	const providerB = "mock_jml_leaver_b"
	db := newJMLTestDB(t)
	connA := seedConnectorWithID(t, db, "01H00000000000000JMLCONNLVRA", providerA)
	connB := seedConnectorWithID(t, db, "01H00000000000000JMLCONNLVRB", providerB)
	team1 := seedJMLTeam(t, db, "01H00000000000000JMLTMLVR1", "team-1")
	team2 := seedJMLTeam(t, db, "01H00000000000000JMLTMLVR2", "team-2")

	mockA := &MockAccessConnector{}
	mockB := &MockAccessConnector{}
	SwapConnector(t, providerA, mockA)
	SwapConnector(t, providerB, mockB)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER06",
		TeamIDs:     []string{team1.ID, team2.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: connA.ID, ResourceExternalID: "projects/a-1", Role: "viewer"},
			{ConnectorID: connA.ID, ResourceExternalID: "projects/a-2", Role: "viewer"},
			{ConnectorID: connB.ID, ResourceExternalID: "buckets/b-1", Role: "reader"},
		},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	res, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01H00000000000000JMLUSER06")
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed: %+v", res.Failed)
	}
	if got, want := len(res.Revoked), 3; got != want {
		t.Errorf("Revoked = %d; want %d", got, want)
	}
	if mockA.RevokeAccessCalls != 2 {
		t.Errorf("connectorA RevokeAccess calls = %d; want 2", mockA.RevokeAccessCalls)
	}
	if mockB.RevokeAccessCalls != 1 {
		t.Errorf("connectorB RevokeAccess calls = %d; want 1", mockB.RevokeAccessCalls)
	}

	var members []models.TeamMember
	if err := db.Where("user_id = ?", "01H00000000000000JMLUSER06").Find(&members).Error; err != nil {
		t.Fatalf("read team_members: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("team_members = %d; want 0 after leaver", len(members))
	}

	var stillActive int64
	if err := db.Model(&models.AccessGrant{}).
		Where("user_id = ? AND revoked_at IS NULL", "01H00000000000000JMLUSER06").
		Count(&stillActive).Error; err != nil {
		t.Fatalf("count active grants: %v", err)
	}
	if stillActive != 0 {
		t.Errorf("active grants after leaver = %d; want 0", stillActive)
	}
}

// TestHandleLeaver_NoActiveGrantsIsNoop asserts a leaver whose user
// has no active grants returns an empty JMLResult and does not
// touch any connector.
func TestHandleLeaver_NoActiveGrantsIsNoop(t *testing.T) {
	db := newJMLTestDB(t)
	jml := NewJMLService(db, NewAccessProvisioningService(db))

	res, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01H00000000000000JMLUSER07")
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if !res.AllOK() {
		t.Errorf("AllOK = false; want true on no-op leaver")
	}
	if len(res.Revoked) != 0 {
		t.Errorf("Revoked = %d; want 0", len(res.Revoked))
	}
}

// TestHandleLeaver_OneRevokeFailsContinuesOthers asserts the leaver
// flow continues revoking remaining grants when one connector fails;
// the failure is captured in JMLResult.Failed.
func TestHandleLeaver_OneRevokeFailsContinuesOthers(t *testing.T) {
	const provider = "mock_jml_leaver_partial"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNLVRP", provider)

	calls := 0
	mock := &MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
			calls++
			if calls == 1 {
				return fmt.Errorf("upstream 5xx on revoke")
			}
			return nil
		},
	}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)

	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER08",
		TeamIDs:     []string{"01H00000000000000JMLTEAMSTUB2"},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/r-1", Role: "viewer"},
			{ConnectorID: conn.ID, ResourceExternalID: "projects/r-2", Role: "viewer"},
		},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	res, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01H00000000000000JMLUSER08")
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if got, want := len(res.Failed), 1; got != want {
		t.Errorf("Failed = %d; want %d", got, want)
	}
	if got, want := len(res.Revoked), 1; got != want {
		t.Errorf("Revoked = %d; want %d (one success after one failure)", got, want)
	}
	if mock.RevokeAccessCalls != 2 {
		t.Errorf("RevokeAccess calls = %d; want 2", mock.RevokeAccessCalls)
	}
}

// TestDiffTeamIDs_SetSemantics covers the diff helper that powers
// HandleMover. Order independence and de-duplication on both sides.
func TestDiffTeamIDs_SetSemantics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		old, new    []string
		wantAdded   []string
		wantRemoved []string
	}{
		{"strict subset", []string{"a", "b"}, []string{"a"}, nil, []string{"b"}},
		{"strict superset", []string{"a"}, []string{"a", "b"}, []string{"b"}, nil},
		{"swap", []string{"a"}, []string{"b"}, []string{"b"}, []string{"a"}},
		{"identical", []string{"a", "b"}, []string{"b", "a"}, nil, nil},
		{"empty old", nil, []string{"a"}, []string{"a"}, nil},
		{"empty new", []string{"a"}, nil, nil, []string{"a"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			added, removed := diffTeamIDs(tc.old, tc.new)
			if !sameSet(added, tc.wantAdded) {
				t.Errorf("added = %v; want %v", added, tc.wantAdded)
			}
			if !sameSet(removed, tc.wantRemoved) {
				t.Errorf("removed = %v; want %v", removed, tc.wantRemoved)
			}
		})
	}
}

// sameSet returns true iff a and b contain the same elements
// (order-independent). Empty / nil treated equivalently.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
