//go:build integration

package access

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// integrationSessionRevoker is an in-memory AccessConnector that
// implements SessionRevoker so the integration test can assert
// the leaver flow walked the per-connector session-revoke layer.
type integrationSessionRevoker struct {
	*MockAccessConnector
	mu       sync.Mutex
	calls    atomic.Int64
	gotUsers []string
}

func (s *integrationSessionRevoker) RevokeUserSessions(_ context.Context, _, _ map[string]interface{}, userExternalID string) error {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotUsers = append(s.gotUsers, userExternalID)
	return nil
}

// integrationSCIMConnector is an in-memory AccessConnector that
// implements the SCIM optional capability so the integration test
// can assert DeleteSCIMResource fired on the SCIM layer.
type integrationSCIMConnector struct {
	*MockAccessConnector
	mu       sync.Mutex
	calls    atomic.Int64
	gotUsers []string
}

func (s *integrationSCIMConnector) PushSCIMUser(_ context.Context, _, _ map[string]interface{}, _ SCIMUser) error {
	return nil
}
func (s *integrationSCIMConnector) PushSCIMGroup(_ context.Context, _, _ map[string]interface{}, _ SCIMGroup) error {
	return nil
}
func (s *integrationSCIMConnector) DeleteSCIMResource(_ context.Context, _, _ map[string]interface{}, _, externalID string) error {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotUsers = append(s.gotUsers, externalID)
	return nil
}

// TestLeaverKillSwitch_FullWorkspace_Integration seeds a workspace
// with 3 connectors (one SessionRevoker, one SCIM, one plain) plus
// a user with grants on all 3, then calls HandleLeaver and asserts
// every kill-switch layer fired and the user has zero active
// grants + zero team memberships after the run.
func TestLeaverKillSwitch_FullWorkspace_Integration(t *testing.T) {
	const (
		ws       = "01H000000000000000WORKSPACE"
		userID   = "01HUSERINT0LEAVER000000001"
		teamID   = "01HTEAMINT0LEAVER000000001"
		provRev  = "mock_int_leaver_revoker"
		provSCIM = "mock_int_leaver_scim"
		provBase = "mock_int_leaver_base"
	)

	db := newJMLTestDB(t)
	connRev := seedConnectorWithSecrets(t, db, "01HCONNINT0LEAVERRVK00001", provRev)
	connSCIM := seedConnectorWithSecrets(t, db, "01HCONNINT0LEAVERSCM00001", provSCIM)
	connBase := seedConnectorWithSecrets(t, db, "01HCONNINT0LEAVERBSE00001", provBase)

	revoker := &integrationSessionRevoker{MockAccessConnector: &MockAccessConnector{}}
	scim := &integrationSCIMConnector{MockAccessConnector: &MockAccessConnector{}}
	plain := &MockAccessConnector{}
	SwapConnector(t, provRev, revoker)
	SwapConnector(t, provSCIM, scim)
	SwapConnector(t, provBase, plain)

	// Seed team_members rows so the per-connector layers know what
	// upstream external id to address.
	for i, c := range []*models.AccessConnector{connRev, connSCIM, connBase} {
		if err := db.Create(&models.TeamMember{
			ID:          "01HTMINTLEAVERFULL0000000" + string(rune('A'+i)),
			TeamID:      teamID,
			UserID:      userID,
			ExternalID:  "ext-" + c.Provider,
			ConnectorID: c.ID,
		}).Error; err != nil {
			t.Fatalf("seed team_member: %v", err)
		}
	}

	// Seed an active grant per connector so the GrantRevoke layer
	// has something to revoke.
	for i, c := range []*models.AccessConnector{connRev, connSCIM, connBase} {
		if err := db.Create(&models.AccessGrant{
			ID:                 "01HGRINTLEAVERFULL00000000" + string(rune('A'+i)),
			WorkspaceID:        ws,
			UserID:             userID,
			ConnectorID:        c.ID,
			ResourceExternalID: "projects/int",
			Role:               "viewer",
		}).Error; err != nil {
			t.Fatalf("seed grant: %v", err)
		}
	}

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)
	z := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(z)
	admin := &stubKeycloakAdmin{mockKeycloakClient: newMockKeycloak()}
	jml.SetSSOFederationService(NewSSOFederationService(admin))
	jml.SetConnectorCredentialsLoader(NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))

	if _, err := jml.HandleLeaver(context.Background(), ws, userID); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}

	if got := revoker.calls.Load(); got != 1 {
		t.Errorf("SessionRevoker.RevokeUserSessions calls = %d; want 1", got)
	}
	if got := scim.calls.Load(); got != 1 {
		t.Errorf("SCIM DeleteSCIMResource calls = %d; want 1", got)
	}
	if got := admin.updateCalls.Load(); got != 1 {
		t.Errorf("Keycloak UpdateUser calls = %d; want 1", got)
	}
	if got := admin.logoutCalls.Load(); got != 1 {
		t.Errorf("Keycloak LogoutUser calls = %d; want 1", got)
	}
	if got := z.Calls.Load(); got != 1 {
		t.Errorf("OpenZiti DisableIdentity calls = %d; want 1", got)
	}

	// Assert post-state: zero active grants, zero team memberships.
	var activeGrants []models.AccessGrant
	if err := db.Where("user_id = ? AND revoked_at IS NULL", userID).Find(&activeGrants).Error; err != nil {
		t.Fatalf("query active grants: %v", err)
	}
	if len(activeGrants) != 0 {
		t.Errorf("active grants after leaver = %d; want 0", len(activeGrants))
	}
	var teamMembers []models.TeamMember
	if err := db.Where("user_id = ?", userID).Find(&teamMembers).Error; err != nil {
		t.Fatalf("query team_members: %v", err)
	}
	if len(teamMembers) != 0 {
		t.Errorf("team_members rows after leaver = %d; want 0", len(teamMembers))
	}
}
