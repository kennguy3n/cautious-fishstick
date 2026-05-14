package access

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubSessionRevokerConnector embeds MockAccessConnector and adds
// the optional SessionRevoker capability so the Phase 11 leaver
// kill-switch tests can assert RevokeUserSessions was called with
// the expected external ID.
type stubSessionRevokerConnector struct {
	*MockAccessConnector
	mu      sync.Mutex
	Calls   atomic.Int64
	UserIDs []string
	Err     error
}

func (s *stubSessionRevokerConnector) RevokeUserSessions(_ context.Context, _, _ map[string]interface{}, userExternalID string) error {
	s.Calls.Add(1)
	s.mu.Lock()
	s.UserIDs = append(s.UserIDs, userExternalID)
	s.mu.Unlock()
	return s.Err
}

// stubSCIMConnector embeds MockAccessConnector and adds the SCIM
// deprovision capability. Phase 11 leaver tests use it to assert
// DeleteSCIMResource was called.
type stubSCIMConnector struct {
	*MockAccessConnector
	mu       sync.Mutex
	Calls    atomic.Int64
	Resource []string
	IDs      []string
	Err      error
}

func (s *stubSCIMConnector) PushSCIMUser(_ context.Context, _, _ map[string]interface{}, _ SCIMUser) error {
	return nil
}
func (s *stubSCIMConnector) PushSCIMGroup(_ context.Context, _, _ map[string]interface{}, _ SCIMGroup) error {
	return nil
}
func (s *stubSCIMConnector) DeleteSCIMResource(_ context.Context, _, _ map[string]interface{}, resourceType, externalID string) error {
	s.Calls.Add(1)
	s.mu.Lock()
	s.Resource = append(s.Resource, resourceType)
	s.IDs = append(s.IDs, externalID)
	s.mu.Unlock()
	return s.Err
}

// stubKeycloakAdmin satisfies KeycloakClient + KeycloakUserAdminClient.
type stubKeycloakAdmin struct {
	*mockKeycloakClient
	updateCalls atomic.Int64
	logoutCalls atomic.Int64
	logoutIDs   []string
	mu          sync.Mutex
	Err         error
}

func (s *stubKeycloakAdmin) UpdateUser(_ context.Context, _, userID string, _ map[string]interface{}) error {
	s.updateCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = userID
	return s.Err
}
func (s *stubKeycloakAdmin) LogoutUser(_ context.Context, _, userID string) error {
	s.logoutCalls.Add(1)
	s.mu.Lock()
	s.logoutIDs = append(s.logoutIDs, userID)
	s.mu.Unlock()
	return nil
}

// seedConnectorWithSecrets inserts an access_connectors row with
// encrypted secrets so the credentials loader can decode them.
func seedConnectorWithSecrets(t *testing.T, db *gorm.DB, id, provider string) *models.AccessConnector {
	t.Helper()
	cipher, kv, err := encryptSecretsMap(PassthroughEncryptor{}, map[string]interface{}{"token": "tok"}, id)
	if err != nil {
		t.Fatalf("seal secrets: %v", err)
	}
	conn := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
		Credentials:   cipher,
	}
	if kvInt := parseIntDefault(kv, 1); kvInt > 0 {
		conn.KeyVersion = kvInt
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed access_connector %s: %v", id, err)
	}
	return conn
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	v := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return def
		}
		v = v*10 + int(ch-'0')
	}
	return v
}

// TestHandleLeaver_KillSwitchExecutesAllLayers asserts that
// HandleLeaver with all Phase 11 hooks wired walks every kill-
// switch layer for the leaver: Keycloak disable, per-connector
// session revoke, SCIM deprovision, OpenZiti identity disable.
func TestHandleLeaver_KillSwitchExecutesAllLayers(t *testing.T) {
	const provider = "mock_jml_killswitch"
	db := newJMLTestDB(t)
	conn := seedConnectorWithSecrets(t, db, "01HCONN0KILLSWITCH00000001", provider)

	revoker := &stubSessionRevokerConnector{MockAccessConnector: &MockAccessConnector{}}
	SwapConnector(t, provider, revoker)

	// Seed a team_members row mapping the leaver to the connector
	// with a connector-side external ID. revokeSessionsAcrossConnectors
	// uses this pivot to know which user_external_id to pass to
	// RevokeUserSessions.
	if err := db.Create(&models.TeamMember{
		ID:          "01HTM0KILLSWITCH00000000001",
		TeamID:      "01HTEAM0KILLSWITCH000000001",
		UserID:      "01HUSER0KILLSWITCH00000001",
		ExternalID:  "okta-id-123",
		ConnectorID: conn.ID,
	}).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)
	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)
	admin := &stubKeycloakAdmin{mockKeycloakClient: newMockKeycloak()}
	jml.SetSSOFederationService(NewSSOFederationService(admin))
	jml.SetConnectorCredentialsLoader(NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0KILLSWITCH00000001"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}

	if got := admin.updateCalls.Load(); got != 1 {
		t.Errorf("Keycloak UpdateUser calls = %d; want 1", got)
	}
	if got := admin.logoutCalls.Load(); got != 1 {
		t.Errorf("Keycloak LogoutUser calls = %d; want 1", got)
	}
	if got := revoker.Calls.Load(); got != 1 {
		t.Errorf("RevokeUserSessions calls = %d; want 1", got)
	}
	revoker.mu.Lock()
	if len(revoker.UserIDs) != 1 || revoker.UserIDs[0] != "okta-id-123" {
		t.Errorf("RevokeUserSessions user_external_id = %v; want [okta-id-123]", revoker.UserIDs)
	}
	revoker.mu.Unlock()
	if got := zClient.Calls.Load(); got != 1 {
		t.Errorf("OpenZiti DisableIdentity calls = %d; want 1", got)
	}
}

// TestHandleLeaver_SessionRevokeFailureDoesNotBlockNextLayer asserts
// that a connector-side RevokeUserSessions error is logged but the
// SCIM and OpenZiti layers still fire.
func TestHandleLeaver_SessionRevokeFailureDoesNotBlockNextLayer(t *testing.T) {
	const provider = "mock_jml_killswitch_err"
	db := newJMLTestDB(t)
	conn := seedConnectorWithSecrets(t, db, "01HCONN0KILLSWITCHERR00001", provider)

	revoker := &stubSessionRevokerConnector{
		MockAccessConnector: &MockAccessConnector{},
		Err:                 errors.New("boom"),
	}
	SwapConnector(t, provider, revoker)

	if err := db.Create(&models.TeamMember{
		ID:          "01HTM0KILLSWITCHERR000000001",
		TeamID:      "01HTEAM0KILLSWITCHERR0000001",
		UserID:      "01HUSER0KILLSWITCHERR000001",
		ExternalID:  "okta-id-err",
		ConnectorID: conn.ID,
	}).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}

	jml := NewJMLService(db, NewAccessProvisioningService(db))
	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)
	admin := &stubKeycloakAdmin{mockKeycloakClient: newMockKeycloak()}
	jml.SetSSOFederationService(NewSSOFederationService(admin))
	jml.SetConnectorCredentialsLoader(NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0KILLSWITCHERR000001"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if got := zClient.Calls.Load(); got != 1 {
		t.Errorf("OpenZiti DisableIdentity calls = %d after session revoke error; want 1", got)
	}
}

// TestHandleLeaver_KeycloakDisableFailureDoesNotBlockNextLayer
// asserts that a Keycloak outage is logged but does not block the
// connector / SCIM / OpenZiti layers.
func TestHandleLeaver_KeycloakDisableFailureDoesNotBlockNextLayer(t *testing.T) {
	const provider = "mock_jml_killswitch_kc_err"
	db := newJMLTestDB(t)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0KILLSWITCHKC0000001", provider)
	SwapConnector(t, provider, &MockAccessConnector{})

	jml := NewJMLService(db, NewAccessProvisioningService(db))
	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)
	admin := &stubKeycloakAdmin{
		mockKeycloakClient: newMockKeycloak(),
		Err:                errors.New("keycloak unreachable"),
	}
	jml.SetSSOFederationService(NewSSOFederationService(admin))

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0KILLSWITCHKC00001"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if got := zClient.Calls.Load(); got != 1 {
		t.Errorf("OpenZiti DisableIdentity calls = %d after Keycloak error; want 1", got)
	}
}

// TestHandleLeaver_KillSwitchIsIdempotent asserts re-running
// HandleLeaver on an already-deprovisioned user is safe: every
// optional hook fires again without panicking. The grant-revoke
// branch short-circuits because there are no active grants left.
func TestHandleLeaver_KillSwitchIsIdempotent(t *testing.T) {
	const provider = "mock_jml_killswitch_idem"
	db := newJMLTestDB(t)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0KILLSWITCHIDEM0001", provider)
	SwapConnector(t, provider, &MockAccessConnector{})

	jml := NewJMLService(db, NewAccessProvisioningService(db))
	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0KILLSWITCHIDEM0001"); err != nil {
		t.Fatalf("HandleLeaver pass 1: %v", err)
	}
	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0KILLSWITCHIDEM0001"); err != nil {
		t.Fatalf("HandleLeaver pass 2: %v", err)
	}
	if got := zClient.Calls.Load(); got != 2 {
		t.Errorf("OpenZiti DisableIdentity calls = %d; want 2 (idempotent re-run)", got)
	}
}
