package access

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newDisconnectTestDB returns a fresh in-memory SQLite DB with the
// access-platform models the Disconnect path touches: connectors and
// grants. Mirrors newProvisioningTestDB so both tests can share a
// connector boundary.
func newDisconnectTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.AccessGrant{},
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessWorkflow{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// captureCreds is a thread-safe collector for the (config, secrets)
// pairs the connector receives during a Disconnect run. Used to
// assert the service decrypts the stored credentials column and
// plumbs the real maps through to RevokeAccess instead of nil.
type captureCreds struct {
	mu      sync.Mutex
	configs []map[string]interface{}
	secrets []map[string]interface{}
}

func (c *captureCreds) record(cfg, sec map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfgCopy := map[string]interface{}{}
	for k, v := range cfg {
		cfgCopy[k] = v
	}
	secCopy := map[string]interface{}{}
	for k, v := range sec {
		secCopy[k] = v
	}
	c.configs = append(c.configs, cfgCopy)
	c.secrets = append(c.secrets, secCopy)
}

// TestConnectorManagementService_Disconnect_PlumbsRealCredentials
// pins the architectural invariant that Disconnect MUST decrypt the
// connector's stored secrets and pass the real (config, secrets)
// pair to AccessProvisioningService.Revoke — which forwards them to
// AccessConnector.RevokeAccess. The previous implementation passed
// nil, nil and every real connector failed the upstream call.
func TestConnectorManagementService_Disconnect_PlumbsRealCredentials(t *testing.T) {
	const provider = "test_provider_disconnect_creds"
	db := newDisconnectTestDB(t)

	creds := &captureCreds{}
	mock := &MockAccessConnector{
		FuncRevokeAccess: func(_ context.Context, cfg, sec map[string]interface{}, _ AccessGrant) error {
			creds.record(cfg, sec)
			return nil
		},
	}
	SwapConnector(t, provider, mock)

	// Seed an access_connectors row with PassthroughEncryptor-shaped
	// (i.e. plaintext) credentials so the decrypt path runs end-to-end.
	connectorID := "01HDISC00000000000000000A"
	cfgJSON, err := json.Marshal(map[string]interface{}{"tenant": "acme"})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	secretsJSON, err := json.Marshal(map[string]interface{}{"api_key": "shhh"})
	if err != nil {
		t.Fatalf("marshal secrets: %v", err)
	}
	conn := &models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   "01HWORKSPACE0DISC00000000A",
		Provider:      provider,
		ConnectorType: "directory",
		Status:        models.StatusConnected,
		Config:        datatypes.JSON(cfgJSON),
		Credentials:   string(secretsJSON),
		KeyVersion:    1,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	// Seed an active grant tied to the connector so Disconnect has
	// something to revoke through provSvc.
	expires := time.Now().Add(24 * time.Hour)
	reqID := "01HREQ00000000000000000010"
	grant := &models.AccessGrant{
		ID:                 "01HGRANT0DISC0000000000A",
		RequestID:          &reqID,
		WorkspaceID:        "01HWORKSPACE0DISC00000000A",
		UserID:             "01HUSER0DISC00000000000A",
		ConnectorID:        connectorID,
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		GrantedAt:          time.Now(),
		ExpiresAt:          &expires,
	}
	if err := db.Create(grant).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	provSvc := NewAccessProvisioningService(db)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, provSvc, nil)

	if err := svc.Disconnect(context.Background(), connectorID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if len(creds.configs) != 1 {
		t.Fatalf("RevokeAccess called %d times; want 1", len(creds.configs))
	}
	if creds.configs[0]["tenant"] != "acme" {
		t.Errorf("config passed to RevokeAccess = %v; want tenant=acme (Disconnect must decrypt stored creds, not pass nil)", creds.configs[0])
	}
	if creds.secrets[0]["api_key"] != "shhh" {
		t.Errorf("secrets passed to RevokeAccess = %v; want api_key=shhh", creds.secrets[0])
	}

	// Verify the connector row is soft-deleted and the grant's
	// revoked_at is set (the per-grant Revoke succeeded against the
	// mock; the bulk safety net is a no-op here).
	var deletedConn models.AccessConnector
	if err := db.Unscoped().Where("id = ?", connectorID).First(&deletedConn).Error; err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	if !deletedConn.DeletedAt.Valid {
		t.Fatalf("expected connector deleted_at to be set")
	}
	var reloadedGrant models.AccessGrant
	if err := db.Where("id = ?", grant.ID).First(&reloadedGrant).Error; err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if reloadedGrant.RevokedAt == nil {
		t.Errorf("expected grant.revoked_at to be set after Disconnect")
	}
}

// TestConnectorManagementService_Disconnect_FallsBackOnRevokeFailure
// pins the safety-net invariant: when the per-grant Revoke fails
// against the upstream connector, the bulk DB-level revoke still
// marks the grant as revoked. The connector is being torn down, so
// leaving the grant active would orphan it against a soft-deleted
// connector that lookupProvider would then reject.
func TestConnectorManagementService_Disconnect_FallsBackOnRevokeFailure(t *testing.T) {
	const provider = "test_provider_disconnect_fallback"
	db := newDisconnectTestDB(t)

	mock := &MockAccessConnector{
		FuncRevokeAccess: func(context.Context, map[string]interface{}, map[string]interface{}, AccessGrant) error {
			// Simulate the upstream provider being unreachable
			// during a tear-down — Revoke fails but Disconnect must
			// still flip the data model into a consistent state.
			return errAccessConnectorBoom
		},
	}
	SwapConnector(t, provider, mock)

	connectorID := "01HDISC00000000000000000B"
	conn := &models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   "01HWORKSPACE0DISC00000000B",
		Provider:      provider,
		ConnectorType: "directory",
		Status:        models.StatusConnected,
		Credentials:   `{"api_key":"shhh"}`,
		KeyVersion:    1,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	expires := time.Now().Add(24 * time.Hour)
	reqID := "01HREQ00000000000000000011"
	grant := &models.AccessGrant{
		ID:                 "01HGRANT0DISC0000000000B",
		RequestID:          &reqID,
		WorkspaceID:        "01HWORKSPACE0DISC00000000B",
		UserID:             "01HUSER0DISC00000000000B",
		ConnectorID:        connectorID,
		ResourceExternalID: "projects/bar",
		Role:               "viewer",
		GrantedAt:          time.Now(),
		ExpiresAt:          &expires,
	}
	if err := db.Create(grant).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	provSvc := NewAccessProvisioningService(db)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, provSvc, nil)

	if err := svc.Disconnect(context.Background(), connectorID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	var reloadedGrant models.AccessGrant
	if err := db.Where("id = ?", grant.ID).First(&reloadedGrant).Error; err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if reloadedGrant.RevokedAt == nil {
		t.Errorf("expected grant.revoked_at to be set by bulk safety net after upstream Revoke failure")
	}
}

// errAccessConnectorBoom is a sentinel used by the fallback test to
// simulate an unreachable upstream provider during Disconnect.
var errAccessConnectorBoom = errors.New("boom: upstream connector unreachable")
