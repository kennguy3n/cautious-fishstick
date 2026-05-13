package access_test

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	"github.com/kennguy3n/cautious-fishstick/internal/workers/handlers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestConnectorLifecycle_Integration walks the full ConnectorManagementService
// happy-path against a real SQLite DB, a real worker handler, and a
// MockAccessConnector configured to emit realistic identities. The
// MockAccessConnector is the ONLY mock — the encryptor is the real
// PassthroughEncryptor, the registry lookup is real, the worker DB
// write path is real.
//
//   1. ConnectorManagementService.Connect → real access_connectors row +
//      real access_jobs (sync_identities) row.
//   2. workers/handlers.AccessSyncIdentities → real team_members rows
//      (one per IdentityTypeUser), plus a real access_sync_state row.
//   3. ConnectorManagementService.Disconnect → real soft-delete on the
//      connector row + real grant revocations on any existing grants.
func TestConnectorLifecycle_Integration(t *testing.T) {
	const provider = "test_provider_lifecycle_integration"
	db := newIntegrationDB(t)

	mock := &access.MockAccessConnector{
		FuncValidate:          func(context.Context, map[string]interface{}, map[string]interface{}) error { return nil },
		FuncConnect:           func(context.Context, map[string]interface{}, map[string]interface{}) error { return nil },
		FuncVerifyPermissions: func(context.Context, map[string]interface{}, map[string]interface{}, []string) ([]string, error) { return nil, nil },
		FuncGetCredentialsMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (map[string]interface{}, error) {
			return nil, nil
		},
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
			batch := []*access.Identity{
				{ExternalID: "user-alice", Type: access.IdentityTypeUser, DisplayName: "Alice", Email: "alice@example.com", Status: "active"},
				{ExternalID: "user-bob", Type: access.IdentityTypeUser, DisplayName: "Bob", Email: "bob@example.com", Status: "active", ManagerID: "user-alice"},
				{ExternalID: "user-carol", Type: access.IdentityTypeUser, DisplayName: "Carol", Email: "carol@example.com", Status: "active"},
				{ExternalID: "user-dan", Type: access.IdentityTypeUser, DisplayName: "Dan", Email: "dan@example.com", Status: "active"},
				{ExternalID: "user-eve", Type: access.IdentityTypeUser, DisplayName: "Eve", Email: "eve@example.com", Status: "active"},
				{ExternalID: "user-frank", Type: access.IdentityTypeUser, DisplayName: "Frank", Email: "frank@example.com", Status: "active"},
				{ExternalID: "user-grace", Type: access.IdentityTypeUser, DisplayName: "Grace", Email: "grace@example.com", Status: "active"},
				{ExternalID: "group-eng", Type: access.IdentityTypeGroup, DisplayName: "Engineering"},
				{ExternalID: "group-sales", Type: access.IdentityTypeGroup, DisplayName: "Sales"},
				{ExternalID: "group-ops", Type: access.IdentityTypeGroup, DisplayName: "Operations"},
			}
			return handler(batch, "checkpoint-final")
		},
		FuncRevokeAccess: func(context.Context, map[string]interface{}, map[string]interface{}, access.AccessGrant) error { return nil },
	}
	access.SwapConnector(t, provider, mock)

	provSvc := access.NewAccessProvisioningService(db)
	svc := access.NewConnectorManagementService(db, access.PassthroughEncryptor{}, provSvc, nil)

	// --- Step 1: Connect ---
	res, err := svc.Connect(context.Background(), access.ConnectInput{
		WorkspaceID:   "01HWORKSPACE0LIFE000000000A",
		Provider:      provider,
		ConnectorType: "directory",
		Config:        map[string]interface{}{"tenant": "acme"},
		Secrets:       map[string]interface{}{"api_key": "shhh"},
		Capabilities:  []string{"read"},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if res.ConnectorID == "" || res.JobID == "" {
		t.Fatalf("unexpected result: %+v", res)
	}

	var conn models.AccessConnector
	if err := db.Where("id = ?", res.ConnectorID).First(&conn).Error; err != nil {
		t.Fatalf("connector row not persisted: %v", err)
	}
	if conn.Status != models.StatusConnected {
		t.Fatalf("connector status = %q; want connected", conn.Status)
	}

	var job models.AccessJob
	if err := db.Where("id = ?", res.JobID).First(&job).Error; err != nil {
		t.Fatalf("job row not persisted: %v", err)
	}
	if job.JobType != models.AccessJobTypeSyncIdentities {
		t.Fatalf("job type = %q; want sync_identities", job.JobType)
	}

	// --- Step 2: Run the real worker handler against the queued job ---
	jc := handlers.JobContext{
		DB:       db,
		Resolve:  func(_ string) (access.AccessConnector, error) { return mock, nil },
		LoadConn: handlers.DefaultLoadConnector,
		Now:      time.Now,
	}
	if err := handlers.AccessSyncIdentities(context.Background(), jc, res.JobID); err != nil {
		t.Fatalf("AccessSyncIdentities: %v", err)
	}

	var memberCount int64
	if err := db.Model(&models.TeamMember{}).Where("connector_id = ?", res.ConnectorID).Count(&memberCount).Error; err != nil {
		t.Fatalf("count team_members: %v", err)
	}
	if memberCount != 7 {
		t.Fatalf("team_members = %d; want 7", memberCount)
	}

	var teamCount int64
	if err := db.Model(&models.Team{}).Where("connector_id = ?", res.ConnectorID).Count(&teamCount).Error; err != nil {
		t.Fatalf("count teams: %v", err)
	}
	if teamCount != 3 {
		t.Fatalf("teams = %d; want 3", teamCount)
	}

	var syncState models.AccessSyncState
	if err := db.Where("connector_id = ?", res.ConnectorID).First(&syncState).Error; err != nil {
		t.Fatalf("sync_state not written: %v", err)
	}
	if syncState.IdentityCount != 10 {
		t.Fatalf("IdentityCount = %d; want 10", syncState.IdentityCount)
	}

	// --- Step 3: Disconnect ---
	if err := svc.Disconnect(context.Background(), res.ConnectorID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	var deletedConn models.AccessConnector
	if err := db.Unscoped().Where("id = ?", res.ConnectorID).First(&deletedConn).Error; err != nil {
		t.Fatalf("re-load connector: %v", err)
	}
	if !deletedConn.DeletedAt.Valid {
		t.Fatalf("connector deleted_at not set: %+v", deletedConn.DeletedAt)
	}
}

// newIntegrationDB constructs a SQLite in-memory DB with every model
// the integration tests need. We intentionally keep this list narrow
// — only the access-platform models are migrated — so unrelated
// schemas don't slow the test loop.
func newIntegrationDB(t *testing.T) *gorm.DB {
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
		&models.AccessGrantEntitlement{},
		&models.AccessWorkflow{},
		&models.AccessJob{},
		&models.AccessSyncState{},
		&models.AccessReview{},
		&models.AccessReviewDecision{},
		&models.Team{},
		&models.TeamMember{},
		&models.Policy{},
	); err != nil {
		t.Fatalf("auto migrate integration: %v", err)
	}
	return db
}


