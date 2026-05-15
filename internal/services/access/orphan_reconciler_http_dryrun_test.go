package access_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// raceSafeOrphanConnector is a goroutine-safe AccessConnector
// implementation that yields a fixed identity list. The
// production access.MockAccessConnector increments a call counter
// without a mutex which trips the race detector when multiple
// HTTP callers invoke the same connector in parallel; this stub
// avoids that mutation entirely.
type raceSafeOrphanConnector struct{ identities []*access.Identity }

func (raceSafeOrphanConnector) Validate(_ context.Context, _, _ map[string]interface{}) error {
	return nil
}
func (raceSafeOrphanConnector) Connect(_ context.Context, _, _ map[string]interface{}) error {
	return nil
}
func (raceSafeOrphanConnector) VerifyPermissions(_ context.Context, _, _ map[string]interface{}, _ []string) ([]string, error) {
	return nil, nil
}
func (raceSafeOrphanConnector) CountIdentities(_ context.Context, _, _ map[string]interface{}) (int, error) {
	return 0, nil
}
func (c raceSafeOrphanConnector) SyncIdentities(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*access.Identity, string) error) error {
	return handler(c.identities, "")
}
func (raceSafeOrphanConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return nil
}
func (raceSafeOrphanConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return nil
}
func (raceSafeOrphanConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, nil
}
func (raceSafeOrphanConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}
func (raceSafeOrphanConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

func init() {
	gin.SetMode(gin.TestMode)
}

const orphanHTTPTestWorkspace = "01H000000000000000WORKSPACE"

// newOrphanHTTPTestDB returns an in-memory sqlite handle migrated
// for the orphan reconciler's full dependency graph (connectors,
// team members, and access_orphan_accounts).
func newOrphanHTTPTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Concurrent goroutines that issue parallel POST requests can
	// race on sqlite's per-connection in-memory tables; capping the
	// pool to 1 connection makes the schema visible to every caller
	// without changing semantics.
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB(): %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(
		&models.AccessConnector{},
		&models.Team{},
		&models.TeamMember{},
		&models.AccessOrphanAccount{},
	); err != nil {
		t.Fatalf("automigrate orphan-http: %v", err)
	}
	return db
}

// seedOrphanHTTPFixture seeds 1 connector + an upstream mock that
// returns 2 identities (u1 + u2) with only u1 backed by a
// team_members row. u2 is the synthetic "unused app account" the
// reconciler will surface.
func seedOrphanHTTPFixture(t *testing.T, db *gorm.DB) string {
	t.Helper()
	const provider = "mock_orphan_http_dryrun"
	const connID = "01HCONN0ORPHANHTTP00000001"
	if err := db.Create(&models.AccessConnector{
		ID:            connID,
		WorkspaceID:   orphanHTTPTestWorkspace,
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	access.SwapConnector(t, provider, raceSafeOrphanConnector{
		identities: []*access.Identity{
			{ExternalID: "u-http-1", Email: "u1@example.com"},
			{ExternalID: "u-http-2", Email: "u2@example.com"},
		},
	})
	if err := db.Create(&models.Team{
		ID:          "01HTEAMORPHANHTTP00000001",
		WorkspaceID: orphanHTTPTestWorkspace,
		Name:        "test-team",
	}).Error; err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := db.Create(&models.TeamMember{
		ID:          "01HTMORPHANHTTP000000001A",
		TeamID:      "01HTEAMORPHANHTTP00000001",
		UserID:      "01HUSERORPHANHTTP00000001",
		ConnectorID: connID,
		ExternalID:  "u-http-1",
	}).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}
	return connID
}

// reconcileResp is the canonical handler envelope under test.
type reconcileResp struct {
	UnusedAppAccounts []struct {
		ID          string `json:"id"`
		AppUserID   string `json:"app_user_id"`
		ConnectorID string `json:"connector_id"`
	} `json:"unused_app_accounts"`
	DryRun bool `json:"dry_run"`
}

func postReconcile(t *testing.T, r *gin.Engine, dryRun bool) reconcileResp {
	t.Helper()
	body := bytes.NewBufferString(`{"workspace_id":"` + orphanHTTPTestWorkspace + `","dry_run":` + boolStr(dryRun) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/reconcile", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry_run=%v status = %d (body=%s); want 200", dryRun, rec.Code, rec.Body.String())
	}
	var out reconcileResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestOrphanReconciler_HTTP_DryRun_DoesNotPersist drives the
// production HTTP route POST /access/orphans/reconcile with
// dry_run=true and asserts:
//   - the response surfaces the detected unused account, and
//   - the access_orphan_accounts table stays empty.
//
// This is the HTTP-level counterpart to the service-level
// TestOrphanReconciler_DryRun_DoesNotPersist test in
// orphan_reconciler_phase11_test.go.
func TestOrphanReconciler_HTTP_DryRun_DoesNotPersist(t *testing.T) {
	db := newOrphanHTTPTestDB(t)
	seedOrphanHTTPFixture(t, db)

	rec := access.NewOrphanReconciler(db, access.NewAccessProvisioningService(db), access.NewConnectorCredentialsLoader(db, access.PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)
	r := handlers.Router(handlers.Dependencies{OrphanReconciler: rec, DisableRateLimiter: true})

	got := postReconcile(t, r, true)
	if !got.DryRun {
		t.Error("envelope dry_run = false; want true echoing the request")
	}
	if len(got.UnusedAppAccounts) != 1 || got.UnusedAppAccounts[0].AppUserID != "u-http-2" {
		t.Errorf("unused_app_accounts = %+v; want exactly [u-http-2]", got.UnusedAppAccounts)
	}
	var n int64
	if err := db.Model(&models.AccessOrphanAccount{}).Count(&n).Error; err != nil {
		t.Fatalf("count orphan rows: %v", err)
	}
	if n != 0 {
		t.Errorf("access_orphan_accounts rows = %d; want 0 after dry_run", n)
	}
}

// TestOrphanReconciler_HTTP_WetRun_Persists drives the same route
// with dry_run=false and asserts the access_orphan_accounts table
// captures the detected unused account.
func TestOrphanReconciler_HTTP_WetRun_Persists(t *testing.T) {
	db := newOrphanHTTPTestDB(t)
	seedOrphanHTTPFixture(t, db)

	rec := access.NewOrphanReconciler(db, access.NewAccessProvisioningService(db), access.NewConnectorCredentialsLoader(db, access.PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)
	r := handlers.Router(handlers.Dependencies{OrphanReconciler: rec, DisableRateLimiter: true})

	got := postReconcile(t, r, false)
	if got.DryRun {
		t.Error("envelope dry_run = true; want false echoing the request")
	}
	if len(got.UnusedAppAccounts) != 1 {
		t.Fatalf("unused_app_accounts = %d; want 1", len(got.UnusedAppAccounts))
	}
	var rows []models.AccessOrphanAccount
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("list orphan rows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("access_orphan_accounts rows = %d; want 1 after wet run", len(rows))
	}
	if rows[0].UserExternalID != "u-http-2" {
		t.Errorf("persisted UserExternalID = %q; want u-http-2", rows[0].UserExternalID)
	}
}

// TestOrphanReconciler_HTTP_ConcurrentDryAndWet asserts the
// per-call dryRun flag (vs a shared struct field) lets concurrent
// callers mix dry and wet sweeps without racing on a shared piece
// of state. The wet caller must persist exactly one row; the dry
// caller must not persist anything additional.
func TestOrphanReconciler_HTTP_ConcurrentDryAndWet(t *testing.T) {
	db := newOrphanHTTPTestDB(t)
	seedOrphanHTTPFixture(t, db)

	rec := access.NewOrphanReconciler(db, access.NewAccessProvisioningService(db), access.NewConnectorCredentialsLoader(db, access.PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)
	r := handlers.Router(handlers.Dependencies{OrphanReconciler: rec, DisableRateLimiter: true})

	const dryCallers = 4
	var wg sync.WaitGroup
	wg.Add(dryCallers + 1)
	for i := 0; i < dryCallers; i++ {
		go func() {
			defer wg.Done()
			got := postReconcile(t, r, true)
			if !got.DryRun {
				t.Errorf("concurrent dry_run echo missing")
			}
		}()
	}
	go func() {
		defer wg.Done()
		got := postReconcile(t, r, false)
		if got.DryRun {
			t.Errorf("wet caller saw dry_run=true echo")
		}
	}()
	wg.Wait()

	var rows []models.AccessOrphanAccount
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("list orphan rows: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows = %d; want exactly 1 after 1 wet + N dry callers", len(rows))
	}
}
