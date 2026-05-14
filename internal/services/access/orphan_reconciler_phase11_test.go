package access

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestOrphanReconciler_DryRun_DoesNotPersist asserts that the
// Phase 11 batch 6 dry-run mode detects unused app accounts but
// never writes to access_orphan_accounts.
func TestOrphanReconciler_DryRun_DoesNotPersist(t *testing.T) {
	const provider = "mock_orphan_dryrun"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	_ = seedConnectorWithSecrets(t, db, "01HCONN0ORPHANDRY000000001", provider)

	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{
				{ExternalID: "u-dry-1", Email: "dry1@example.com"},
				{ExternalID: "u-dry-2", Email: "dry2@example.com"},
			}, "")
		},
	}
	SwapConnector(t, provider, mock)

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)

	got, err := rec.ReconcileWorkspaceDryRun(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ReconcileWorkspaceDryRun: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("dry-run detected = %d; want 2 (%v)", len(got), got)
	}
	for _, r := range got {
		if r.ID != "" {
			t.Errorf("dry-run row has ID=%q; want empty (not persisted)", r.ID)
		}
	}
	var rows []models.AccessOrphanAccount
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("list orphans: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("persisted orphans after dry-run = %d; want 0", len(rows))
	}
	if rec.DryRun {
		t.Errorf("DryRun flag = true after ReconcileWorkspaceDryRun; want false (must be restored)")
	}
}

// TestOrphanReconciler_PerConnectorDelay_ThrottlesIterations
// asserts the configurable per-connector throttle introduces a
// delay between connector iterations.
func TestOrphanReconciler_PerConnectorDelay_ThrottlesIterations(t *testing.T) {
	const providerA = "mock_orphan_throttle_a"
	const providerB = "mock_orphan_throttle_b"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	_ = seedConnectorWithSecrets(t, db, "01HCONN0ORPHANTHROTTLE00A01", providerA)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0ORPHANTHROTTLE00B01", providerB)

	emit := func(externalID string) *MockAccessConnector {
		return &MockAccessConnector{
			FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
				return h([]*Identity{{ExternalID: externalID}}, "")
			},
		}
	}
	SwapConnector(t, providerA, emit("u-a"))
	SwapConnector(t, providerB, emit("u-b"))

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(50 * time.Millisecond)

	start := time.Now()
	if _, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("ReconcileWorkspace: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Errorf("elapsed = %v with 2 connectors and 50ms delay; want >= 50ms", elapsed)
	}
}

// TestOrphanReconciler_PerConnectorDelay_ZeroDisabled asserts that
// passing 0 to SetPerConnectorDelay disables the throttle.
func TestOrphanReconciler_PerConnectorDelay_ZeroDisabled(t *testing.T) {
	const providerA = "mock_orphan_throttle_zero_a"
	const providerB = "mock_orphan_throttle_zero_b"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	_ = seedConnectorWithSecrets(t, db, "01HCONN0ORPHANTHROTTLEZ0A01", providerA)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0ORPHANTHROTTLEZ0B01", providerB)

	emit := func(externalID string) *MockAccessConnector {
		return &MockAccessConnector{
			FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
				return h([]*Identity{{ExternalID: externalID}}, "")
			},
		}
	}
	SwapConnector(t, providerA, emit("u-a"))
	SwapConnector(t, providerB, emit("u-b"))

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)

	start := time.Now()
	if _, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("ReconcileWorkspace: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("elapsed = %v; want fast (no throttle)", elapsed)
	}
}
