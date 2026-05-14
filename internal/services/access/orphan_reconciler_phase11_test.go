package access

import (
	"context"
	"errors"
	"strings"
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
	// A real ReconcileWorkspace after the dry-run must still persist
	// rows — dry-run is per-call, not a sticky struct flag.
	wet, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err != nil {
		t.Fatalf("ReconcileWorkspace (wet) after dry-run: %v", err)
	}
	if len(wet) != 2 {
		t.Errorf("wet sweep detected = %d; want 2", len(wet))
	}
	for _, r := range wet {
		if r.ID == "" {
			t.Errorf("wet sweep row has empty ID; want persisted")
		}
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

// TestOrphanReconciler_DryRunIsolatedFromWet asserts that a
// dry-run sweep does NOT alter the behaviour of a subsequent wet
// sweep when the two are interleaved sequentially. Together with
// the in-test wet-after-dry assertion in
// TestOrphanReconciler_DryRun_DoesNotPersist this locks in the
// Phase 11 batch 6 race fix where dry-run was a shared struct
// field — concurrent HTTP requests could flip the bool and let
// other requests silently skip persistence.
func TestOrphanReconciler_DryRunIsolatedFromWet(t *testing.T) {
	const provider = "mock_orphan_dryrun_isolated"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	_ = seedConnectorWithSecrets(t, db, "01HCONN0ORPHANISOLATED00001", provider)

	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{{ExternalID: "u-iso-1"}}, "")
		},
	}
	SwapConnector(t, provider, mock)

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)

	// Interleave dry/wet/dry. The wet sweep in the middle must
	// persist a row even though the dry sweeps before and after
	// pass dryRun=true to the same reconcileConnector code path.
	if _, err := rec.ReconcileWorkspaceDryRun(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("dry-run 1: %v", err)
	}
	if _, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("wet: %v", err)
	}
	if _, err := rec.ReconcileWorkspaceDryRun(context.Background(), "01H000000000000000WORKSPACE"); err != nil {
		t.Fatalf("dry-run 2: %v", err)
	}

	var rows []models.AccessOrphanAccount
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("list orphans: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("persisted orphans after dry+wet+dry = %d; want 1 (the wet sweep)", len(rows))
	}
}

// TestOrphanReconciler_BestEffortAcrossConnectors_FailingConnectorDoesNotBlockOthers
// asserts that when one of N connectors in a workspace fails, the
// reconciler continues iterating the remaining connectors instead
// of short-circuiting on the first error (per docs/ARCHITECTURE.md
// §12.2 the reconciler is best-effort across connectors). The
// failure surfaces as an aggregated error so the cron can still
// log it.
func TestOrphanReconciler_BestEffortAcrossConnectors_FailingConnectorDoesNotBlockOthers(t *testing.T) {
	const providerFail = "mock_orphan_best_effort_fail"
	const providerB = "mock_orphan_best_effort_b"
	const providerC = "mock_orphan_best_effort_c"
	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	// Seed three connectors. The first one's mock returns an
	// error; the next two emit a distinct upstream identity each.
	// All three must run; rows from B + C must persist.
	_ = seedConnectorWithSecrets(t, db, "01HCONN0BESTEFFORT00000A001", providerFail)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0BESTEFFORT00000B001", providerB)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0BESTEFFORT00000C001", providerC)

	SwapConnector(t, providerFail, &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, _ func([]*Identity, string) error) error {
			return errors.New("upstream boom")
		},
	})
	SwapConnector(t, providerB, &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{{ExternalID: "u-best-effort-b", Email: "b@example.com"}}, "")
		},
	})
	SwapConnector(t, providerC, &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
			return h([]*Identity{{ExternalID: "u-best-effort-c", Email: "c@example.com"}}, "")
		},
	})

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)

	got, err := rec.ReconcileWorkspace(context.Background(), "01H000000000000000WORKSPACE")
	if err == nil {
		t.Fatalf("ReconcileWorkspace returned nil error; want aggregated error from failing connector")
	}
	if !strings.Contains(err.Error(), "upstream boom") {
		t.Errorf("aggregated error %q; want it to contain failing connector's message", err.Error())
	}
	if len(got) != 2 {
		t.Fatalf("orphan rows returned = %d; want 2 (one each from connector B and C)", len(got))
	}
	externals := map[string]bool{}
	for _, r := range got {
		externals[r.UserExternalID] = true
	}
	if !externals["u-best-effort-b"] || !externals["u-best-effort-c"] {
		t.Errorf("orphans returned = %v; want both u-best-effort-b and u-best-effort-c", externals)
	}

	var persisted []models.AccessOrphanAccount
	if err := db.Find(&persisted).Error; err != nil {
		t.Fatalf("list orphans: %v", err)
	}
	if len(persisted) != 2 {
		t.Errorf("persisted orphans = %d; want 2 (failing connector's pass left no rows, B + C each landed one)", len(persisted))
	}

	scanned, failed, serr := rec.WorkspaceConnectorStats(context.Background(), "01H000000000000000WORKSPACE")
	if serr != nil {
		t.Fatalf("WorkspaceConnectorStats: %v", serr)
	}
	if scanned != 3 {
		t.Errorf("scanned = %d; want 3 (all connectors attempted under best-effort)", scanned)
	}
	if failed != 1 {
		t.Errorf("failed = %d; want 1 (only the first connector raised)", failed)
	}
}
