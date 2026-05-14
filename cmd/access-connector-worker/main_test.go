package main

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/config"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubGrantRevoker is the minimal cron.GrantRevoker implementation
// the wiring test needs. The enforcer never invokes Revoke during
// construction so the call body is intentionally trivial.
type stubGrantRevoker struct{}

func (stubGrantRevoker) Revoke(_ context.Context, _ *models.AccessGrant, _, _ map[string]interface{}) error {
	return nil
}

// stubCredentialsLoader is the minimal
// cron.ConnectorCredentialsLoader implementation the wiring test
// needs. No call is made during construction so an empty body is
// safe.
type stubCredentialsLoader struct{}

func (stubCredentialsLoader) LoadConnectorCredentials(_ context.Context, _ string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

// TestWireCronJobs_AppliesGrantExpiryWarningHours is the Phase 11
// batch 6 regression for the config-wiring gap where the worker
// binary read ACCESS_GRANT_EXPIRY_WARNING_HOURS into
// cfg.GrantExpiryWarningHours but never invoked
// (*GrantExpiryEnforcer).SetWarningHours, leaving the operator
// override silently dropped on the floor. The test runs
// WireCronJobs with a non-default warning window and asserts the
// resulting enforcer exposes that exact window via its public
// accessor.
func TestWireCronJobs_AppliesGrantExpiryWarningHours(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	cfg := config.Access{GrantExpiryWarningHours: 72}
	jobs := WireCronJobs(db, nil, nil, stubGrantRevoker{}, stubCredentialsLoader{}, nil, cfg)
	if jobs.GrantExpiryEnforcer == nil {
		t.Fatalf("WireCronJobs: GrantExpiryEnforcer = nil; want non-nil")
	}
	if got := jobs.GrantExpiryEnforcer.WarningHours(); got != 72 {
		t.Errorf("WarningHours() = %d; want 72 (cfg.GrantExpiryWarningHours)", got)
	}
}

// TestWireCronJobs_GrantExpiryWarningHoursZeroFallsBackToDefault
// asserts the SetWarningHours guard (<=0 → 24) is exercised when
// the env var is unset and cfg.GrantExpiryWarningHours is the
// zero value. Without this guard a misconfigured deployment could
// land on the look-ahead-disabled state silently.
func TestWireCronJobs_GrantExpiryWarningHoursZeroFallsBackToDefault(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	cfg := config.Access{GrantExpiryWarningHours: 0}
	jobs := WireCronJobs(db, nil, nil, stubGrantRevoker{}, stubCredentialsLoader{}, nil, cfg)
	if jobs.GrantExpiryEnforcer == nil {
		t.Fatalf("WireCronJobs: GrantExpiryEnforcer = nil; want non-nil")
	}
	if got := jobs.GrantExpiryEnforcer.WarningHours(); got != 24 {
		t.Errorf("WarningHours() = %d; want 24 (SetWarningHours default)", got)
	}
}

// TestBuildOrphanReconciler_AppliesPerConnectorDelay is the
// Phase 11 batch 6 regression for the config-wiring gap where the
// worker binary read
// ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR into
// cfg.OrphanReconcileDelayPerConnector but never invoked
// (*OrphanReconciler).SetPerConnectorDelay, leaving the operator
// override silently dropped on the floor. BuildOrphanReconciler
// is the seam where the setter call landed (option (a) in the
// PR-thread discussion) — the test asserts the helper applies
// cfg.OrphanReconcileDelayPerConnector to the concrete pointer
// before WireCronJobs ever sees the WorkspaceOrphanReconciler
// interface view.
func TestBuildOrphanReconciler_AppliesPerConnectorDelay(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	prov := access.NewAccessProvisioningService(db)
	cred := access.NewConnectorCredentialsLoader(db, access.PassthroughEncryptor{})
	cfg := config.Access{OrphanReconcileDelayPerConnector: 250 * time.Millisecond}
	r := BuildOrphanReconciler(db, prov, cred, cfg)
	if r == nil {
		t.Fatalf("BuildOrphanReconciler: got nil; want non-nil reconciler")
	}
	if got, want := r.PerConnectorDelay(), 250*time.Millisecond; got != want {
		t.Errorf("PerConnectorDelay() = %v; want %v (cfg.OrphanReconcileDelayPerConnector)", got, want)
	}
}

// TestBuildOrphanReconciler_NilDepsReturnNil asserts the helper
// short-circuits to nil when any required dependency is nil so
// the scaffold main() — which currently passes three nils — can
// still hand the value straight into WireCronJobs, which then
// omits the orphan cron entirely.
func TestBuildOrphanReconciler_NilDepsReturnNil(t *testing.T) {
	cfg := config.Access{OrphanReconcileDelayPerConnector: time.Second}

	cases := []struct {
		name string
		fn   func() *access.OrphanReconciler
	}{
		{
			name: "all nil",
			fn: func() *access.OrphanReconciler {
				return BuildOrphanReconciler(nil, nil, nil, cfg)
			},
		},
		{
			name: "nil db",
			fn: func() *access.OrphanReconciler {
				return BuildOrphanReconciler(nil, &access.AccessProvisioningService{}, &access.ConnectorCredentialsLoader{}, cfg)
			},
		},
		{
			name: "nil provisioning service",
			fn: func() *access.OrphanReconciler {
				db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
				return BuildOrphanReconciler(db, nil, &access.ConnectorCredentialsLoader{}, cfg)
			},
		},
		{
			name: "nil credentials loader",
			fn: func() *access.OrphanReconciler {
				db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
				return BuildOrphanReconciler(db, &access.AccessProvisioningService{}, nil, cfg)
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn(); got != nil {
				t.Errorf("BuildOrphanReconciler(%s) = %v; want nil", tc.name, got)
			}
		})
	}
}
