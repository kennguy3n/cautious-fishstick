package main

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/config"
	"github.com/kennguy3n/cautious-fishstick/internal/cron"
	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubGrantExpiryNotifier is the minimal cron.GrantExpiryNotifier
// implementation the wiring test needs. No call is made during
// WireCronJobs so the bodies are intentionally trivial — the test
// only asserts the pointer landed on the enforcer via its public
// Notifier() accessor.
type stubGrantExpiryNotifier struct{}

func (stubGrantExpiryNotifier) SendGrantRevokedNotification(_ context.Context, _, _, _, _ string, _ time.Time) error {
	return nil
}
func (stubGrantExpiryNotifier) SendGrantExpiryWarning(_ context.Context, _, _, _, _ string, _ time.Time, _ int) error {
	return nil
}

// stubAuditProducer is the minimal access.AuditProducer the wiring
// test needs. No call is made during WireCronJobs so the body is
// trivial — the test only asserts the pointer landed on the
// enforcer via its public AuditProducer() accessor.
type stubAuditProducer struct{}

func (*stubAuditProducer) PublishAccessAuditLogs(_ context.Context, _ string, _ []*access.AuditLogEntry) error {
	return nil
}
func (*stubAuditProducer) Close() error { return nil }

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
	jobs := WireCronJobs(db, nil, nil, stubGrantRevoker{}, stubCredentialsLoader{}, nil, nil, nil, cfg)
	if jobs.GrantExpiryEnforcer == nil {
		t.Fatalf("WireCronJobs: GrantExpiryEnforcer = nil; want non-nil")
	}
	if got := jobs.GrantExpiryEnforcer.WarningHours(); got != 72 {
		t.Errorf("WarningHours() = %d; want 72 (cfg.GrantExpiryWarningHours)", got)
	}
}

// TestWireCronJobs_WiresGrantExpiryNotifierAndAuditProducer is the
// Phase 11 batch 6 round-7 regression for the wiring gap where
// WireCronJobs called SetWarningHours on the GrantExpiryEnforcer
// but did NOT call SetNotifier or SetAuditProducer, leaving the
// notification + audit hooks disconnected even though both
// features were implemented in the enforcer. The test passes a
// non-nil stub for each hook and asserts the pointers landed on
// the enforcer via its public Notifier() / AuditProducer()
// accessors. Without the wiring, both accessors would return nil
// and downstream SIEM consumers + users would never see any
// grant-expiry traffic out of the production binary.
func TestWireCronJobs_WiresGrantExpiryNotifierAndAuditProducer(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	notifier := stubGrantExpiryNotifier{}
	audit := &stubAuditProducer{}
	cfg := config.Access{GrantExpiryWarningHours: 24}
	jobs := WireCronJobs(db, nil, nil, stubGrantRevoker{}, stubCredentialsLoader{}, notifier, audit, nil, cfg)
	if jobs.GrantExpiryEnforcer == nil {
		t.Fatalf("WireCronJobs: GrantExpiryEnforcer = nil; want non-nil")
	}
	if jobs.GrantExpiryEnforcer.Notifier() == nil {
		t.Error("Notifier() = nil; want non-nil (SetNotifier must wire grantExpiryNotifier)")
	}
	if jobs.GrantExpiryEnforcer.AuditProducer() == nil {
		t.Error("AuditProducer() = nil; want non-nil (SetAuditProducer must wire auditProducer)")
	}
	// Phase 11 batch 6 round-7: the warning sweep cadence must
	// also be populated so StartCronJobs has something to tick
	// for jobs.GrantExpiryEnforcer.RunWarning.
	if jobs.GrantExpiryWarningInterval <= 0 {
		t.Errorf("GrantExpiryWarningInterval = %v; want > 0 (the warning sweep must have a tick cadence)", jobs.GrantExpiryWarningInterval)
	}
}

// TestWireCronJobs_GrantExpiryNotifierNilStaysSkipped asserts the
// scaffold path where grantExpiryNotifier is nil does not panic
// and leaves the enforcer's Notifier() returning nil so the
// enforcer's Status="skipped" branch (round 3) fires correctly
// when RunWarning ticks against an unwired notifier.
func TestWireCronJobs_GrantExpiryNotifierNilStaysSkipped(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	cfg := config.Access{GrantExpiryWarningHours: 24}
	jobs := WireCronJobs(db, nil, nil, stubGrantRevoker{}, stubCredentialsLoader{}, nil, nil, nil, cfg)
	if jobs.GrantExpiryEnforcer == nil {
		t.Fatalf("WireCronJobs: GrantExpiryEnforcer = nil; want non-nil (nil notifier must not omit the cron)")
	}
	if jobs.GrantExpiryEnforcer.Notifier() != nil {
		t.Error("Notifier() = non-nil; want nil so the enforcer's Status=\"skipped\" branch fires")
	}
	if jobs.GrantExpiryEnforcer.AuditProducer() != nil {
		t.Error("AuditProducer() = non-nil; want nil so the audit branch short-circuits")
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
	jobs := WireCronJobs(db, nil, nil, stubGrantRevoker{}, stubCredentialsLoader{}, nil, nil, nil, cfg)
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

// TestWireCronJobs_NilInterfaceTrapDoesNotEnableOrphanCron is the
// Phase 11 batch 6 round-8 regression for the nil-interface
// gotcha where a typed-nil concrete *access.OrphanReconciler
// assigned directly into a cron.WorkspaceOrphanReconciler-typed
// variable produces a non-nil interface value carrying a nil
// dynamic pointer. WireCronJobs' `orphanReconciler != nil` guard
// would then evaluate to true and construct a scheduler around
// the nil pointer — the first tick would panic on a nil-pointer
// deref.
//
// main()'s wrap pattern guards against this by assigning to the
// interface variable only when the concrete pointer is non-nil
// (so the interface stays a properly-nil interface in the
// scaffold path). The test below replays both patterns:
//
//  1. The buggy pattern (direct assign of typed nil) — confirms
//     WireCronJobs WOULD construct a non-nil scheduler around the
//     bogus interface, illustrating the bug.
//  2. The safe wrap pattern from main() — confirms the
//     interface stays nil and WireCronJobs correctly omits the
//     orphan cron.
//
// The first sub-test is a should-not-happen assertion: it documents
// the bug surface so a future refactor cannot reintroduce the gap
// without flipping this assertion.
func TestWireCronJobs_NilInterfaceTrapDoesNotEnableOrphanCron(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	cfg := config.Access{}

	// Scaffold-path build: nil deps → BuildOrphanReconciler
	// returns a nil concrete *access.OrphanReconciler. This is
	// the value main() wraps before handing it to WireCronJobs.
	concreteNil := BuildOrphanReconciler(nil, nil, nil, cfg)
	if concreteNil != nil {
		t.Fatalf("BuildOrphanReconciler(nil deps) = %v; want nil concrete pointer (precondition for the wrap test)", concreteNil)
	}

	t.Run("buggy_direct_assign_produces_non_nil_interface", func(t *testing.T) {
		// Direct assignment of the typed-nil pointer to an
		// interface variable. Go converts (*T)(nil) into an
		// interface value with a non-nil type tag, so the
		// `!= nil` check below is true even though the
		// dynamic pointer is nil — the classic gotcha.
		var buggy cron.WorkspaceOrphanReconciler = concreteNil
		if buggy == nil {
			t.Fatal("regression: nil-interface gotcha appears to be gone; the test premise is invalid — re-evaluate the wrap pattern in main()")
		}
		// We intentionally do NOT call WireCronJobs with the
		// buggy value because the resulting scheduler would
		// panic on first tick. The point of this sub-test is
		// to document why main()'s wrap pattern is required.
	})

	t.Run("safe_wrap_keeps_interface_nil_and_omits_orphan_cron", func(t *testing.T) {
		// Mirrors the wrap pattern in cmd/access-connector-
		// worker/main.go: assign to the interface variable
		// only when the concrete pointer is non-nil so the
		// interface stays a properly-nil interface.
		var safe cron.WorkspaceOrphanReconciler
		if concreteNil != nil {
			safe = concreteNil
		}
		if safe != nil {
			t.Fatalf("safe wrap: interface = %v; want nil (the concrete pointer was nil so the interface must stay nil)", safe)
		}
		jobs := WireCronJobs(db, nil, nil, nil, nil, nil, nil, safe, cfg)
		if jobs.OrphanReconcilerScheduler != nil {
			t.Errorf("OrphanReconcilerScheduler = %v; want nil (WireCronJobs' orphanReconciler != nil guard must skip the cron when the interface is properly nil)", jobs.OrphanReconcilerScheduler)
		}
	})
}

// TestStartCronJobs_EmptyJobsReturnsResolvedWaitGroup asserts the
// graceful-shutdown contract Devin Review #3246201801 flagged at
// the wiring layer: StartCronJobs returns a *sync.WaitGroup so
// main() can bound a drain on wg.Wait() after ctx.Done(). The
// scaffold path (empty CronJobs, e.g. when ACCESS_DATABASE_URL is
// unset) must return a WaitGroup with zero outstanding counts so
// the drain is an immediate no-op instead of blocking the binary's
// exit on a cron that was never started.
func TestStartCronJobs_EmptyJobsReturnsResolvedWaitGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := StartCronJobs(ctx, CronJobs{})
	if wg == nil {
		t.Fatal("StartCronJobs returned a nil *sync.WaitGroup; main() would panic dereferencing it")
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wg.Wait blocked on an empty cron set; want immediate return so the scaffold-path drain is a no-op")
	}
}

// TestRunCron_ExitsOnContextCancel pins the per-goroutine drain
// behaviour StartCronJobs relies on: each runCron invocation must
// return when its ctx is cancelled so the defer wg.Done() at the
// StartCronJobs spawn site fires and the parent wg.Wait can
// resolve. A goroutine that ignores ctx.Done would orphan its
// WaitGroup count and main()'s drain would always hit the timeout
// branch.
func TestRunCron_ExitsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runCron(ctx, "test-job", 5*time.Millisecond, func(ctx context.Context) error {
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		})
		close(done)
	}()

	// Wait until at least one tick has fired so the goroutine is
	// definitely inside the runCron select loop, then cancel.
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("runCron never ticked; cannot validate drain semantics")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCron did not return after context cancel; goroutine would leak past wg.Wait")
	}
}
