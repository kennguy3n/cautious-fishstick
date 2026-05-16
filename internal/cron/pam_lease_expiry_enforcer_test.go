package cron

import (
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// fakePAMLeaseExpirer is a test stub for PAMLeaseExpirer that
// captures every call without touching a DB. lastExpiredIDs records
// the exact ID slice the enforcer passed to ExpireLeasesByIDs so
// the batch/bulk regression test (the cron must flip exactly the
// snapshot it terminated sessions for) has a concrete assertion
// target rather than a row-count.
type fakePAMLeaseExpirer struct {
	expired         []models.PAMLease
	expiredErr      error
	expireRows      int
	expireErr       error
	notifyCallCount int
	lastNotify      []models.PAMLease
	lastExpiredIDs  []string
}

func (f *fakePAMLeaseExpirer) ExpiredLeases(_ context.Context, _ int) ([]models.PAMLease, error) {
	return f.expired, f.expiredErr
}

func (f *fakePAMLeaseExpirer) ExpireLeasesByIDs(_ context.Context, ids []string) (int, error) {
	f.lastExpiredIDs = append([]string(nil), ids...)
	return f.expireRows, f.expireErr
}

func (f *fakePAMLeaseExpirer) NotifyExpired(_ context.Context, leases []models.PAMLease) {
	f.notifyCallCount++
	f.lastNotify = leases
}

// fakePAMSessionTerminator is the test stub for the optional
// session-terminator hook.
type fakePAMSessionTerminator struct {
	calls   map[string]int
	perCall int
	err     error
}

func (f *fakePAMSessionTerminator) TerminateSessionsForLease(_ context.Context, leaseID, _ string) (int, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[leaseID]++
	if f.err != nil {
		return 0, f.err
	}
	return f.perCall, nil
}

func TestPAMLeaseExpiryEnforcer_NilExpirer(t *testing.T) {
	enf := NewPAMLeaseExpiryEnforcer(nil, nil, 0)
	_, _, err := enf.Run(context.Background())
	if err == nil {
		t.Fatalf("Run with nil expirer should error")
	}
}

func TestPAMLeaseExpiryEnforcer_EmptyResultSet(t *testing.T) {
	expirer := &fakePAMLeaseExpirer{}
	enf := NewPAMLeaseExpiryEnforcer(expirer, nil, 50)
	leases, sessions, err := enf.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if leases != 0 || sessions != 0 {
		t.Fatalf("counts = (%d, %d); want (0, 0)", leases, sessions)
	}
	if expirer.notifyCallCount != 1 {
		t.Fatalf("notify calls = %d; want 1", expirer.notifyCallCount)
	}
}

func TestPAMLeaseExpiryEnforcer_ExpiresOverdueLeases(t *testing.T) {
	expirer := &fakePAMLeaseExpirer{
		expired:    []models.PAMLease{{ID: "lease-1"}, {ID: "lease-2"}, {ID: "lease-3"}},
		expireRows: 3,
	}
	terminator := &fakePAMSessionTerminator{perCall: 1}
	enf := NewPAMLeaseExpiryEnforcer(expirer, terminator, 100)
	leases, sessions, err := enf.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if leases != 3 {
		t.Fatalf("leases expired = %d; want 3", leases)
	}
	if sessions != 3 {
		t.Fatalf("sessions terminated = %d; want 3", sessions)
	}
	if len(terminator.calls) != 3 {
		t.Fatalf("terminator calls = %d; want 3", len(terminator.calls))
	}
	// The cron MUST flip exactly the snapshot it terminated
	// sessions for. The previous implementation used ExpireLeases()
	// which bulk-flipped everything past expires_at, allowing rows
	// beyond the batch to be marked revoked silently. With the
	// ExpireLeasesByIDs contract we can verify the enforcer passes
	// the same 3 IDs it just terminated sessions for.
	if len(expirer.lastExpiredIDs) != 3 {
		t.Fatalf("expireByIDs ids = %v; want 3 ids", expirer.lastExpiredIDs)
	}
	for i, want := range []string{"lease-1", "lease-2", "lease-3"} {
		if expirer.lastExpiredIDs[i] != want {
			t.Fatalf("expireByIDs[%d] = %q; want %q", i, expirer.lastExpiredIDs[i], want)
		}
	}
}

func TestPAMLeaseExpiryEnforcer_TerminatorFailureIsLogged(t *testing.T) {
	expirer := &fakePAMLeaseExpirer{
		expired:    []models.PAMLease{{ID: "lease-1"}, {ID: "lease-2"}},
		expireRows: 2,
	}
	terminator := &fakePAMSessionTerminator{err: errors.New("boom")}
	enf := NewPAMLeaseExpiryEnforcer(expirer, terminator, 100)
	leases, sessions, err := enf.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should swallow per-lease terminate failures: %v", err)
	}
	if leases != 2 {
		t.Fatalf("leases expired = %d; want 2", leases)
	}
	if sessions != 0 {
		t.Fatalf("sessions terminated = %d; want 0 on terminator error", sessions)
	}
}

func TestPAMLeaseExpiryEnforcer_ExpiredLeasesError(t *testing.T) {
	expirer := &fakePAMLeaseExpirer{expiredErr: errors.New("db down")}
	enf := NewPAMLeaseExpiryEnforcer(expirer, nil, 100)
	_, _, err := enf.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when ExpiredLeases fails")
	}
}

func TestPAMLeaseExpiryEnforcer_ExpireLeasesError(t *testing.T) {
	expirer := &fakePAMLeaseExpirer{
		expired:   []models.PAMLease{{ID: "lease-1"}},
		expireErr: errors.New("db down"),
	}
	enf := NewPAMLeaseExpiryEnforcer(expirer, nil, 100)
	_, _, err := enf.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when ExpireLeasesByIDs fails")
	}
}

func TestPAMLeaseExpiryEnforcer_NilTerminatorIsOk(t *testing.T) {
	expirer := &fakePAMLeaseExpirer{
		expired:    []models.PAMLease{{ID: "lease-1"}},
		expireRows: 1,
	}
	enf := NewPAMLeaseExpiryEnforcer(expirer, nil, 100)
	leases, sessions, err := enf.Run(context.Background())
	if err != nil {
		t.Fatalf("Run with nil terminator: %v", err)
	}
	if leases != 1 || sessions != 0 {
		t.Fatalf("counts = (%d, %d); want (1, 0)", leases, sessions)
	}
}

func TestDefaultPAMLeaseExpiryInterval_DefaultsToOneMinute(t *testing.T) {
	t.Setenv("PAM_LEASE_EXPIRY_CHECK_INTERVAL", "")
	if got := DefaultPAMLeaseExpiryInterval(); got.Minutes() != 1 {
		t.Fatalf("default interval = %v; want 1m", got)
	}
}

func TestDefaultPAMLeaseExpiryInterval_HonoursOverride(t *testing.T) {
	t.Setenv("PAM_LEASE_EXPIRY_CHECK_INTERVAL", "30s")
	if got := DefaultPAMLeaseExpiryInterval(); got.Seconds() != 30 {
		t.Fatalf("override interval = %v; want 30s", got)
	}
}

func TestDefaultPAMLeaseExpiryInterval_InvalidValueFallsBack(t *testing.T) {
	t.Setenv("PAM_LEASE_EXPIRY_CHECK_INTERVAL", "not-a-duration")
	if got := DefaultPAMLeaseExpiryInterval(); got.Minutes() != 1 {
		t.Fatalf("invalid interval should fall back to 1m, got %v", got)
	}
}

func TestEnsureDBNonNil(t *testing.T) {
	if err := EnsureDBNonNil(nil); err == nil {
		t.Fatalf("nil DB should error")
	}
}
