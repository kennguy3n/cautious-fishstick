package cron

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// PAMLeaseExpirer is the narrow contract PAMLeaseExpiryEnforcer
// uses to flip expired leases into a terminal state. The production
// implementation is *pam.PAMLeaseService; tests substitute a stub
// that captures every call.
//
// ExpireLeasesByIDs is the entry point the enforcer drives — it
// flips exactly the set of leases the snapshot returned, so the
// session-termination + notification work the enforcer ran above
// stays tied to the rows actually moved to revoked.
type PAMLeaseExpirer interface {
	ExpiredLeases(ctx context.Context, batchSize int) ([]models.PAMLease, error)
	ExpireLeasesByIDs(ctx context.Context, leaseIDs []string) (int, error)
	NotifyExpired(ctx context.Context, leases []models.PAMLease)
}

// PAMSessionTerminator is the optional hook PAMLeaseExpiryEnforcer
// uses to terminate any pam_sessions tied to a lease that just
// expired. The production implementation will wrap the pam-gateway
// session terminator; tests substitute a stub.
type PAMSessionTerminator interface {
	TerminateSessionsForLease(ctx context.Context, leaseID, reason string) (int, error)
}

// PAMLeaseExpiryEnforcer is the Phase 6 background cron job that
// sweeps pam_leases whose expires_at has passed and revokes each
// row through the supplied PAMLeaseExpirer. Mirrors the contract
// of GrantExpiryEnforcer but for the JIT-lease lifecycle instead
// of standing access_grants.
//
// On each tick the enforcer:
//  1. Calls ExpiredLeases(batchSize) to fetch a snapshot of the
//     leases that the next ExpireLeases call would sweep.
//  2. For each expired lease, terminates any active sessions tied
//     to that lease through the optional PAMSessionTerminator
//     (best-effort, individual failures are logged + non-fatal).
//  3. Calls ExpireLeases() to flip the snapshot into the revoked
//     state in a single bulk UPDATE.
//  4. Fires NotifyExpired so the lease holder learns their JIT
//     access has lapsed.
//  5. Emits a structured "pam_lease_expiry_summary" log line with
//     leases_expired, sessions_terminated, duration_ms.
type PAMLeaseExpiryEnforcer struct {
	expirer    PAMLeaseExpirer
	terminator PAMSessionTerminator
	batchSize  int
	now        func() time.Time
}

// NewPAMLeaseExpiryEnforcer returns an enforcer bound to expirer.
// expirer must not be nil; terminator may be nil for dev / test
// binaries where the gateway side is not wired up yet. batchSize
// caps the number of leases processed per tick (zero / negative
// falls back to 100).
func NewPAMLeaseExpiryEnforcer(expirer PAMLeaseExpirer, terminator PAMSessionTerminator, batchSize int) *PAMLeaseExpiryEnforcer {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &PAMLeaseExpiryEnforcer{
		expirer:    expirer,
		terminator: terminator,
		batchSize:  batchSize,
		now:        time.Now,
	}
}

// SetClock overrides time.Now. Tests use this to pin tick
// timestamps to a deterministic value for log assertions.
func (e *PAMLeaseExpiryEnforcer) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// Run executes a single sweep. Returns (leasesExpired,
// sessionsTerminated, error). The expire is atomic for the
// snapshot it pulled — either every snapshot row flips or none —
// but the per-session terminate is best-effort.
//
// The flow snapshots up to batchSize leases via ExpiredLeases,
// terminates sessions + collects them for notification, then flips
// exactly that snapshot via ExpireLeasesByIDs. Excess overdue
// leases beyond batchSize are intentionally left for the next
// tick rather than swept by a bulk UPDATE — otherwise the cron
// would silently revoke leases without terminating their sessions
// or notifying their holders.
func (e *PAMLeaseExpiryEnforcer) Run(ctx context.Context) (int, int, error) {
	if e == nil || e.expirer == nil {
		return 0, 0, errors.New("cron: pam_lease_expiry_enforcer missing expirer")
	}
	start := e.now()
	expired, err := e.expirer.ExpiredLeases(ctx, e.batchSize)
	if err != nil {
		return 0, 0, fmt.Errorf("cron: list expired pam_leases: %w", err)
	}
	terminatedTotal := 0
	if e.terminator != nil {
		for i := range expired {
			lease := expired[i]
			n, terr := e.terminator.TerminateSessionsForLease(ctx, lease.ID, "lease expired")
			if terr != nil {
				log.Printf("cron: pam_lease_expiry_enforcer: terminate sessions lease=%s: %v", lease.ID, terr)
				continue
			}
			terminatedTotal += n
		}
	}
	leaseIDs := make([]string, len(expired))
	for i := range expired {
		leaseIDs[i] = expired[i].ID
	}
	expiredCount, err := e.expirer.ExpireLeasesByIDs(ctx, leaseIDs)
	if err != nil {
		return 0, terminatedTotal, fmt.Errorf("cron: expire pam_leases by ids: %w", err)
	}
	e.expirer.NotifyExpired(ctx, expired)
	durationMs := time.Since(start).Milliseconds()
	log.Printf("pam_lease_expiry_summary leases_expired=%d sessions_terminated=%d duration_ms=%d", expiredCount, terminatedTotal, durationMs)
	return expiredCount, terminatedTotal, nil
}

// DefaultPAMLeaseExpiryInterval returns the tick interval the
// worker binary should use when running the PAM lease expiry
// enforcer, consulting the PAM_LEASE_EXPIRY_CHECK_INTERVAL env
// var with a 1m default. Leases are shorter-lived than grants so
// the default cadence is tighter than the grant enforcer.
func DefaultPAMLeaseExpiryInterval() time.Duration {
	v := os.Getenv("PAM_LEASE_EXPIRY_CHECK_INTERVAL")
	if v == "" {
		return time.Minute
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("cron: invalid PAM_LEASE_EXPIRY_CHECK_INTERVAL=%q, falling back to 1m: %v", v, err)
		return time.Minute
	}
	return d
}

// EnsureDBNonNil is a sanity check exported so the worker binary
// can refuse to boot when the PAM module is wired without a DB.
// Returns nil when db is non-nil.
func EnsureDBNonNil(db *gorm.DB) error {
	if db == nil {
		return errors.New("cron: pam_lease_expiry_enforcer requires a non-nil *gorm.DB")
	}
	return nil
}
