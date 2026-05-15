package cron

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubGrantExpiryNotifier captures every notification call so tests
// can assert the enforcer fired the right hook with the right
// arguments after revoke / warning sweeps.
type stubGrantExpiryNotifier struct {
	mu          sync.Mutex
	revokeCalls []struct {
		WorkspaceID, UserID, ConnectorID, ResourceID string
		ExpiresAt                                    time.Time
	}
	warnCalls []struct {
		WorkspaceID, UserID, ConnectorID, ResourceID string
		ExpiresAt                                    time.Time
		HoursAhead                                   int
	}
	revokeErr error
	warnErr   error
}

func (s *stubGrantExpiryNotifier) SendGrantRevokedNotification(_ context.Context, workspaceID, userID, connectorID, resourceID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeCalls = append(s.revokeCalls, struct {
		WorkspaceID, UserID, ConnectorID, ResourceID string
		ExpiresAt                                    time.Time
	}{workspaceID, userID, connectorID, resourceID, expiresAt})
	return s.revokeErr
}

func (s *stubGrantExpiryNotifier) SendGrantExpiryWarning(_ context.Context, workspaceID, userID, connectorID, resourceID string, expiresAt time.Time, hoursAhead int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warnCalls = append(s.warnCalls, struct {
		WorkspaceID, UserID, ConnectorID, ResourceID string
		ExpiresAt                                    time.Time
		HoursAhead                                   int
	}{workspaceID, userID, connectorID, resourceID, expiresAt, hoursAhead})
	return s.warnErr
}

// stubAuditProducer captures every PublishAccessAuditLogs call.
type stubAuditProducer struct {
	mu      sync.Mutex
	calls   atomic.Int64
	entries [][]*access.AuditLogEntry
	errs    []error
}

func (s *stubAuditProducer) PublishAccessAuditLogs(_ context.Context, _ string, entries []*access.AuditLogEntry) error {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entries)
	return nil
}

func (s *stubAuditProducer) Close() error { return nil }

// TestGrantExpiryEnforcer_NotifiesOnRevoke asserts that after a
// successful revoke the enforcer fires SendGrantRevokedNotification
// with the correct workspace/user/resource arguments.
func TestGrantExpiryEnforcer_NotifiesOnRevoke(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	seedGrant(t, db, "01HGRANT0NOTIFY000000000A", &pastT)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{}, map[string]interface{}{"api_key": "k"}, nil)
	notifier := &stubGrantExpiryNotifier{}
	audit := &stubAuditProducer{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetNotifier(notifier)
	e.SetAuditProducer(audit)

	if _, err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if len(notifier.revokeCalls) != 1 {
		t.Fatalf("revoke notify calls = %d; want 1", len(notifier.revokeCalls))
	}
	got := notifier.revokeCalls[0]
	if got.WorkspaceID != "01HWORKSPACE0000000000000A" {
		t.Errorf("workspace_id = %q", got.WorkspaceID)
	}
	if got.UserID != "01HUSER00000000000000000A" {
		t.Errorf("user_id = %q", got.UserID)
	}
	if got.ResourceID != "projects/foo" {
		t.Errorf("resource_id = %q; want projects/foo", got.ResourceID)
	}
	if !got.ExpiresAt.Equal(pastT) {
		t.Errorf("expires_at = %v; want %v", got.ExpiresAt, pastT)
	}
	if audit.calls.Load() != 1 {
		t.Errorf("audit calls = %d; want 1", audit.calls.Load())
	}
}

// TestGrantExpiryEnforcer_AuditEventOnRevoke asserts that on
// revoke success the enforcer emits an access.grant.expiry audit
// event with action=auto_revoked and status=success.
func TestGrantExpiryEnforcer_AuditEventOnRevoke(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	seedGrant(t, db, "01HGRANT0AUDIT0000000000A", &pastT)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{}, map[string]interface{}{"api_key": "k"}, nil)
	audit := &stubAuditProducer{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetAuditProducer(audit)
	if _, err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) != 1 || len(audit.entries[0]) != 1 {
		t.Fatalf("audit batches = %d (entries[0] len = %d); want 1/1", len(audit.entries), func() int {
			if len(audit.entries) == 0 {
				return 0
			}
			return len(audit.entries[0])
		}())
	}
	entry := audit.entries[0][0]
	if entry.EventType != "access.grant.expiry" {
		t.Errorf("event_type = %q; want access.grant.expiry", entry.EventType)
	}
	if entry.Action != string(access.GrantExpiryActionRevoked) {
		t.Errorf("action = %q; want auto_revoked", entry.Action)
	}
	if entry.Outcome != "success" {
		t.Errorf("outcome = %q; want success", entry.Outcome)
	}
	// Serialise the raw data to JSON so we cover the encoder.
	if _, err := json.Marshal(entry); err != nil {
		t.Errorf("serialise audit entry: %v", err)
	}
}

// TestGrantExpiryEnforcer_RunWarning_FiresWithinWindow asserts the
// look-ahead sweep finds grants expiring within warningHours and
// fires SendGrantExpiryWarning with the correct hoursAhead arg.
func TestGrantExpiryEnforcer_RunWarning_FiresWithinWindow(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	inThreeHours := now.Add(3 * time.Hour)
	inFourtyEightHours := now.Add(48 * time.Hour)
	seedGrant(t, db, "01HGRANT0WARN0000000000A0", &inThreeHours)
	seedGrant(t, db, "01HGRANT0OUTSIDE0000000A1", &inFourtyEightHours)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	notifier := &stubGrantExpiryNotifier{}
	audit := &stubAuditProducer{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetWarningHours(24)
	e.SetNotifier(notifier)
	e.SetAuditProducer(audit)

	warned, err := e.RunWarning(context.Background())
	if err != nil {
		t.Fatalf("RunWarning: %v", err)
	}
	if warned != 1 {
		t.Errorf("warned = %d; want 1 (only the 3h-out grant)", warned)
	}
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if len(notifier.warnCalls) != 1 {
		t.Fatalf("warn notify calls = %d; want 1", len(notifier.warnCalls))
	}
	if got := notifier.warnCalls[0].HoursAhead; got != 3 {
		t.Errorf("hoursAhead = %d; want 3", got)
	}
	if audit.calls.Load() != 1 {
		t.Errorf("audit calls = %d; want 1 warn entry", audit.calls.Load())
	}
}

// TestGrantExpiryEnforcer_RunWarning_NotifierErrorIsLogged asserts
// a notifier failure is captured as lastErr but does not abort
// remaining grants in the sweep.
func TestGrantExpiryEnforcer_RunWarning_NotifierErrorIsLogged(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	soon := now.Add(2 * time.Hour)
	seedGrant(t, db, "01HGRANT0WARNERR00000000A", &soon)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	notifier := &stubGrantExpiryNotifier{warnErr: errFake}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetWarningHours(24)
	e.SetNotifier(notifier)

	warned, err := e.RunWarning(context.Background())
	if err == nil {
		t.Error("err = nil; want notifier error surfaced")
	}
	if warned != 0 {
		t.Errorf("warned = %d; want 0 on notifier failure", warned)
	}
}

// TestGrantExpiryEnforcer_RunWarning_AuditsEvenWhenNotifierFails
// is the Phase 11 batch 6 regression for the inconsistency where
// a notifier failure used to short-circuit the audit-event
// emission. SIEM ingestion must observe every warning attempt,
// including failed ones, so dashboards can pivot on warned-then-
// failed grants.
func TestGrantExpiryEnforcer_RunWarning_AuditsEvenWhenNotifierFails(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	soon := now.Add(2 * time.Hour)
	seedGrant(t, db, "01HGRANT0WARNAUDIT000000A", &soon)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	notifier := &stubGrantExpiryNotifier{warnErr: errFake}
	audit := &stubAuditProducer{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetWarningHours(24)
	e.SetNotifier(notifier)
	e.SetAuditProducer(audit)

	warned, err := e.RunWarning(context.Background())
	if err == nil {
		t.Error("err = nil; want notifier error surfaced")
	}
	if warned != 0 {
		t.Errorf("warned = %d; want 0 on notifier failure", warned)
	}

	if audit.calls.Load() != 1 {
		t.Fatalf("audit calls = %d; want 1 (the failed-notify audit event)", audit.calls.Load())
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) != 1 || len(audit.entries[0]) != 1 {
		t.Fatalf("audit batches = %d (entries[0] len = %d); want 1/1", len(audit.entries), func() int {
			if len(audit.entries) == 0 {
				return 0
			}
			return len(audit.entries[0])
		}())
	}
	entry := audit.entries[0][0]
	if entry.EventType != "access.grant.expiry" {
		t.Errorf("event_type = %q; want access.grant.expiry", entry.EventType)
	}
	if entry.Action != string(access.GrantExpiryActionWarned) {
		t.Errorf("action = %q; want warned", entry.Action)
	}
	if entry.Outcome != "failed" {
		t.Errorf("outcome = %q; want failed (notifier returned an error)", entry.Outcome)
	}
}

// TestGrantExpiryEnforcer_RunWarning_NilNotifierIsSkipped is the
// Phase 11 batch 6 round-3 regression for the asymmetry where a
// nil notifier silently inflated the warned counter and emitted
// Status="success" audit events even though no notification had
// actually been attempted. When the notifier hook is unwired,
// the audit event MUST carry Outcome="skipped" (matching the
// LeaverKillSwitchEvent convention) and the warned counter MUST
// stay at zero so dashboards do not over-report warning coverage.
func TestGrantExpiryEnforcer_RunWarning_NilNotifierIsSkipped(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	soon := now.Add(2 * time.Hour)
	seedGrant(t, db, "01HGRANT0WARNNIL00000000A", &soon)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	audit := &stubAuditProducer{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetWarningHours(24)
	// Intentionally NO SetNotifier — the notifier hook is nil.
	e.SetAuditProducer(audit)

	warned, err := e.RunWarning(context.Background())
	if err != nil {
		t.Fatalf("RunWarning: %v (want nil because the warning attempt was skipped, not failed)", err)
	}
	if warned != 0 {
		t.Errorf("warned = %d; want 0 (no notifier wired ⇒ no actual notification was attempted)", warned)
	}

	if audit.calls.Load() != 1 {
		t.Fatalf("audit calls = %d; want 1 (the skipped-notify audit event)", audit.calls.Load())
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) != 1 || len(audit.entries[0]) != 1 {
		t.Fatalf("audit batches = %d (entries[0] len = %d); want 1/1", len(audit.entries), func() int {
			if len(audit.entries) == 0 {
				return 0
			}
			return len(audit.entries[0])
		}())
	}
	entry := audit.entries[0][0]
	if entry.EventType != "access.grant.expiry" {
		t.Errorf("event_type = %q; want access.grant.expiry", entry.EventType)
	}
	if entry.Action != string(access.GrantExpiryActionWarned) {
		t.Errorf("action = %q; want warned", entry.Action)
	}
	if entry.Outcome != "skipped" {
		t.Errorf("outcome = %q; want skipped (notifier hook is nil so no notification was attempted)", entry.Outcome)
	}
}

// TestGrantExpiryEnforcer_RunWarning_DedupPerGrant is the Phase 11
// batch 6 round-7 regression for the bug where RunWarning had no
// dedup mechanism — under the default (1h tick × 24h warning window)
// configuration, a single grant 12 hours from expiry would receive
// up to 12 duplicate "your access expires in N hours" notifications
// across consecutive ticks before being auto-revoked. The fix
// stamps models.AccessGrant.LastWarnedAt after a successful
// notification, and the next tick's query+iteration skips any
// grant whose LastWarnedAt is within the warning window. This test
// asserts the warned counter increments exactly once across two
// consecutive ticks for the same grant, and that the stamp lands
// on the row.
func TestGrantExpiryEnforcer_RunWarning_DedupPerGrant(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	soon := now.Add(2 * time.Hour)
	seedGrant(t, db, "01HGRANT0DEDUP0000000000A", &soon)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	notifier := &stubGrantExpiryNotifier{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	// Pin the enforcer clock so the second tick still falls
	// inside the warning window (a real 1h-later tick would
	// also remain inside the default 24h window, but pinning
	// makes the assertion deterministic).
	e.SetClock(func() time.Time { return now })
	e.SetWarningHours(24)
	e.SetNotifier(notifier)

	warnedFirst, err := e.RunWarning(context.Background())
	if err != nil {
		t.Fatalf("RunWarning (first tick): %v", err)
	}
	if warnedFirst != 1 {
		t.Errorf("first tick warned = %d; want 1 (initial notification)", warnedFirst)
	}

	// Verify the stamp landed on the row so the dedup pivot
	// can take effect on the next tick.
	var row models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0DEDUP0000000000A").First(&row).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.LastWarnedAt == nil {
		t.Fatal("LastWarnedAt = nil after a successful notification; want non-nil so the next tick dedups")
	}

	// Advance the enforcer clock by 1 hour so the second tick
	// looks like a real subsequent run. The grant's expiry is
	// still 1h ahead at this point, well inside the 24h warning
	// window, so without dedup it would fire again.
	e.SetClock(func() time.Time { return now.Add(1 * time.Hour) })

	warnedSecond, err := e.RunWarning(context.Background())
	if err != nil {
		t.Fatalf("RunWarning (second tick): %v", err)
	}
	if warnedSecond != 0 {
		t.Errorf("second tick warned = %d; want 0 (dedup must suppress the duplicate notification)", warnedSecond)
	}

	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if len(notifier.warnCalls) != 1 {
		t.Errorf("warning notify calls = %d; want 1 (dedup must collapse the two ticks into a single notification)", len(notifier.warnCalls))
	}
}

// TestGrantExpiryEnforcer_RunWarning_DedupPushedIntoSQL is the
// Phase 11 batch 6 round-8 regression for the bug where the
// LastWarnedAt dedup pivot only filtered already-warned grants
// after LIMIT had already chopped the result set, so a workspace
// with a hot tail of already-warned grants would consume the
// batch budget on rows that get continue'd and unwarned grants
// beyond position batchSize would never receive a notification.
// The fix pushes the (last_warned_at IS NULL OR last_warned_at <
// now - window) predicate into the WHERE clause so LIMIT only
// counts unwarned rows.
//
// The test seeds batchSize=3, then inserts 3 already-warned grants
// AND 1 fresh unwarned grant in the warning window. Without the
// SQL pushdown, LIMIT 3 returns the 3 already-warned rows, the
// loop skips them all, and the fresh grant is silently dropped.
// With the pushdown, LIMIT 3 returns the fresh grant first and
// warned==1.
func TestGrantExpiryEnforcer_RunWarning_DedupPushedIntoSQL(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	soon := now.Add(2 * time.Hour)
	// Three rows that have already been warned within the
	// 24h dedup window. last_warned_at is set to "30 minutes
	// ago" so the predicate (last_warned_at < now - 24h)
	// excludes them.
	recentlyWarned := now.Add(-30 * time.Minute)
	for _, id := range []string{
		"01HGRANT0WARNED0000000001A",
		"01HGRANT0WARNED0000000002A",
		"01HGRANT0WARNED0000000003A",
	} {
		seedGrant(t, db, id, &soon)
		if err := db.Model(&models.AccessGrant{}).
			Where("id = ?", id).
			Update("last_warned_at", recentlyWarned).Error; err != nil {
			t.Fatalf("stamp last_warned_at for %s: %v", id, err)
		}
	}
	// One fresh grant in the same workspace + window that has
	// never been warned. This is the row the fix must surface
	// inside the LIMIT=3 batch.
	seedGrant(t, db, "01HGRANT0FRESH00000000004A", &soon)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	notifier := &stubGrantExpiryNotifier{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 3)
	e.SetClock(func() time.Time { return now })
	e.SetWarningHours(24)
	e.SetNotifier(notifier)

	warned, err := e.RunWarning(context.Background())
	if err != nil {
		t.Fatalf("RunWarning: %v", err)
	}
	if warned != 1 {
		t.Errorf("warned = %d; want 1 (the SQL WHERE clause must filter the 3 already-warned rows so LIMIT 3 returns the fresh grant)", warned)
	}

	notifier.mu.Lock()
	callCount := len(notifier.warnCalls)
	notifier.mu.Unlock()
	if callCount != 1 {
		t.Errorf("warning notify calls = %d; want 1 (only the fresh grant must be notified)", callCount)
	}

	// Verify the fresh row picked up a stamp and the three
	// already-warned rows kept their pre-existing stamp
	// (i.e. the loop never touched them).
	var fresh models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0FRESH00000000004A").First(&fresh).Error; err != nil {
		t.Fatalf("load fresh grant: %v", err)
	}
	if fresh.LastWarnedAt == nil {
		t.Error("fresh grant LastWarnedAt = nil; want non-nil (the SQL pushdown surfaced this row and the loop stamped it)")
	}
	var olderStampedCount int64
	if err := db.Model(&models.AccessGrant{}).
		Where("id IN ?", []string{
			"01HGRANT0WARNED0000000001A",
			"01HGRANT0WARNED0000000002A",
			"01HGRANT0WARNED0000000003A",
		}).
		Where("last_warned_at = ?", recentlyWarned).
		Count(&olderStampedCount).Error; err != nil {
		t.Fatalf("count older stamped: %v", err)
	}
	if olderStampedCount != 3 {
		t.Errorf("count of already-warned rows still carrying the original stamp = %d; want 3 (the SQL filter must have excluded them so the loop never restamped them)", olderStampedCount)
	}
}

// errFake is a sentinel for the notifier failure test above.
var errFake = errFakeT("notifier broke")

type errFakeT string

func (e errFakeT) Error() string { return string(e) }

// alreadyRevokedRevoker simulates the race-condition path where
// another process (operator action, SCIM deprovision, a competing
// enforcer tick) revoked the grant between our query and our
// Revoke call. The standard captureRevoker only returns
// ErrAlreadyRevoked when grant.RevokedAt is non-nil, but the
// enforcer query filters revoked_at IS NULL so we'd never even
// fetch such a row. This stub always returns ErrAlreadyRevoked so
// the test can exercise the idempotent-success branch directly.
type alreadyRevokedRevoker struct {
	calls int
}

func (r *alreadyRevokedRevoker) Revoke(_ context.Context, _ *models.AccessGrant, _, _ map[string]interface{}) error {
	r.calls++
	return access.ErrAlreadyRevoked
}

// TestGrantExpiryEnforcer_AlreadyRevokedIsSkipped is the Phase 11
// batch 6 round-6 regression for the bug where ErrAlreadyRevoked
// emitted Status="success" audit events identical to a fresh
// auto-revoke AND fired a duplicate SendGrantRevokedNotification
// to the user. The fix gives the race-condition path a distinct
// Status="skipped" so SIEM consumers can pivot on Status to
// separate "we revoked it" from "it was already revoked when we
// got here", and so emitRevokedSideEffects' notifier guard
// (status == "success") naturally suppresses the duplicate
// notification. The revoked counter must also stay at zero —
// the enforcer's tick did not in fact revoke this grant.
func TestGrantExpiryEnforcer_AlreadyRevokedIsSkipped(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	seedGrant(t, db, "01HGRANT0ALREADY00000000A", &pastT)

	rev := &alreadyRevokedRevoker{}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{}, map[string]interface{}{"api_key": "k"}, nil)
	notifier := &stubGrantExpiryNotifier{}
	audit := &stubAuditProducer{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })
	e.SetNotifier(notifier)
	e.SetAuditProducer(audit)

	revoked, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v (want nil because ErrAlreadyRevoked is idempotent)", err)
	}
	if revoked != 0 {
		t.Errorf("revoked = %d; want 0 (the enforcer tick did not revoke; another process did)", revoked)
	}
	if rev.calls != 1 {
		t.Errorf("revoker calls = %d; want 1", rev.calls)
	}

	// The user-facing notification MUST be suppressed — the user
	// has either already been notified by whichever process beat
	// us to the revoke, or the revoke happened out-of-band and a
	// duplicate "your access was revoked" message would be
	// misleading.
	notifier.mu.Lock()
	if len(notifier.revokeCalls) != 0 {
		t.Errorf("revoke notify calls = %d; want 0 (ErrAlreadyRevoked must NOT fire SendGrantRevokedNotification)", len(notifier.revokeCalls))
	}
	notifier.mu.Unlock()

	// The audit event MUST still fire so SIEM observes the
	// idempotent skip, with Outcome="skipped" so dashboards
	// can distinguish it from a fresh auto-revoke.
	if audit.calls.Load() != 1 {
		t.Fatalf("audit calls = %d; want 1 (the skipped-revoke audit event)", audit.calls.Load())
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) != 1 || len(audit.entries[0]) != 1 {
		t.Fatalf("audit batches = %d (entries[0] len = %d); want 1/1", len(audit.entries), func() int {
			if len(audit.entries) == 0 {
				return 0
			}
			return len(audit.entries[0])
		}())
	}
	entry := audit.entries[0][0]
	if entry.EventType != "access.grant.expiry" {
		t.Errorf("event_type = %q; want access.grant.expiry", entry.EventType)
	}
	if entry.Action != string(access.GrantExpiryActionRevoked) {
		t.Errorf("action = %q; want auto_revoked", entry.Action)
	}
	if entry.Outcome != "skipped" {
		t.Errorf("outcome = %q; want skipped (the grant was already revoked when the enforcer got there)", entry.Outcome)
	}
	// Serialise the entry to JSON to cover the encoder and
	// confirm the Status field surfaces in the wire payload.
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("serialise audit entry: %v", err)
	}
	if want := `"outcome":"skipped"`; !contains(string(raw), want) {
		t.Errorf("serialised entry missing %q; got %s", want, raw)
	}
}

// contains is a tiny helper to avoid pulling strings.Contains
// into a test file that otherwise has no strings dependency.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestGrantExpiryEnforcer_NoAuditProducerIsNoOp asserts the
// enforcer never panics when audit producer / notifier are nil.
func TestGrantExpiryEnforcer_NoAuditProducerIsNoOp(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	seedGrant(t, db, "01HGRANT0NOAUDIT00000000A", &pastT)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{}, map[string]interface{}{"api_key": "k"}, nil)
	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })

	if _, err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0NOAUDIT00000000A").First(&got).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("revoked_at not set")
	}
}

// TestGrantExpiryEnforcer_RunWarning_ThenRunRevokes is the Phase 11
// batch 6 interaction test for T12: a grant that is first surfaced
// by RunWarning (so its LastWarnedAt column gets stamped) must
// still be picked up by Run once its ExpiresAt has elapsed, even
// though the dedup pivot would suppress a second warning. This
// guarantees the dedup column is scoped to RunWarning only and
// cannot accidentally veto a real revoke.
func TestGrantExpiryEnforcer_RunWarning_ThenRunRevokes(t *testing.T) {
	db := newGrantDB(t)
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := t0.Add(2 * time.Hour)
	seedGrant(t, db, "01HGRANT0WARNREVOKE000000A", &expiresAt)

	rev := &captureRevoker{now: func() time.Time { return t0 }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{}, map[string]interface{}{"api_key": "k"}, nil)
	notifier := &stubGrantExpiryNotifier{}

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return t0 })
	e.SetWarningHours(24)
	e.SetNotifier(notifier)

	// Tick 1: RunWarning fires the heads-up notification and
	// stamps LastWarnedAt on the grant row.
	warned, err := e.RunWarning(context.Background())
	if err != nil {
		t.Fatalf("RunWarning (warn tick): %v", err)
	}
	if warned != 1 {
		t.Fatalf("warn tick warned = %d; want 1", warned)
	}
	var rowAfterWarn models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0WARNREVOKE000000A").First(&rowAfterWarn).Error; err != nil {
		t.Fatalf("load after warn: %v", err)
	}
	if rowAfterWarn.LastWarnedAt == nil {
		t.Fatal("LastWarnedAt = nil after warn; want stamped so dedup engages")
	}
	if rowAfterWarn.RevokedAt != nil {
		t.Fatal("RevokedAt = non-nil after warn; warning sweep must not revoke")
	}

	// Advance the clock past ExpiresAt and Run() the eviction
	// sweep. The grant has already been warned (LastWarnedAt is
	// set), so this is the exact interaction T12 cares about:
	// the dedup column scoped to RunWarning must not stop Run from
	// revoking a now-expired grant.
	e.SetClock(func() time.Time { return t0.Add(3 * time.Hour) })
	rev.now = func() time.Time { return t0.Add(3 * time.Hour) }

	revoked, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run (eviction tick): %v", err)
	}
	if revoked != 1 {
		t.Fatalf("eviction tick revoked = %d; want 1", revoked)
	}
	if len(rev.calls) != 1 || rev.calls[0] != "01HGRANT0WARNREVOKE000000A" {
		t.Errorf("captureRevoker.calls = %v; want [warned grant]", rev.calls)
	}
	var rowAfterRun models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0WARNREVOKE000000A").First(&rowAfterRun).Error; err != nil {
		t.Fatalf("load after run: %v", err)
	}
	if rowAfterRun.RevokedAt == nil {
		t.Fatal("RevokedAt = nil after Run; warned grant must still get revoked when it expires")
	}
}
