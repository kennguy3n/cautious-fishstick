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

// errFake is a sentinel for the notifier failure test above.
var errFake = errFakeT("notifier broke")

type errFakeT string

func (e errFakeT) Error() string { return string(e) }

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
