package cron

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// notifCapture captures every SendCredentialExpiryWarning call the
// test stub receives: connector ID, provider, and expiry time.
type notifCapture struct {
	ConnectorID string
	Provider    string
	ExpiresAt   time.Time
}

type stubNotificationSender struct {
	mu      sync.Mutex
	calls   []notifCapture
	err     error
}

func (s *stubNotificationSender) SendCredentialExpiryWarning(_ context.Context, connectorID, provider string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, notifCapture{
		ConnectorID: connectorID,
		Provider:    provider,
		ExpiresAt:   expiresAt,
	})
	return s.err
}

func newCredDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func ptrTime(t time.Time) *time.Time { return &t }

func seedCredConnector(t *testing.T, db *gorm.DB, id, provider string, expiresAt *time.Time) {
	t.Helper()
	row := &models.AccessConnector{
		ID:                    id,
		WorkspaceID:           "01HWORKSPACE0000000000000A",
		Provider:              provider,
		ConnectorType:         "test",
		CredentialExpiredTime: expiresAt,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
}

// TestCredentialChecker_Run_NotifiesExpiringConnectors asserts that
// Run scans for connectors whose credential_expired_time is within
// the warning horizon and emits a notification per flagged
// connector.
func TestCredentialChecker_Run_NotifiesExpiringConnectors(t *testing.T) {
	db := newCredDB(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	// Expiring in 5 days — within default 14-day horizon.
	seedCredConnector(t, db, "01HCONN_EXPIRING_A", "okta", ptrTime(now.Add(5*24*time.Hour)))
	// Expiring in 30 days — outside horizon.
	seedCredConnector(t, db, "01HCONN_SAFE_B", "github", ptrTime(now.Add(30*24*time.Hour)))
	// Already expired (in the past) — should also be flagged.
	seedCredConnector(t, db, "01HCONN_EXPIRED_C", "microsoft", ptrTime(now.Add(-2*24*time.Hour)))
	// No expiry set — should NOT be flagged.
	seedCredConnector(t, db, "01HCONN_NOEXPIRY_D", "duo", nil)

	sender := &stubNotificationSender{}
	c := NewCredentialChecker(db, sender, 14)
	c.SetClock(func() time.Time { return now })

	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("notifications = %d; want 2 (expiring + already expired)", len(sender.calls))
	}
	ids := map[string]bool{}
	for _, call := range sender.calls {
		ids[call.ConnectorID] = true
	}
	if !ids["01HCONN_EXPIRING_A"] {
		t.Error("missing notification for expiring connector")
	}
	if !ids["01HCONN_EXPIRED_C"] {
		t.Error("missing notification for already-expired connector")
	}
}

// TestCredentialChecker_Run_NoConnectorsIsNoop asserts that Run
// with no expiring connectors returns nil — no notifications, no
// error.
func TestCredentialChecker_Run_NoConnectorsIsNoop(t *testing.T) {
	db := newCredDB(t)
	sender := &stubNotificationSender{}
	c := NewCredentialChecker(db, sender, 14)
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Errorf("notifications = %d; want 0", len(sender.calls))
	}
}

// TestCredentialChecker_Run_NotifierErrorContinuesLoop asserts that
// a notification failure for one connector does NOT abort the loop;
// the next connector is still checked. The error is surfaced via
// Run's return value.
func TestCredentialChecker_Run_NotifierErrorContinuesLoop(t *testing.T) {
	db := newCredDB(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seedCredConnector(t, db, "01HCONN_ERR_1", "okta", ptrTime(now.Add(3*24*time.Hour)))
	seedCredConnector(t, db, "01HCONN_ERR_2", "github", ptrTime(now.Add(5*24*time.Hour)))

	sender := &stubNotificationSender{err: errors.New("smtp down")}
	c := NewCredentialChecker(db, sender, 14)
	c.SetClock(func() time.Time { return now })

	err := c.Run(context.Background())
	if err == nil {
		t.Fatal("Run returned nil; want last-seen error")
	}
	if len(sender.calls) != 2 {
		t.Errorf("notifications = %d; want 2 (loop must continue past error)", len(sender.calls))
	}
}

// TestCredentialChecker_Run_NilNotifierIsGraceful asserts that Run
// works with a nil notifier — it logs but doesn't crash. This is
// the dev-binary path where no email/Slack is wired.
func TestCredentialChecker_Run_NilNotifierIsGraceful(t *testing.T) {
	db := newCredDB(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seedCredConnector(t, db, "01HCONN_NILNOTIF", "okta", ptrTime(now.Add(3*24*time.Hour)))

	c := NewCredentialChecker(db, nil, 14)
	c.SetClock(func() time.Time { return now })
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestCredentialChecker_Run_MissingDependenciesError asserts the
// checker refuses to run with a nil db.
func TestCredentialChecker_Run_MissingDependenciesError(t *testing.T) {
	if err := (&CredentialChecker{}).Run(context.Background()); err == nil {
		t.Error("Run with nil db returned nil; want error")
	}
}

// TestCredentialChecker_Run_SoftDeletedConnectorsSkipped asserts
// that soft-deleted connectors are excluded from the scan.
func TestCredentialChecker_Run_SoftDeletedConnectorsSkipped(t *testing.T) {
	db := newCredDB(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seedCredConnector(t, db, "01HCONN_SOFT_DEL", "okta", ptrTime(now.Add(3*24*time.Hour)))

	if err := db.Delete(&models.AccessConnector{}, "id = ?", "01HCONN_SOFT_DEL").Error; err != nil {
		t.Fatalf("soft-delete: %v", err)
	}

	sender := &stubNotificationSender{}
	c := NewCredentialChecker(db, sender, 14)
	c.SetClock(func() time.Time { return now })
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Errorf("notifications = %d; want 0 (soft-deleted connector)", len(sender.calls))
	}
}
