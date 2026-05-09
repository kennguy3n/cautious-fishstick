package cron

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// NotificationSender is the narrow contract CredentialChecker uses
// to emit best-effort notifications. The production implementation
// is an adapter over *notification.NotificationService; tests
// substitute a stub that captures every call.
type NotificationSender interface {
	SendCredentialExpiryWarning(ctx context.Context, connectorID, provider string, expiresAt time.Time) error
}

// NotificationSenderFunc is the function adapter for
// NotificationSender, identical in spirit to the access package's
// OpenZitiClientFunc.
type NotificationSenderFunc func(ctx context.Context, connectorID, provider string, expiresAt time.Time) error

// SendCredentialExpiryWarning satisfies NotificationSender.
func (f NotificationSenderFunc) SendCredentialExpiryWarning(ctx context.Context, connectorID, provider string, expiresAt time.Time) error {
	return f(ctx, connectorID, provider, expiresAt)
}

// CredentialChecker is the Phase 6 background worker that scans
// access_connectors for soon-to-expire credentials and emits a
// notification via NotificationSender. The scanner runs on the
// same external ticker pattern as CampaignScheduler /
// AnomalyScanner: Run is called by the access-connector-worker
// binary at the configured interval.
//
// The checker reads credential_expired_time from the
// access_connectors table (set during Connect or by the optional
// GetCredentialsMetadata probe). Connectors whose credentials
// expire within warningDays are flagged via a notification; those
// already expired are also included so the admin dashboard can
// surface both "about to expire" and "already expired" rows.
//
// Best-effort: a notification failure on one connector does NOT
// abort the loop. The last error is surfaced via the returned err
// for callers that want aggregate diagnostics.
type CredentialChecker struct {
	db          *gorm.DB
	notifier    NotificationSender
	warningDays int
	now         func() time.Time
}

// NewCredentialChecker returns a checker bound to db that fires
// warnings via notifier when credentials expire within
// warningDays. warningDays <= 0 defaults to 14 (mirrors
// DefaultCredentialExpiryWarningDays). notifier may be nil — in
// that case notifications are silently skipped (the scanner still
// runs and logs so admins see the console output).
func NewCredentialChecker(db *gorm.DB, notifier NotificationSender, warningDays int) *CredentialChecker {
	if warningDays <= 0 {
		warningDays = 14
	}
	return &CredentialChecker{
		db:          db,
		notifier:    notifier,
		warningDays: warningDays,
		now:         time.Now,
	}
}

// SetClock overrides time.Now. Tests use this to pin expiry
// comparisons to a deterministic timestamp.
func (c *CredentialChecker) SetClock(now func() time.Time) {
	if now != nil {
		c.now = now
	}
}

// Run scans access_connectors whose credential_expired_time is at
// or before now + warningDays, and emits a notification per flagged
// connector. Soft-deleted connectors are excluded (GORM default
// scope).
//
// Run is safe to call repeatedly — notifications are fire-and-
// forget. De-duplication (if needed) is the responsibility of the
// notification channel, not the scanner.
func (c *CredentialChecker) Run(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("cron: credential checker is not fully wired")
	}
	now := c.now()
	horizon := now.Add(time.Duration(c.warningDays) * 24 * time.Hour)

	var flagged []models.AccessConnector
	if err := c.db.WithContext(ctx).
		Where("credential_expired_time IS NOT NULL").
		Where("credential_expired_time <= ?", horizon).
		Find(&flagged).Error; err != nil {
		return fmt.Errorf("cron: credential_checker: query: %w", err)
	}
	if len(flagged) == 0 {
		log.Printf("cron: credential_checker: no connectors expiring within %d days", c.warningDays)
		return nil
	}

	var lastErr error
	for i := range flagged {
		conn := &flagged[i]
		expiresAt := *conn.CredentialExpiredTime
		remaining := expiresAt.Sub(now).Truncate(time.Hour)
		log.Printf("cron: credential_checker: connector_id=%s provider=%s expires=%v (in %s)",
			conn.ID, conn.Provider, expiresAt, remaining)

		if c.notifier == nil {
			continue
		}
		if err := c.notifier.SendCredentialExpiryWarning(ctx, conn.ID, conn.Provider, expiresAt); err != nil {
			log.Printf("cron: credential_checker: notify failed for connector_id=%s: %v", conn.ID, err)
			lastErr = err
		}
	}
	return lastErr
}
