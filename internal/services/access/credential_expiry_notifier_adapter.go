package access

import (
	"context"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/notification"
)

// CredentialExpiryNotifierAdapter wraps *notification.NotificationService
// so the cron.CredentialChecker can dispatch credential-expiry
// alerts through the standard notification fan-out without the
// cron package importing the notification package directly.
//
// The adapter is the production implementation of
// cron.NotificationSender. Tests inject a stub that captures every
// call instead.
//
// A nil adapter / nil Inner is a no-op success — keeps the worker
// binary's wiring trivial in dev binaries that don't have any
// channel configured.
type CredentialExpiryNotifierAdapter struct {
	Inner *notification.NotificationService
}

// NewCredentialExpiryNotifierAdapter wraps the supplied
// *notification.NotificationService. Identical to manually setting
// the Inner field; the constructor exists so cmd/* binaries can
// inline the wire-up without the field-init syntax.
func NewCredentialExpiryNotifierAdapter(inner *notification.NotificationService) *CredentialExpiryNotifierAdapter {
	return &CredentialExpiryNotifierAdapter{Inner: inner}
}

// SendCredentialExpiryWarning satisfies cron.NotificationSender.
// Errors from the underlying notification dispatch are surfaced to
// the caller (the cron loop logs them and continues with the next
// connector — best-effort semantics).
func (a *CredentialExpiryNotifierAdapter) SendCredentialExpiryWarning(
	ctx context.Context,
	connectorID, workspaceID, provider string,
	expiresAt time.Time,
) error {
	if a == nil || a.Inner == nil {
		return nil
	}
	_, err := a.Inner.NotifyCredentialExpiry(ctx, connectorID, workspaceID, provider, expiresAt)
	return err
}
