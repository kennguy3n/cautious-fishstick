package access

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/notification"
)

func TestCredentialExpiryNotifierAdapter_DispatchesViaNotificationService(t *testing.T) {
	inMem := &notification.InMemoryNotifier{}
	svc := notification.NewNotificationService(inMem)
	adapter := NewCredentialExpiryNotifierAdapter(svc)

	expiresAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	err := adapter.SendCredentialExpiryWarning(
		context.Background(),
		"01HCONN_T25",
		"01HWS_T25",
		"okta",
		expiresAt,
	)
	if err != nil {
		t.Fatalf("SendCredentialExpiryWarning: %v", err)
	}
	captured := inMem.Captured()
	if len(captured) != 1 {
		t.Fatalf("notifier captures = %d; want 1", len(captured))
	}
	got := captured[0]
	if got.Kind != notification.KindCredentialExpiry {
		t.Errorf("kind = %q; want %q", got.Kind, notification.KindCredentialExpiry)
	}
	if got.RecipientUserID != "workspace:01HWS_T25" {
		t.Errorf("recipient = %q; want workspace:01HWS_T25", got.RecipientUserID)
	}
	if !strings.Contains(got.Body, "01HCONN_T25") {
		t.Errorf("body missing connector id: %q", got.Body)
	}
	if md, _ := got.Metadata["provider"].(string); md != "okta" {
		t.Errorf("metadata.provider = %v; want okta", got.Metadata["provider"])
	}
}

func TestCredentialExpiryNotifierAdapter_NilIsNoop(t *testing.T) {
	var a *CredentialExpiryNotifierAdapter
	if err := a.SendCredentialExpiryWarning(context.Background(), "c", "w", "p", time.Now()); err != nil {
		t.Fatalf("nil adapter: %v", err)
	}
	a = &CredentialExpiryNotifierAdapter{}
	if err := a.SendCredentialExpiryWarning(context.Background(), "c", "w", "p", time.Now()); err != nil {
		t.Fatalf("nil-inner adapter: %v", err)
	}
}

func TestCredentialExpiryNotifierAdapter_RequiresWorkspaceID(t *testing.T) {
	svc := notification.NewNotificationService(&notification.InMemoryNotifier{})
	adapter := NewCredentialExpiryNotifierAdapter(svc)

	err := adapter.SendCredentialExpiryWarning(context.Background(), "c1", "", "okta", time.Now())
	if err == nil {
		t.Fatal("expected error when workspace_id is empty")
	}
}

// failingNotifier always returns the same error so we can assert
// that adapter callers see the channel-level failure surfaced
// through the NotificationService.
type failingNotifier struct{}

func (failingNotifier) Send(_ context.Context, _ notification.Notification) error {
	return errors.New("channel offline")
}
func (failingNotifier) Name() string { return "failing-test" }

func TestCredentialExpiryNotifierAdapter_FailedDispatchReturnsNil(t *testing.T) {
	// The NotificationService swallows per-channel errors (it logs
	// them and surfaces them via NotifyResult.Failed). The adapter
	// therefore returns nil even when every channel failed — the
	// cron loop relies on this to keep iterating through the rest
	// of the flagged connectors. The PerChannel stats give callers
	// visibility into the failures via the NotifyResult; the
	// adapter doesn't propagate that to keep its contract narrow.
	svc := notification.NewNotificationService(failingNotifier{})
	adapter := NewCredentialExpiryNotifierAdapter(svc)

	err := adapter.SendCredentialExpiryWarning(
		context.Background(),
		"c1",
		"w1",
		"okta",
		time.Now().Add(2*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("expected nil to match notification service best-effort contract, got %v", err)
	}
}
