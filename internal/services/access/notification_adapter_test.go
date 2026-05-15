package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/notification"
)

// TestNotificationAdapter_NilAdapter_NoOp verifies that calling
// NotifyReviewersPending on a (*NotificationAdapter)(nil) is a
// no-op success. The AccessReviewService relies on this so its
// wiring stays uniform whether or not notifications are enabled.
func TestNotificationAdapter_NilAdapter_NoOp(t *testing.T) {
	var a *NotificationAdapter
	if err := a.NotifyReviewersPending(context.Background(), "rev-1", nil); err != nil {
		t.Errorf("nil adapter NotifyReviewersPending = %v; want nil", err)
	}
	if err := a.NotifyRequester(context.Background(), "req-1", "user-1", "hi"); err != nil {
		t.Errorf("nil adapter NotifyRequester = %v; want nil", err)
	}
}

// TestNotificationAdapter_NilInner_NoOp verifies that an adapter
// with a nil Inner field returns nil for both methods so dev /
// test binaries that wire the adapter unconditionally still boot
// cleanly without a notification.NotificationService.
func TestNotificationAdapter_NilInner_NoOp(t *testing.T) {
	a := &NotificationAdapter{Inner: nil}
	if err := a.NotifyReviewersPending(context.Background(), "rev-1", []ReviewerPendingDecisionRef{{
		ReviewerUserID: "rev-user",
		GrantID:        "g-1",
		GrantSummary:   "summary",
		DueAt:          time.Now(),
	}}); err != nil {
		t.Errorf("nil-Inner NotifyReviewersPending = %v; want nil", err)
	}
	if err := a.NotifyRequester(context.Background(), "req-1", "user-1", "hi"); err != nil {
		t.Errorf("nil-Inner NotifyRequester = %v; want nil", err)
	}
}

// TestNotificationAdapter_NotifyReviewersPending_ForwardsToInner
// asserts the adapter translates the access-package ref shape into
// the notification-package shape and the inner NotificationService
// receives one Send per (reviewer × channel) pair.
func TestNotificationAdapter_NotifyReviewersPending_ForwardsToInner(t *testing.T) {
	mem := &notification.InMemoryNotifier{}
	svc := notification.NewNotificationService(mem)
	a := NewNotificationServiceAdapter(svc)

	due := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	refs := []ReviewerPendingDecisionRef{
		{ReviewerUserID: "alice", GrantID: "g-1", GrantSummary: "Salesforce admin", DueAt: due},
		{ReviewerUserID: "bob", GrantID: "g-2", GrantSummary: "GitHub repo", DueAt: due},
	}
	if err := a.NotifyReviewersPending(context.Background(), "rev-1", refs); err != nil {
		t.Fatalf("NotifyReviewersPending: %v", err)
	}
	got := mem.Captured()
	if len(got) < 2 {
		t.Fatalf("captured = %d notifications; want at least 2 (one per reviewer)", len(got))
	}
}

// TestNotificationAdapter_NotifyReviewersPending_BestEffortFanOut
// verifies a failing inner Notifier does NOT surface a non-nil
// error from the adapter. NotificationService logs per-channel
// failures into its result but treats fan-out as best-effort, so
// the adapter contract is "forward inner.Err" rather than "forward
// per-channel failures" — the only channel here fails yet the
// adapter still returns nil.
func TestNotificationAdapter_NotifyReviewersPending_BestEffortFanOut(t *testing.T) {
	failing := &notification.InMemoryNotifier{
		Fail: func(_ notification.Notification) error { return errors.New("inmem boom") },
	}
	svc := notification.NewNotificationService(failing)
	a := NewNotificationServiceAdapter(svc)

	// NotificationService.NotifyReviewersPending logs per-channel
	// failures into the result but does NOT return a non-nil error
	// for them (best-effort fan-out). The adapter therefore
	// returns nil even when the only channel fails — exercising
	// the success path on the adapter side keeps the wiring
	// trivial for AccessReviewService.
	if err := a.NotifyReviewersPending(context.Background(), "rev-1", []ReviewerPendingDecisionRef{
		{ReviewerUserID: "alice", GrantID: "g-1", GrantSummary: "Salesforce admin", DueAt: time.Now()},
	}); err != nil {
		t.Errorf("NotifyReviewersPending = %v; want nil (best-effort fan-out)", err)
	}
}

// TestNotificationAdapter_NotifyRequester_ForwardsToInner verifies
// the requester-status path lands on the inner notifier.
func TestNotificationAdapter_NotifyRequester_ForwardsToInner(t *testing.T) {
	mem := &notification.InMemoryNotifier{}
	svc := notification.NewNotificationService(mem)
	a := NewNotificationServiceAdapter(svc)
	if err := a.NotifyRequester(context.Background(), "req-1", "user-1", "your request is pending manager approval"); err != nil {
		t.Fatalf("NotifyRequester: %v", err)
	}
	got := mem.Captured()
	if len(got) == 0 {
		t.Fatal("captured = 0 notifications; want >=1 from NotifyRequester")
	}
}

// TestNewNotificationServiceAdapter_PreservesInner verifies the
// constructor surfaces the supplied service via Inner without
// reordering or wrapping.
func TestNewNotificationServiceAdapter_PreservesInner(t *testing.T) {
	svc := notification.NewNotificationService()
	a := NewNotificationServiceAdapter(svc)
	if a == nil || a.Inner != svc {
		t.Fatalf("NewNotificationServiceAdapter: Inner not preserved (got %+v)", a)
	}
}
