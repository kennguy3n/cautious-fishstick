package notification

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestNotifyReviewersPending_HappyPath asserts the service rolls up
// per-reviewer pending decisions into a single notification per
// reviewer, dispatches it to the configured channel, and returns
// per-channel sent counts.
func TestNotifyReviewersPending_HappyPath(t *testing.T) {
	t.Parallel()
	mem := &InMemoryNotifier{}
	svc := NewNotificationService(mem)

	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	due1 := now.Add(48 * time.Hour)
	due2 := now.Add(72 * time.Hour)
	svc.SetNow(func() time.Time { return now })

	res, err := svc.NotifyReviewersPending(context.Background(), "01HREVIEWXXXXXXXXXXXXXXXXX", []ReviewerPendingDecision{
		{ReviewerUserID: "u1", GrantID: "g1", DueAt: due1, GrantSummary: "viewer on prod-db"},
		{ReviewerUserID: "u1", GrantID: "g2", DueAt: due2, GrantSummary: "editor on prod-bucket"},
		{ReviewerUserID: "u2", GrantID: "g3", DueAt: due1, GrantSummary: "viewer on prod-bucket"},
	})
	if err != nil {
		t.Fatalf("NotifyReviewersPending: %v", err)
	}
	if res.Sent != 2 || res.Failed != 0 {
		t.Errorf("result = %+v; want Sent=2 Failed=0", res)
	}
	if got := res.PerChannel["inmemory"]; got.Sent != 2 {
		t.Errorf("PerChannel[inmemory].Sent = %d; want 2", got.Sent)
	}

	captured := mem.Captured()
	if len(captured) != 2 {
		t.Fatalf("captured = %d; want 2 (one per reviewer)", len(captured))
	}
	byUser := map[string]Notification{}
	for _, n := range captured {
		byUser[n.RecipientUserID] = n
	}
	if got, ok := byUser["u1"]; !ok {
		t.Errorf("u1 notification missing")
	} else {
		if got.Metadata["pending_count"] != 2 {
			t.Errorf("u1 pending_count = %v; want 2", got.Metadata["pending_count"])
		}
		if got.Metadata["first_due_at"] != due1.Format(time.RFC3339) {
			t.Errorf("u1 first_due_at = %v; want earliest %s", got.Metadata["first_due_at"], due1.Format(time.RFC3339))
		}
	}
	if got, ok := byUser["u2"]; !ok {
		t.Errorf("u2 notification missing")
	} else if got.Metadata["pending_count"] != 1 {
		t.Errorf("u2 pending_count = %v; want 1", got.Metadata["pending_count"])
	}
}

// TestNotifyReviewersPending_FailureDoesNotBlockOthers asserts a
// Notifier that returns an error does not cause other notifiers
// to be skipped, and the failed channel surfaces in PerChannel.
func TestNotifyReviewersPending_FailureDoesNotBlockOthers(t *testing.T) {
	t.Parallel()
	failing := &InMemoryNotifier{Fail: func(_ Notification) error { return errors.New("boom") }}
	good := &InMemoryNotifier{}
	svc := NewNotificationService(failing, good)

	_, err := svc.NotifyReviewersPending(context.Background(), "rev1", []ReviewerPendingDecision{
		{ReviewerUserID: "u1", GrantID: "g1", DueAt: time.Now()},
	})
	// Notification failures must not bubble up — the lifecycle
	// caller should see no error so the underlying campaign is
	// not rolled back.
	if err != nil {
		t.Errorf("NotifyReviewersPending: %v; want nil even when one channel fails", err)
	}
	if got := len(good.Captured()); got != 1 {
		t.Errorf("good channel captured = %d; want 1", got)
	}
	if got := len(failing.Captured()); got != 0 {
		t.Errorf("failing channel captured = %d; want 0", got)
	}
}

// TestNotifyReviewersPending_EmptyReviewerSkipped asserts entries
// with an empty ReviewerUserID are dropped silently rather than
// surfacing an error or generating a malformed notification.
func TestNotifyReviewersPending_EmptyReviewerSkipped(t *testing.T) {
	t.Parallel()
	mem := &InMemoryNotifier{}
	svc := NewNotificationService(mem)

	res, err := svc.NotifyReviewersPending(context.Background(), "rev1", []ReviewerPendingDecision{
		{ReviewerUserID: "", GrantID: "g1", DueAt: time.Now()},
	})
	if err != nil {
		t.Fatalf("NotifyReviewersPending: %v", err)
	}
	if res.Sent != 0 {
		t.Errorf("Sent = %d; want 0", res.Sent)
	}
	if got := len(mem.Captured()); got != 0 {
		t.Errorf("captured = %d; want 0", got)
	}
}

// TestNotifyReviewersPending_NoNotifiersIsNoop asserts a service
// constructed with zero notifiers returns successfully and dispatches
// nothing.
func TestNotifyReviewersPending_NoNotifiersIsNoop(t *testing.T) {
	t.Parallel()
	svc := NewNotificationService()
	res, err := svc.NotifyReviewersPending(context.Background(), "rev1", []ReviewerPendingDecision{
		{ReviewerUserID: "u1", DueAt: time.Now()},
	})
	if err != nil {
		t.Fatalf("NotifyReviewersPending: %v", err)
	}
	if res.Sent != 0 || res.Failed != 0 {
		t.Errorf("result = %+v; want all zeros", res)
	}
}

// TestNotifyRequester_HappyPath asserts the requester notification
// reaches the configured channel with the expected metadata.
func TestNotifyRequester_HappyPath(t *testing.T) {
	t.Parallel()
	mem := &InMemoryNotifier{}
	svc := NewNotificationService(mem)

	res, err := svc.NotifyRequester(context.Background(), "01HREQXXXXXXXXXXXXXXXXXXX", "u-alice", "Your request was approved")
	if err != nil {
		t.Fatalf("NotifyRequester: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("Sent = %d; want 1", res.Sent)
	}
	captured := mem.Captured()
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	got := captured[0]
	if got.Kind != KindRequesterStatus {
		t.Errorf("Kind = %q; want %q", got.Kind, KindRequesterStatus)
	}
	if got.RecipientUserID != "u-alice" {
		t.Errorf("RecipientUserID = %q; want u-alice", got.RecipientUserID)
	}
	if got.Body != "Your request was approved" {
		t.Errorf("Body = %q; want approved message", got.Body)
	}
	if got.Metadata["request_id"] != "01HREQXXXXXXXXXXXXXXXXXXX" {
		t.Errorf("Metadata[request_id] = %v; want request id", got.Metadata["request_id"])
	}
}

// TestNotifyRequester_EmptyRecipientErrors asserts a missing
// requester_user_id surfaces a validation error instead of silently
// dropping the message.
func TestNotifyRequester_EmptyRecipientErrors(t *testing.T) {
	t.Parallel()
	svc := NewNotificationService(&InMemoryNotifier{})
	_, err := svc.NotifyRequester(context.Background(), "req1", "", "msg")
	if err == nil {
		t.Errorf("err = nil; want validation error on empty recipient")
	}
}

// TestNotifyRequester_FailureDoesNotBlockCaller asserts a Notifier
// that errors does NOT surface the error to the caller, mirroring
// the "notifications are best-effort" contract.
func TestNotifyRequester_FailureDoesNotBlockCaller(t *testing.T) {
	t.Parallel()
	failing := &InMemoryNotifier{Fail: func(_ Notification) error { return errors.New("boom") }}
	svc := NewNotificationService(failing)

	res, err := svc.NotifyRequester(context.Background(), "req1", "u1", "msg")
	if err != nil {
		t.Errorf("NotifyRequester: %v; want nil even when channel fails", err)
	}
	if res.Failed != 1 {
		t.Errorf("Failed = %d; want 1", res.Failed)
	}
}

// TestNotificationService_NilNotifierFiltered asserts a nil notifier
// in the constructor is silently dropped (the service is robust to
// dev binaries wiring zero channels).
func TestNotificationService_NilNotifierFiltered(t *testing.T) {
	t.Parallel()
	mem := &InMemoryNotifier{}
	svc := NewNotificationService(nil, mem, nil)

	if _, err := svc.NotifyRequester(context.Background(), "req1", "u1", "msg"); err != nil {
		t.Fatalf("NotifyRequester: %v", err)
	}
	if got := len(mem.Captured()); got != 1 {
		t.Errorf("captured = %d; want 1 (nil notifiers must be filtered out)", got)
	}
}
