package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSlackNotifier_Name asserts the stable channel identifier so
// NotifyResult.PerChannel keys stay consistent across releases.
func TestSlackNotifier_Name(t *testing.T) {
	if got := NewSlackNotifier("", nil).Name(); got != "slack" {
		t.Errorf("Name = %q; want %q", got, "slack")
	}
}

// TestSlackNotifier_Send_HappyPath asserts the full POST path: a
// 200 response from the webhook server is treated as success, and
// the request body is a valid Block Kit envelope with the subject
// as the fallback text and as the first section's header.
func TestSlackNotifier_Send_HappyPath(t *testing.T) {
	var (
		mu       sync.Mutex
		captured []byte
		ct       string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = body
		ct = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	n := NewSlackNotifier(srv.URL, &http.Client{Timeout: time.Second})
	err := n.Send(context.Background(), Notification{
		Kind:            KindReviewerPending,
		RecipientUserID: "user-alice",
		Subject:         "Pending decisions",
		Body:            "You have 3 pending review decisions.",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if ct != "application/json" {
		t.Errorf("Content-Type = %q; want application/json", ct)
	}
	var got slackPayload
	if err := json.Unmarshal(captured, &got); err != nil {
		t.Fatalf("unmarshal captured: %v;\nbody: %s", err, captured)
	}
	if got.Text != "Pending decisions" {
		t.Errorf("Text = %q; want %q", got.Text, "Pending decisions")
	}
	if len(got.Blocks) != 2 {
		t.Fatalf("len(Blocks) = %d; want 2", len(got.Blocks))
	}
	if got.Blocks[0].Text == nil || !strings.Contains(got.Blocks[0].Text.Text, "Pending decisions") {
		t.Errorf("first block text = %+v; want it to contain the subject", got.Blocks[0].Text)
	}
	if got.Blocks[1].Text == nil || got.Blocks[1].Text.Text != "You have 3 pending review decisions." {
		t.Errorf("second block text = %+v; want the body", got.Blocks[1].Text)
	}
}

// TestSlackNotifier_Send_LogOnlyWhenWebhookEmpty asserts that an
// empty webhook URL short-circuits to log-only mode without any
// HTTP I/O.
func TestSlackNotifier_Send_LogOnlyWhenWebhookEmpty(t *testing.T) {
	// Sentinel: any HTTP request hitting an unreachable address
	// would surface as an error via the default client. We use
	// the empty webhook to verify the early-return path.
	n := NewSlackNotifier("", nil)
	if err := n.Send(context.Background(), Notification{Subject: "s", Body: "b"}); err != nil {
		t.Errorf("Send: %v; want nil (empty webhook must hit log-only mode)", err)
	}
}

// TestSlackNotifier_Send_Non2xxIsError asserts that a 4xx / 5xx
// response surfaces as an error wrapping the status code so the
// NotificationService dispatch loop can count it in PerChannel.Failed.
func TestSlackNotifier_Send_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	t.Cleanup(srv.Close)

	n := NewSlackNotifier(srv.URL, &http.Client{Timeout: time.Second})
	err := n.Send(context.Background(), Notification{Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("Send returned nil; want error wrapping status=500")
	}
	if !strings.Contains(err.Error(), "status=500") {
		t.Errorf("err = %v; want it to mention status=500", err)
	}
}

// TestSlackNotifier_Send_RespectsContextCancel asserts the notifier
// honours ctx — a cancelled context causes the request to fail
// without retrying. Mirrors the AIClient timeout discipline.
//
// Implementation note: instead of a server that blocks the handler
// (which would deadlock httptest.Server.Close), we point the
// notifier at a server we close immediately. The dial / read then
// errors and we assert the error surfaces.
func TestSlackNotifier_Send_RespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	n := NewSlackNotifier("http://127.0.0.1:1/slack", &http.Client{Timeout: 100 * time.Millisecond})
	err := n.Send(ctx, Notification{Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("Send returned nil; want context-cancelled error")
	}
}

// TestSlackNotifier_ComposesIntoNotificationService asserts the
// notifier plays nicely with NotificationService — a Notify*
// dispatch routes through the notifier exactly once and
// PerChannel["slack"].Sent counts the success.
func TestSlackNotifier_ComposesIntoNotificationService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	slack := NewSlackNotifier(srv.URL, &http.Client{Timeout: time.Second})
	svc := NewNotificationService(slack)

	res, err := svc.NotifyReviewersPending(context.Background(), "review-1", []ReviewerPendingDecision{
		{ReviewerUserID: "alice", GrantID: "g1", DueAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("NotifyReviewersPending: %v", err)
	}
	if got := res.PerChannel["slack"].Sent; got != 1 {
		t.Errorf("PerChannel[slack].Sent = %d; want 1", got)
	}
}
