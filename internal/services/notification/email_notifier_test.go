package notification

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubSMTPSender captures every SendMail call for the email notifier
// tests. The struct is goroutine-safe so tests can dispatch
// concurrent Send calls if needed.
type stubSMTPSender struct {
	mu    sync.Mutex
	calls []stubSMTPCall
	err   error
}

type stubSMTPCall struct {
	Addr string
	Auth smtp.Auth
	From string
	To   []string
	Msg  []byte
}

func (s *stubSMTPSender) SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, stubSMTPCall{Addr: addr, Auth: auth, From: from, To: append([]string{}, to...), Msg: append([]byte{}, msg...)})
	return s.err
}

// TestEmailNotifier_Name asserts the stable channel identifier so
// NotifyResult.PerChannel keys stay consistent across releases.
func TestEmailNotifier_Name(t *testing.T) {
	n := NewEmailNotifier(EmailNotifierConfig{}, EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return nil, nil
	}), nil)
	if got := n.Name(); got != "email" {
		t.Errorf("Name = %q; want %q", got, "email")
	}
}

// TestEmailNotifier_Send_HappyPath asserts the full SMTP dispatch
// path: resolver returns one address, sender is called once with the
// configured host:port, the rendered body has From / To / Subject
// headers and the body content.
func TestEmailNotifier_Send_HappyPath(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(_ context.Context, userID string) ([]string, error) {
		if userID != "user-alice" {
			t.Fatalf("resolver got userID %q; want user-alice", userID)
		}
		return []string{"alice@example.com"}, nil
	})
	sender := &stubSMTPSender{}
	cfg := EmailNotifierConfig{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "noreply@example.com",
		Username: "noreply",
		Password: "secret",
	}
	n := NewEmailNotifier(cfg, resolver, sender)

	err := n.Send(context.Background(), Notification{
		Kind:            KindReviewerPending,
		RecipientUserID: "user-alice",
		Subject:         "Pending decisions",
		Body:            "You have 3 pending review decisions.",
		CreatedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("sender.calls = %d; want 1", len(sender.calls))
	}
	c := sender.calls[0]
	if c.Addr != "smtp.example.com:587" {
		t.Errorf("Addr = %q; want smtp.example.com:587", c.Addr)
	}
	if c.From != "noreply@example.com" {
		t.Errorf("From = %q; want noreply@example.com", c.From)
	}
	if len(c.To) != 1 || c.To[0] != "alice@example.com" {
		t.Errorf("To = %v; want [alice@example.com]", c.To)
	}
	if c.Auth == nil {
		t.Errorf("Auth = nil; want smtp.PlainAuth (username was set)")
	}
	body := string(c.Msg)
	for _, want := range []string{
		"From: noreply@example.com",
		"To: alice@example.com",
		"Subject: Pending decisions",
		"You have 3 pending review decisions.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q;\nfull body:\n%s", want, body)
		}
	}
}

// TestEmailNotifier_Send_NoUsernameOmitsAuth asserts that when
// Username is empty the notifier dispatches with auth=nil. SMTP
// servers in dev / test (e.g. mailhog) typically run unauthenticated
// and PlainAuth would otherwise force a real handshake.
func TestEmailNotifier_Send_NoUsernameOmitsAuth(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return []string{"a@b"}, nil
	})
	sender := &stubSMTPSender{}
	n := NewEmailNotifier(EmailNotifierConfig{Host: "h", Port: 25, From: "f@e"}, resolver, sender)
	if err := n.Send(context.Background(), Notification{RecipientUserID: "u", Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sender.calls[0].Auth != nil {
		t.Errorf("Auth = %T; want nil (Username was empty)", sender.calls[0].Auth)
	}
}

// TestEmailNotifier_Send_LogOnlyWhenHostEmpty asserts that an empty
// Host short-circuits to log-only mode without invoking the sender.
// This is the dev / test posture where SMTP is intentionally
// unconfigured.
func TestEmailNotifier_Send_LogOnlyWhenHostEmpty(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return []string{"a@b"}, nil
	})
	sender := &stubSMTPSender{}
	n := NewEmailNotifier(EmailNotifierConfig{}, resolver, sender)
	if err := n.Send(context.Background(), Notification{RecipientUserID: "u", Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Errorf("sender.calls = %d; want 0 (log-only mode must not dial SMTP)", len(sender.calls))
	}
}

// TestEmailNotifier_Send_NoAddressIsNoop asserts that a resolver
// returning no addresses is silently skipped (no error, no SMTP
// call). Phase 5 notifications are best-effort and a directory miss
// must NOT fail the dispatch.
func TestEmailNotifier_Send_NoAddressIsNoop(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return nil, nil
	})
	sender := &stubSMTPSender{}
	n := NewEmailNotifier(EmailNotifierConfig{Host: "h", Port: 25, From: "f@e"}, resolver, sender)
	if err := n.Send(context.Background(), Notification{RecipientUserID: "u", Subject: "s", Body: "b"}); err != nil {
		t.Errorf("Send: %v; want nil (missing address must be a soft skip)", err)
	}
	if len(sender.calls) != 0 {
		t.Errorf("sender.calls = %d; want 0 (no address must skip dispatch)", len(sender.calls))
	}
}

// TestEmailNotifier_Send_ResolverErrorSurfaces asserts that a
// resolver error is wrapped and returned to the caller. The
// NotificationService dispatch loop logs / counters on this — the
// notifier itself must not swallow the error.
func TestEmailNotifier_Send_ResolverErrorSurfaces(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return nil, errors.New("directory unreachable")
	})
	n := NewEmailNotifier(EmailNotifierConfig{Host: "h", Port: 25, From: "f@e"}, resolver, &stubSMTPSender{})
	err := n.Send(context.Background(), Notification{RecipientUserID: "u", Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("Send returned nil; want resolver error to surface")
	}
	if !strings.Contains(err.Error(), "directory unreachable") {
		t.Errorf("err = %v; want it to wrap the resolver error", err)
	}
}

// TestEmailNotifier_Send_SMTPErrorSurfaces asserts that an SMTP
// dispatch failure is wrapped and returned. The dispatch loop
// counts this in PerChannel.Failed; it must NOT panic.
func TestEmailNotifier_Send_SMTPErrorSurfaces(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return []string{"a@b"}, nil
	})
	sender := &stubSMTPSender{err: errors.New("smtp dial timeout")}
	n := NewEmailNotifier(EmailNotifierConfig{Host: "h", Port: 25, From: "f@e"}, resolver, sender)
	err := n.Send(context.Background(), Notification{RecipientUserID: "u", Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("Send returned nil; want smtp error to surface")
	}
	if !strings.Contains(err.Error(), "smtp dial timeout") {
		t.Errorf("err = %v; want it to wrap the smtp error", err)
	}
}

// TestEmailNotifier_Send_EmptyRecipientReturnsValidationError
// asserts the validation guard rail: an empty RecipientUserID
// returns an error before any I/O.
func TestEmailNotifier_Send_EmptyRecipientReturnsValidationError(t *testing.T) {
	n := NewEmailNotifier(EmailNotifierConfig{}, EmailRecipientResolverFunc(func(context.Context, string) ([]string, error) {
		return nil, nil
	}), nil)
	err := n.Send(context.Background(), Notification{Subject: "s", Body: "b"})
	if err == nil {
		t.Error("Send returned nil; want validation error for empty recipient_user_id")
	}
}

// TestEmailNotifier_ComposesIntoNotificationService asserts the
// notifier plays nicely with NotificationService — a Notify*
// dispatch routes through the notifier's Send method exactly once
// per recipient, and PerChannel["email"].Sent counts the success.
func TestEmailNotifier_ComposesIntoNotificationService(t *testing.T) {
	resolver := EmailRecipientResolverFunc(func(_ context.Context, userID string) ([]string, error) {
		return []string{userID + "@example.com"}, nil
	})
	sender := &stubSMTPSender{}
	email := NewEmailNotifier(EmailNotifierConfig{Host: "h", Port: 25, From: "f@e"}, resolver, sender)
	svc := NewNotificationService(email)

	res, err := svc.NotifyReviewersPending(context.Background(), "review-1", []ReviewerPendingDecision{
		{ReviewerUserID: "alice", GrantID: "g1", DueAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("NotifyReviewersPending: %v", err)
	}
	if got := res.PerChannel["email"].Sent; got != 1 {
		t.Errorf("PerChannel[email].Sent = %d; want 1", got)
	}
	if got := res.PerChannel["email"].Failed; got != 0 {
		t.Errorf("PerChannel[email].Failed = %d; want 0", got)
	}
}
