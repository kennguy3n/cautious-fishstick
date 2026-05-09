package notification

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

// EmailRecipientResolver maps an internal user ID to one or more
// email addresses. Production callers wire in the workspace's
// directory service; tests stub it directly.
//
// Returning a nil / empty slice is "no addresses on file" and the
// EmailNotifier short-circuits to a logged warning — Phase 5
// notifications are best-effort and a missing recipient must NOT
// fail the dispatch.
type EmailRecipientResolver interface {
	ResolveEmail(ctx context.Context, userID string) ([]string, error)
}

// EmailRecipientResolverFunc is a function adapter that satisfies
// EmailRecipientResolver. Useful for ad-hoc wiring from cmd/* and
// for tests that want a lambda.
type EmailRecipientResolverFunc func(ctx context.Context, userID string) ([]string, error)

// ResolveEmail satisfies EmailRecipientResolver.
func (f EmailRecipientResolverFunc) ResolveEmail(ctx context.Context, userID string) ([]string, error) {
	return f(ctx, userID)
}

// SMTPSender is the narrow contract EmailNotifier uses to dial
// SMTP. The Go standard library net/smtp.SendMail signature
// satisfies it directly via SMTPSenderFunc.
//
// The interface exists purely so tests can stub the SMTP dial
// without spinning up a server. In production wire SMTPSenderFunc(
// smtp.SendMail) onto the notifier at boot.
type SMTPSender interface {
	SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

// SMTPSenderFunc adapts a function (e.g. smtp.SendMail) to the
// SMTPSender interface.
type SMTPSenderFunc func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error

// SendMail satisfies SMTPSender.
func (f SMTPSenderFunc) SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	return f(addr, auth, from, to, msg)
}

// EmailNotifierConfig is the typed snapshot of the SMTP knobs the
// notifier needs. Mirrors the NOTIFICATION_SMTP_* env vars defined
// in internal/config/access.go.
//
// Host empty means "log-only mode" — the notifier formats the
// message and logs it without dialling SMTP. This matches the
// dev/test posture where SMTP is intentionally unconfigured.
type EmailNotifierConfig struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
}

// EmailNotifier is the Phase 5 SMTP-backed Notifier. Implements the
// notification.Notifier interface so it composes into
// NotificationService alongside InMemoryNotifier and SlackNotifier.
//
// Failure semantics: errors from SMTP / the recipient resolver are
// logged and surfaced as the Send return value, but the
// NotificationService dispatch loop swallows them — notifications
// are best-effort per PHASES Phase 5 and MUST NOT roll back the
// caller's lifecycle write.
type EmailNotifier struct {
	cfg      EmailNotifierConfig
	resolver EmailRecipientResolver
	sender   SMTPSender
}

// NewEmailNotifier returns a notifier configured with cfg. resolver
// must not be nil — without a way to map user IDs to addresses the
// notifier has nothing to do. sender may be nil in which case
// Send falls back to net/smtp.SendMail (the production default).
//
// Construct one EmailNotifier per process at boot from
// cmd/ztna-api/main.go (or similar) and pass it to
// NewNotificationService.
func NewEmailNotifier(cfg EmailNotifierConfig, resolver EmailRecipientResolver, sender SMTPSender) *EmailNotifier {
	if sender == nil {
		sender = SMTPSenderFunc(smtp.SendMail)
	}
	return &EmailNotifier{
		cfg:      cfg,
		resolver: resolver,
		sender:   sender,
	}
}

// Name satisfies Notifier. Returns the stable channel identifier
// surfaced in NotifyResult.PerChannel for observability.
func (e *EmailNotifier) Name() string { return "email" }

// Send satisfies Notifier. Resolves the recipient's email addresses,
// formats a plain-text RFC 5322 message, and dispatches via SMTP.
// An empty Host in the config short-circuits to a logged warning —
// the dev / test posture where email is intentionally unconfigured.
//
// Errors are returned to the caller (NotificationService) which
// logs them and rolls them up into NotifyResult.PerChannel; they
// are NEVER allowed to roll back the caller's lifecycle
// transaction.
func (e *EmailNotifier) Send(ctx context.Context, n Notification) error {
	if e == nil {
		return errors.New("notification: email: nil notifier")
	}
	if e.resolver == nil {
		return errors.New("notification: email: resolver is required")
	}
	if n.RecipientUserID == "" {
		return errors.New("notification: email: recipient_user_id is required")
	}

	addrs, err := e.resolver.ResolveEmail(ctx, n.RecipientUserID)
	if err != nil {
		return fmt.Errorf("notification: email: resolve %s: %w", n.RecipientUserID, err)
	}
	if len(addrs) == 0 {
		// No address on file is best-effort: log and swallow so
		// the dispatch loop's PerChannel.Failed counter doesn't
		// inflate on a directory miss.
		log.Printf("notification: email: no address on file for user %s; skipping", n.RecipientUserID)
		return nil
	}

	body := e.formatMessage(addrs, n)
	if e.cfg.Host == "" {
		// Log-only mode for dev / test. The body includes the
		// rendered headers so operators can eyeball the
		// formatting without dialling SMTP.
		log.Printf("notification: email: log-only mode; would send to %s subject=%q", strings.Join(addrs, ","), n.Subject)
		return nil
	}

	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)
	var auth smtp.Auth
	if e.cfg.Username != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	}
	if err := e.sender.SendMail(addr, auth, e.cfg.From, addrs, []byte(body)); err != nil {
		return fmt.Errorf("notification: email: smtp dial %s: %w", addr, err)
	}
	return nil
}

// formatMessage renders the RFC 5322 message bytes for a single
// notification. Plain text only — channels that need rich formatting
// pick that up at the rendering layer (the Slack notifier for Slack
// Block Kit, etc.). The function is exported via Send only; tests
// reach in via the package boundary by calling Send with a stub
// SMTPSender that captures the bytes.
func (e *EmailNotifier) formatMessage(to []string, n Notification) string {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(e.cfg.From)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(strings.Join(to, ", "))
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(strings.ReplaceAll(n.Subject, "\n", " "))
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(n.Body)
	if !strings.HasSuffix(n.Body, "\n") {
		b.WriteString("\r\n")
	}
	return b.String()
}
