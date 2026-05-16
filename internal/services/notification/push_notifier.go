package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// PushSubscription mirrors the W3C PushSubscription serialised
// payload one-for-one. Operators register a subscription per browser
// session via the access-platform UI; the access service stores the
// rows in push_subscriptions and the WebPushNotifier dispatches
// notifications by POST'ing the rendered payload to Endpoint.
//
// Per docs/architecture.md Phase 5/6 the push channel is best-effort: an
// HTTP failure logs but does NOT abort the parent fan-out — see the
// Send method below.
//
// Notable invariants:
//
//   - Endpoint is the absolute URL the browser-supplied push service
//     accepts POST'd encrypted payloads at.
//   - P256DH and Auth are the per-subscription public keys used to
//     encrypt the body. The Phase 5 implementation uses the simpler
//     "VAPID-less" delivery — bodies are sent in plain JSON to the
//     endpoint and rely on TLS for confidentiality. Phase 7+ wires
//     full RFC 8291 payload encryption.
type PushSubscription struct {
	UserID   string `json:"user_id"`
	Endpoint string `json:"endpoint"`
	P256DH   string `json:"p256dh,omitempty"`
	Auth     string `json:"auth,omitempty"`
}

// PushSubscriptionResolver maps an internal user ID to zero or more
// PushSubscriptions. Production callers wire this to a row scan
// against the push_subscriptions table; tests inject a slice
// directly.
//
// A user with zero subscriptions is fine — the notifier short-
// circuits to a no-op success for that recipient (mirrors the
// EmailNotifier "no address on file" behaviour).
type PushSubscriptionResolver interface {
	ResolvePushSubscriptions(ctx context.Context, userID string) ([]PushSubscription, error)
}

// PushSubscriptionResolverFunc is a function adapter that satisfies
// PushSubscriptionResolver. Useful for ad-hoc wiring from cmd/* and
// for tests.
type PushSubscriptionResolverFunc func(ctx context.Context, userID string) ([]PushSubscription, error)

// ResolvePushSubscriptions satisfies PushSubscriptionResolver.
func (f PushSubscriptionResolverFunc) ResolvePushSubscriptions(ctx context.Context, userID string) ([]PushSubscription, error) {
	if f == nil {
		return nil, nil
	}
	return f(ctx, userID)
}

// PushHTTPClient is the narrow contract the WebPushNotifier uses to
// POST the rendered notification body to a subscription endpoint.
// *http.Client satisfies it; tests substitute a fake.
type PushHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WebPushNotifier is the Phase 5/6 push channel. It looks each
// recipient up via the configured PushSubscriptionResolver and
// POSTs a small JSON envelope to every active subscription's
// endpoint.
//
// Failure semantics mirror the email channel: a per-subscription
// HTTP error logs and bumps the failed counter but never aborts the
// fan-out. Per docs/architecture.md cross-cutting criteria notifications
// MUST NOT roll back the parent lifecycle transaction.
type WebPushNotifier struct {
	resolver PushSubscriptionResolver
	client   PushHTTPClient
	timeout  time.Duration
}

// NewWebPushNotifier constructs a notifier. resolver is required.
// client may be nil (defaults to http.DefaultClient with a 5-second
// timeout). timeout caps each individual HTTP request; defaults to
// 5s when zero.
func NewWebPushNotifier(resolver PushSubscriptionResolver, client PushHTTPClient, timeout time.Duration) *WebPushNotifier {
	if resolver == nil {
		panic("notification: WebPushNotifier requires a non-nil resolver")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &WebPushNotifier{resolver: resolver, client: client, timeout: timeout}
}

// Name satisfies Notifier — used by NotifyResult.PerChannel for
// observability dashboards.
func (n *WebPushNotifier) Name() string { return "webpush" }

// pushEnvelope is the JSON shape POST'd to each subscription
// endpoint. Mirrors the Notification field set the
// NotificationService publishes. We send plain JSON in Phase 5/6 —
// Phase 7+ will swap this for RFC 8291 ECDH-ES encrypted payloads.
type pushEnvelope struct {
	Kind            string                 `json:"kind"`
	Subject         string                 `json:"subject"`
	Body            string                 `json:"body"`
	RecipientUserID string                 `json:"recipient_user_id"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}

// Send fans the notification out to every subscription registered
// under n.RecipientUserID. Per-subscription errors are logged and
// returned as a joined error so callers can surface partial failure
// in NotifyResult; the function never aborts mid-loop.
//
// A recipient with zero subscriptions is treated as success (no-op)
// because Phase 5 push is opt-in — operators should not be spammed
// about users who never enrolled a browser.
//
// A nil HTTP request body is impossible: we always render the
// envelope, even when Subject + Body are empty, because the browser-
// side service worker still needs something to surface.
func (n *WebPushNotifier) Send(ctx context.Context, notif Notification) error {
	if n.resolver == nil {
		return fmt.Errorf("notification: WebPushNotifier has no resolver")
	}
	subs, err := n.resolver.ResolvePushSubscriptions(ctx, notif.RecipientUserID)
	if err != nil {
		return fmt.Errorf("notification: webpush resolve %s: %w", notif.RecipientUserID, err)
	}
	if len(subs) == 0 {
		log.Printf("notification: webpush: no subscriptions for user %q; skipping", notif.RecipientUserID)
		return nil
	}
	body, err := json.Marshal(pushEnvelope{
		Kind:            string(notif.Kind),
		Subject:         notif.Subject,
		Body:            notif.Body,
		RecipientUserID: notif.RecipientUserID,
		Metadata:        notif.Metadata,
		CreatedAt:       notif.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("notification: webpush encode: %w", err)
	}

	var firstErr error
	failures := 0
	for _, sub := range subs {
		if sub.Endpoint == "" {
			log.Printf("notification: webpush: empty endpoint for user %q; skipping", notif.RecipientUserID)
			continue
		}
		if err := n.postOne(ctx, sub, body); err != nil {
			failures++
			log.Printf("notification: webpush deliver %s for user %s: %v", redactEndpoint(sub.Endpoint), notif.RecipientUserID, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if failures > 0 {
		return firstErr
	}
	return nil
}

func (n *WebPushNotifier) postOne(ctx context.Context, sub PushSubscription, body []byte) error {
	reqCtx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("TTL", "300")
	if sub.P256DH != "" {
		req.Header.Set("X-Push-P256DH", sub.P256DH)
	}
	if sub.Auth != "" {
		req.Header.Set("X-Push-Auth", sub.Auth)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
}

// redactEndpoint returns the endpoint URL with any embedded path /
// query stripped — push endpoints frequently encode the
// subscription token in the path, which is sensitive.
func redactEndpoint(endpoint string) string {
	if i := strings.Index(endpoint, "://"); i >= 0 {
		rest := endpoint[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return endpoint[:i+3+j] + "/…"
		}
	}
	return endpoint
}

var _ Notifier = (*WebPushNotifier)(nil)
