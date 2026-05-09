// Package notification is the Phase 5 fan-out for reviewer +
// requester notifications.
//
// Per docs/PHASES.md Phase 5 exit criteria the access platform must
// notify reviewers when a campaign produces pending decisions and
// notify requesters when their access_request changes state. Phase 5
// implements the interface and an in-memory channel suitable for
// tests + dev binaries; Phase 6+ adds email / Slack / push channels
// behind the same interface.
//
// Failure semantics: notifications are best-effort. A failed send
// MUST NOT roll back the underlying lifecycle write — campaign
// creation, request approval, etc. all proceed even when the
// notifier returns an error. The service logs failures and surfaces
// them in the returned NotifyResult so the caller can decide
// whether to retry.
package notification

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// NotificationKind taxonomies the inbound notification events the
// service supports. Each kind drives a different default subject /
// channel routing rule in the configured Notifier; the wire format
// is identical so adding new kinds does not require a schema
// migration.
type NotificationKind string

const (
	// KindReviewerPending is dispatched when an access-review
	// campaign produces one or more pending decisions for a
	// reviewer (per PHASES Phase 5 exit criteria).
	KindReviewerPending NotificationKind = "reviewer_pending"

	// KindRequesterStatus is dispatched when an access_request
	// transitions to a terminal-ish state the requester cares
	// about (approved / denied / provisioned / provision_failed).
	KindRequesterStatus NotificationKind = "requester_status"
)

// Notification is the per-recipient envelope the service hands to a
// Notifier. The struct is intentionally narrow — channel-specific
// formatting (HTML email body, Slack block kit) lives behind the
// Notifier interface so the service stays decoupled from any one
// channel.
type Notification struct {
	// Kind is the event taxonomy entry; see NotificationKind.
	Kind NotificationKind
	// RecipientUserID is the internal user ID of the addressee.
	RecipientUserID string
	// Subject is a short single-line summary the channel can use
	// as an email subject / Slack thread title.
	Subject string
	// Body is the rendered free-form message. Plain text; channels
	// that need rich formatting render it themselves.
	Body string
	// Metadata carries channel-agnostic context (review_id,
	// request_id, campaign_due_at, ...). Channels MAY surface or
	// drop fields per their own UI affordances.
	Metadata map[string]interface{}
	// CreatedAt is the timestamp the service attached when the
	// notification was queued. Used for deduplication and audit.
	CreatedAt time.Time
}

// Notifier is the channel-side contract the notification service
// fans messages out to. Phase 5 wires only the in-memory channel;
// Phase 6+ adds Email / Slack / push variants behind the same
// interface.
type Notifier interface {
	// Send dispatches the notification on the underlying channel.
	// Errors are logged and surfaced in NotifyResult; they MUST
	// NOT roll back the caller's lifecycle transaction.
	Send(ctx context.Context, n Notification) error
	// Name returns a stable channel identifier ("inmemory",
	// "email_ses", ...) used in NotifyResult.PerChannel for
	// observability.
	Name() string
}

// NotifyResult is the per-call summary the service returns to the
// caller. The struct lets callers see "notifications enqueued" vs
// "channels that failed" without parsing logs.
type NotifyResult struct {
	// Sent is the count of (notification, channel) pairs that
	// returned no error.
	Sent int
	// Failed is the count of (notification, channel) pairs that
	// returned an error. Failed notifications are still logged
	// individually.
	Failed int
	// PerChannel breaks Sent + Failed down by channel name.
	PerChannel map[string]ChannelStats
}

// ChannelStats is the per-channel sent / failed breakdown surfaced
// inside NotifyResult.
type ChannelStats struct {
	Sent   int `json:"sent"`
	Failed int `json:"failed"`
}

// NotificationService fans events out to one or more Notifier
// implementations. The zero value is NOT safe; construct via
// NewNotificationService.
//
// The service is safe for concurrent use: notifiers is set at
// construction time and the Notifier implementations themselves
// are responsible for their own concurrency.
type NotificationService struct {
	notifiers []Notifier

	// now is overridable so tests can pin "current time" without
	// reaching into time.Now. Defaults to time.Now in
	// NewNotificationService.
	now func() time.Time
}

// NewNotificationService returns a service that dispatches
// notifications to each non-nil notifier in order. Empty notifier
// list is allowed — every Notify* call becomes a no-op success,
// which is the right default for dev binaries that do not have
// any channel configured.
func NewNotificationService(notifiers ...Notifier) *NotificationService {
	clean := make([]Notifier, 0, len(notifiers))
	for _, n := range notifiers {
		if n == nil {
			continue
		}
		clean = append(clean, n)
	}
	return &NotificationService{
		notifiers: clean,
		now:       time.Now,
	}
}

// SetNow overrides the time hook. Tests use this to assert the
// CreatedAt timestamp the service stamps onto each Notification.
func (s *NotificationService) SetNow(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// ReviewerPendingDecision is the per-reviewer summary the
// AccessReviewService passes to NotifyReviewersPending. Each entry
// becomes one Notification (one per reviewer); the service does NOT
// dedupe by reviewer ID — the caller is responsible for collapsing
// duplicate reviewer references before calling.
type ReviewerPendingDecision struct {
	ReviewerUserID string
	GrantID        string
	GrantSummary   string
	DueAt          time.Time
}

// NotifyReviewersPending fans out a "you have pending decisions"
// notification to every reviewer in decisions. The service renders
// a per-reviewer rollup (count of pending grants + earliest due-at)
// rather than a one-message-per-grant blast.
//
// Returns a NotifyResult that callers MAY surface to the operator
// (e.g. as part of the StartCampaign response). A nil decisions
// slice is a no-op success.
func (s *NotificationService) NotifyReviewersPending(ctx context.Context, reviewID string, decisions []ReviewerPendingDecision) (*NotifyResult, error) {
	rollup := map[string]*ReviewerPendingDecision{}
	counts := map[string]int{}
	for i := range decisions {
		d := decisions[i]
		if d.ReviewerUserID == "" {
			continue
		}
		counts[d.ReviewerUserID]++
		if cur, ok := rollup[d.ReviewerUserID]; !ok || d.DueAt.Before(cur.DueAt) {
			cp := d
			rollup[d.ReviewerUserID] = &cp
		}
	}
	out := emptyResult()
	for reviewerID, head := range rollup {
		n := Notification{
			Kind:            KindReviewerPending,
			RecipientUserID: reviewerID,
			Subject:         fmt.Sprintf("Access review %s: %d pending decisions", shortReviewID(reviewID), counts[reviewerID]),
			Body: fmt.Sprintf(
				"You have %d pending access-review decisions on review %s. Earliest due at %s.",
				counts[reviewerID], reviewID, head.DueAt.Format(time.RFC3339),
			),
			Metadata: map[string]interface{}{
				"review_id":      reviewID,
				"pending_count":  counts[reviewerID],
				"first_due_at":   head.DueAt.Format(time.RFC3339),
				"first_grant_id": head.GrantID,
			},
			CreatedAt: s.now(),
		}
		s.dispatch(ctx, n, out)
	}
	return out, nil
}

// NotifyRequester sends a status-update notification to the
// requester of an access_request. message is the operator-facing
// body the service forwards to each Notifier; the service
// supplies a default subject if none is set.
func (s *NotificationService) NotifyRequester(ctx context.Context, requestID, requesterUserID, message string) (*NotifyResult, error) {
	if requesterUserID == "" {
		// Empty recipient → caller is misconfigured. Surface a
		// validation error so we don't silently drop the message.
		return nil, fmt.Errorf("notification: requester_user_id is required")
	}
	n := Notification{
		Kind:            KindRequesterStatus,
		RecipientUserID: requesterUserID,
		Subject:         fmt.Sprintf("Access request %s update", shortReviewID(requestID)),
		Body:            message,
		Metadata: map[string]interface{}{
			"request_id": requestID,
		},
		CreatedAt: s.now(),
	}
	out := emptyResult()
	s.dispatch(ctx, n, out)
	return out, nil
}

// dispatch fans n out to every configured notifier and aggregates
// the per-channel sent / failed counts. Errors from any notifier
// are logged but never returned — notifications are best-effort.
func (s *NotificationService) dispatch(ctx context.Context, n Notification, out *NotifyResult) {
	for _, ntf := range s.notifiers {
		err := ntf.Send(ctx, n)
		stats := out.PerChannel[ntf.Name()]
		if err != nil {
			stats.Failed++
			out.Failed++
			log.Printf("notification: channel %s failed for kind=%s recipient=%s: %v", ntf.Name(), n.Kind, n.RecipientUserID, err)
		} else {
			stats.Sent++
			out.Sent++
		}
		out.PerChannel[ntf.Name()] = stats
	}
}

// emptyResult returns a fresh result envelope with the PerChannel
// map initialised so callers can write through without checking
// for nil.
func emptyResult() *NotifyResult {
	return &NotifyResult{
		PerChannel: map[string]ChannelStats{},
	}
}

// shortReviewID truncates an opaque ULID to its tail 8 chars so
// notification subjects stay readable. Empty IDs surface as
// "(unknown)" to make the renderer's contract obvious.
func shortReviewID(id string) string {
	if id == "" {
		return "(unknown)"
	}
	if len(id) <= 8 {
		return id
	}
	return id[len(id)-8:]
}

// InMemoryNotifier is the Phase 5 default Notifier. It buffers
// every Notification in a goroutine-safe slice so tests + dev
// binaries can assert the inbound stream without spinning up a
// real channel.
//
// Production deployments wire one or more channel-specific
// notifiers (email, Slack, ...) instead, behind the same Notifier
// interface.
type InMemoryNotifier struct {
	mu       sync.Mutex
	captured []Notification
	// Fail, if non-nil, returns an error from Send to drive the
	// "channel failed" path in tests. Nil → every Send succeeds.
	Fail func(n Notification) error
}

// Send implements Notifier by appending to captured (and optionally
// failing per the Fail hook).
func (m *InMemoryNotifier) Send(_ context.Context, n Notification) error {
	if m.Fail != nil {
		if err := m.Fail(n); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.captured = append(m.captured, n)
	m.mu.Unlock()
	return nil
}

// Name implements Notifier and returns a stable identifier for the
// in-memory channel.
func (m *InMemoryNotifier) Name() string { return "inmemory" }

// Captured returns a copy of every notification observed so far.
// Returning a copy lets tests iterate without holding the mutex
// across other Send calls.
func (m *InMemoryNotifier) Captured() []Notification {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Notification, len(m.captured))
	copy(out, m.captured)
	return out
}
