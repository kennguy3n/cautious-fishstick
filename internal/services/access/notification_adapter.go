package access

import (
	"context"

	"github.com/kennguy3n/cautious-fishstick/internal/services/notification"
)

// NotificationAdapter wraps *notification.NotificationService so the
// access package can satisfy the ReviewNotifier interface without a
// direct import dependency.
//
// Construction is intentionally trivial:
//
//	notifSvc := notification.NewNotificationService(...)
//	reviewSvc.SetNotifier(&access.NotificationAdapter{Inner: notifSvc}, resolver)
//
// The adapter MAY have a nil Inner — in that case NotifyReviewersPending
// is a no-op. This makes it cheap to wire in unconditionally.
type NotificationAdapter struct {
	Inner *notification.NotificationService
}

// NotifyReviewersPending forwards to the inner notification service,
// translating the access-package wire shape (ReviewerPendingDecisionRef)
// into the notification-package shape (ReviewerPendingDecision).
//
// Errors are surfaced to the caller (AccessReviewService) which logs
// them but does not roll back. The adapter therefore preserves the
// PROPOSAL §5.4 invariant that lifecycle writes proceed even when a
// channel is offline.
func (a *NotificationAdapter) NotifyReviewersPending(ctx context.Context, reviewID string, refs []ReviewerPendingDecisionRef) error {
	if a == nil || a.Inner == nil {
		return nil
	}
	out := make([]notification.ReviewerPendingDecision, 0, len(refs))
	for _, r := range refs {
		out = append(out, notification.ReviewerPendingDecision{
			ReviewerUserID: r.ReviewerUserID,
			GrantID:        r.GrantID,
			GrantSummary:   r.GrantSummary,
			DueAt:          r.DueAt,
		})
	}
	_, err := a.Inner.NotifyReviewersPending(ctx, reviewID, out)
	return err
}

// NotifyRequester forwards a per-request status notification to the
// inner notification service. Used by the Phase 8 workflow engine's
// ServiceStepPerformer to ping the requester when their access
// request enters a pending step (manager_approval / security_review
// / multi_level).
//
// A nil adapter / nil Inner is a no-op success — keeps the workflow
// engine's wiring trivial in dev and test binaries that don't have
// any channel configured.
func (a *NotificationAdapter) NotifyRequester(ctx context.Context, requestID, requesterUserID, message string) error {
	if a == nil || a.Inner == nil {
		return nil
	}
	_, err := a.Inner.NotifyRequester(ctx, requestID, requesterUserID, message)
	return err
}

// NewNotificationServiceAdapter is a constructor convenience that
// wraps the supplied *notification.NotificationService into a
// *NotificationAdapter. Identical to manually setting Inner; the
// constructor exists so cmd/* binaries can wire the adapter inline
// without importing the field-init syntax.
func NewNotificationServiceAdapter(inner *notification.NotificationService) *NotificationAdapter {
	return &NotificationAdapter{Inner: inner}
}
