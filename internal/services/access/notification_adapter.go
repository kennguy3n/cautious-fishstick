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
