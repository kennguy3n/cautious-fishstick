package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubReviewNotifier captures every NotifyReviewersPending call for
// the StartCampaign-with-notifier tests. Set Err to drive the
// "channel returned an error" path; the access service must NOT
// surface that error to its caller (notifications are best-effort
// per PHASES Phase 5).
type stubReviewNotifier struct {
	Err   error
	Calls []stubNotifyCall
}

type stubNotifyCall struct {
	ReviewID  string
	Decisions []ReviewerPendingDecisionRef
}

func (s *stubReviewNotifier) NotifyReviewersPending(_ context.Context, reviewID string, refs []ReviewerPendingDecisionRef) error {
	s.Calls = append(s.Calls, stubNotifyCall{ReviewID: reviewID, Decisions: append([]ReviewerPendingDecisionRef(nil), refs...)})
	return s.Err
}

// stubReviewerResolver returns a fixed reviewer-per-grant mapping.
// Set Err to surface a resolver failure.
type stubReviewerResolver struct {
	Err     error
	OnPerGrant func(grantID string) (string, time.Time)
}

func (s *stubReviewerResolver) ResolveReviewers(_ context.Context, _ string, decisions []models.AccessReviewDecision) ([]ReviewerPendingDecisionRef, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	out := make([]ReviewerPendingDecisionRef, 0, len(decisions))
	for _, d := range decisions {
		userID := "u-default"
		due := time.Now().Add(72 * time.Hour)
		if s.OnPerGrant != nil {
			userID, due = s.OnPerGrant(d.GrantID)
		}
		out = append(out, ReviewerPendingDecisionRef{
			ReviewerUserID: userID,
			GrantID:        d.GrantID,
			DueAt:          due,
		})
	}
	return out, nil
}

// TestStartCampaign_NotifiesReviewersAfterCommit asserts the
// notifier sees one call with the resolved reviewer references.
func TestStartCampaign_NotifiesReviewersAfterCommit(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTRN001", ws, "u1", conn, "admin", "host-a")
	seedActiveGrant(t, db, "01H000000000000000GRANTRN002", ws, "u2", conn, "admin", "host-b")

	notif := &stubReviewNotifier{}
	resolver := &stubReviewerResolver{}
	svc := NewAccessReviewService(db, nil)
	svc.SetNotifier(notif, resolver)

	_, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "Quarterly review",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(notif.Calls) != 1 {
		t.Fatalf("notifier calls = %d; want 1", len(notif.Calls))
	}
	if got := len(notif.Calls[0].Decisions); got != 2 {
		t.Errorf("notifier saw %d decisions; want 2", got)
	}
}

// TestStartCampaign_NotifierFailureDoesNotBlock asserts a notifier
// error does NOT surface to the StartCampaign caller and does NOT
// roll back the campaign rows.
func TestStartCampaign_NotifierFailureDoesNotBlock(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTRN010", ws, "u1", conn, "admin", "host-a")

	notif := &stubReviewNotifier{Err: errors.New("smtp down")}
	resolver := &stubReviewerResolver{}
	svc := NewAccessReviewService(db, nil)
	svc.SetNotifier(notif, resolver)

	review, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "Quarterly review",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v; want nil even when notifier fails", err)
	}
	if review.ID == "" {
		t.Errorf("review.ID is empty; campaign was rolled back")
	}
	if len(decisions) != 1 {
		t.Errorf("decisions = %d; want 1 (campaign was rolled back)", len(decisions))
	}
}

// TestStartCampaign_NoNotifierIsNoop asserts a service constructed
// without a notifier creates the campaign normally and dispatches
// nothing.
func TestStartCampaign_NoNotifierIsNoop(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTRN020", ws, "u1", conn, "admin", "host-a")

	svc := NewAccessReviewService(db, nil)

	review, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "Quarterly review",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if review.ID == "" || len(decisions) != 1 {
		t.Errorf("unexpected campaign state: review=%v decisions=%d", review, len(decisions))
	}
}

// TestStartCampaign_ResolverFailureDoesNotBlock asserts a resolver
// error is logged but does NOT propagate to the caller.
func TestStartCampaign_ResolverFailureDoesNotBlock(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTRN030", ws, "u1", conn, "admin", "host-a")

	notif := &stubReviewNotifier{}
	resolver := &stubReviewerResolver{Err: errors.New("ldap down")}
	svc := NewAccessReviewService(db, nil)
	svc.SetNotifier(notif, resolver)

	_, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "Quarterly review",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v; want nil even when resolver fails", err)
	}
	if len(notif.Calls) != 0 {
		t.Errorf("notifier calls = %d; want 0 when resolver failed", len(notif.Calls))
	}
}
