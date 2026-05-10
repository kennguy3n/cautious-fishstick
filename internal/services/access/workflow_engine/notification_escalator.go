package workflow_engine

import (
	"context"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// EscalationNotifier is the narrow notification contract the
// production NotifyingEscalator depends on. The cmd/access-workflow-
// engine binary wires this to access.NotificationAdapter (which
// itself wraps notification.NotificationService); tests substitute a
// stub that records calls in a slice.
//
// The interface is split from PendingNotifier intentionally so the
// performer and escalator can be tested in isolation without each
// stub having to implement the union of methods.
type EscalationNotifier interface {
	NotifyRequester(ctx context.Context, requestID, requesterUserID, message string) error
}

// NotifyingEscalator is the production Escalator that the
// access-workflow-engine binary wires onto EscalationChecker. It
// composes:
//
//   - a *gorm.DB for the state-history audit row written for every
//     escalation (so the audit trail records the from/to handover);
//   - an optional EscalationNotifier for the requester-side ping.
//
// Per docs/PHASES.md Phase 5/8 cross-cutting criteria, side effects
// in this struct are best-effort — a notification failure MUST NOT
// prevent the state-history row from being written, and a state-
// history write failure MUST NOT prevent the in-memory escalation
// from completing (the EscalationChecker will surface the underlying
// error to its caller, but the per-call ordering means audit trail
// is preserved whenever possible).
type NotifyingEscalator struct {
	db       *gorm.DB
	notifier EscalationNotifier
	actorID  string
	now      func() time.Time
	newID    func() string
}

// NewNotifyingEscalator constructs a NotifyingEscalator. db is
// required; notifier is optional (passing nil disables the requester
// ping but still writes the audit row).
func NewNotifyingEscalator(db *gorm.DB, notifier EscalationNotifier) *NotifyingEscalator {
	if db == nil {
		panic("workflow_engine: NotifyingEscalator requires non-nil db")
	}
	return &NotifyingEscalator{
		db:       db,
		notifier: notifier,
		actorID:  SystemActorID,
		now:      time.Now,
		newID:    newPerformerULID,
	}
}

// SetClock overrides the time hook. Tests use this to pin CreatedAt
// timestamps in audit assertions.
func (e *NotifyingEscalator) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// WithActorID overrides the actor string the escalator stamps onto
// state-history rows. Returns the escalator for chaining.
func (e *NotifyingEscalator) WithActorID(actor string) *NotifyingEscalator {
	if actor != "" {
		e.actorID = actor
	}
	return e
}

// Escalate is invoked by EscalationChecker once per pending request
// whose oldest approval step has exceeded its timeout. It performs
// two side effects:
//
//  1. Writes an AccessRequestStateHistory row recording the
//     escalation event. The from→to states are both
//     RequestStateRequested (escalation does not flip the request
//     state); the Reason field captures the from/to roles.
//  2. Fans out a best-effort notification to the requester so they
//     know their pending step has been bumped.
//
// Order matters: the audit row is written FIRST. A failure to write
// the audit row is surfaced as an error so the EscalationChecker
// will retry on its next pass. A failure to send the notification is
// swallowed (logged) so we don't roll back the audit row — the audit
// row is the durable record.
func (e *NotifyingEscalator) Escalate(ctx context.Context, req *models.AccessRequest, wf *models.AccessWorkflow, from, to string) error {
	if req == nil || wf == nil {
		return nil
	}
	history := &models.AccessRequestStateHistory{
		ID:          e.newID(),
		RequestID:   req.ID,
		FromState:   req.State,
		ToState:     req.State,
		ActorUserID: e.actorID,
		Reason:      fmt.Sprintf("workflow_engine: escalation %s → %s (workflow %s)", from, to, wf.ID),
		CreatedAt:   e.now(),
	}
	if err := e.db.WithContext(ctx).Create(history).Error; err != nil {
		return fmt.Errorf("workflow_engine: escalation audit for request %s: %w", req.ID, err)
	}
	if e.notifier != nil && req.RequesterUserID != "" {
		msg := fmt.Sprintf("Your access request was escalated from %s to %s.", from, to)
		if nerr := e.notifier.NotifyRequester(ctx, req.ID, req.RequesterUserID, msg); nerr != nil {
			log.Printf("workflow_engine: escalation notify request %s: %v", req.ID, nerr)
		}
	}
	return nil
}

var _ Escalator = (*NotifyingEscalator)(nil)
