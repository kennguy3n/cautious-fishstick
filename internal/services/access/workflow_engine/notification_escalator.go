package workflow_engine

import (
	"context"
	"errors"
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
// Per docs/architecture.md Phase 5/8 cross-cutting criteria, side effects
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

// errEscalationAlreadyRecorded is returned from the inner CAS
// transaction when another writer has already advanced
// AccessRequest.EscalationLevel past the value we observed. Surfaced
// as a sentinel so the outer Escalate method can distinguish "no work
// to do" from a real DB error and silently return nil — the contract
// with EscalationChecker is that Escalate is idempotent.
var errEscalationAlreadyRecorded = errors.New("workflow_engine: escalation already recorded")

// Escalate is invoked by EscalationChecker once per pending request
// whose oldest approval step has exceeded its timeout. It performs
// three side effects, in order:
//
//  1. CAS-bumps AccessRequest.EscalationLevel and stamps
//     LastEscalatedAt = now. The CAS condition on the previously
//     observed EscalationLevel is what makes Escalate safe to call
//     concurrently from multiple pollers — only one writer wins; the
//     loser sees RowsAffected == 0 and bails silently.
//  2. Writes an AccessRequestStateHistory row recording the
//     escalation event. The from→to states are both
//     RequestStateRequested (escalation does not flip the request
//     state); the Reason field captures the from/to roles. Steps 1
//     and 2 happen in a single GORM transaction so an audit row is
//     never written without a corresponding CAS bump and vice versa.
//  3. Fans out a best-effort notification to the requester so they
//     know their pending step has been bumped. Notification failures
//     are logged but do NOT roll back the durable audit row — the
//     audit row is the source of truth, the notification is a
//     courtesy.
func (e *NotifyingEscalator) Escalate(ctx context.Context, req *models.AccessRequest, wf *models.AccessWorkflow, from, to string) error {
	if req == nil || wf == nil {
		return nil
	}
	expectedLevel := req.EscalationLevel
	stamped := e.now()
	historyID := e.newID()

	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Conditional update: only bump escalation_level if it
		// still matches what we observed. If a concurrent
		// EscalationChecker already advanced it, RowsAffected
		// will be 0 and we treat this Escalate as a no-op.
		result := tx.Model(&models.AccessRequest{}).
			Where("id = ? AND escalation_level = ?", req.ID, expectedLevel).
			Updates(map[string]interface{}{
				"escalation_level":  expectedLevel + 1,
				"last_escalated_at": stamped,
			})
		if result.Error != nil {
			return fmt.Errorf("workflow_engine: escalation cas for request %s: %w", req.ID, result.Error)
		}
		if result.RowsAffected == 0 {
			return errEscalationAlreadyRecorded
		}
		history := &models.AccessRequestStateHistory{
			ID:          historyID,
			RequestID:   req.ID,
			FromState:   req.State,
			ToState:     req.State,
			ActorUserID: e.actorID,
			Reason:      fmt.Sprintf("workflow_engine: escalation %s → %s (workflow %s)", from, to, wf.ID),
			CreatedAt:   stamped,
		}
		if err := tx.Create(history).Error; err != nil {
			return fmt.Errorf("workflow_engine: escalation audit for request %s: %w", req.ID, err)
		}
		return nil
	})
	if errors.Is(err, errEscalationAlreadyRecorded) {
		return nil
	}
	if err != nil {
		return err
	}

	// Reflect the new state on the in-memory request so the caller
	// (EscalationChecker) and any subsequent code in the same Run()
	// pass observe a consistent view without reloading.
	req.EscalationLevel = expectedLevel + 1
	req.LastEscalatedAt = &stamped

	if e.notifier != nil && req.RequesterUserID != "" {
		msg := fmt.Sprintf("Your access request was escalated from %s to %s.", from, to)
		if nerr := e.notifier.NotifyRequester(ctx, req.ID, req.RequesterUserID, msg); nerr != nil {
			log.Printf("workflow_engine: escalation notify request %s: %v", req.ID, nerr)
		}
	}
	return nil
}

var _ Escalator = (*NotifyingEscalator)(nil)
