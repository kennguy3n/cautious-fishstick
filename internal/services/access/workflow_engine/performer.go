package workflow_engine

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// SystemActorID is the actor stamped onto every state-history row
// the production performer writes when no real user is in the loop
// (auto_approve, system-marked pending, ...). The audit trail
// surfaces this so operators can tell engine-driven transitions
// from human-driven transitions at a glance.
//
// The string is intentionally not a ULID — operators reading the
// audit log immediately know the actor is the engine itself rather
// than wondering which user "system" maps to.
const SystemActorID = "workflow_engine"

// ApproveRequester is the narrow contract the production
// ServiceStepPerformer uses to flip an AccessRequest from
// requested → approved. It maps 1:1 to
// AccessRequestService.ApproveRequest so the production wiring is a
// thin pass-through, but stays an interface so the performer can be
// unit-tested without spinning up the full service.
type ApproveRequester interface {
	ApproveRequest(ctx context.Context, requestID, actorUserID, reason string) error
}

// PendingNotifier is the optional contract the production performer
// uses to fan out a "your access request is awaiting review"
// notification to the requester. The production wiring is
// notification.NotificationService.NotifyRequester (adapted via
// notification_adapter.go); passing nil disables the notification.
//
// Per docs/PHASES.md Phase 5 / Phase 8 cross-cutting criteria
// notifications are best-effort: a failed Notify MUST NOT roll back
// the underlying state-history write.
type PendingNotifier interface {
	NotifyRequester(ctx context.Context, requestID, requesterUserID, message string) error
}

// ServiceStepPerformer is the production StepPerformer that
// access-workflow-engine wires onto WorkflowExecutor. It composes:
//
//   - an ApproveRequester for the auto_approve / pre-evaluated
//     manager_approval / security_review approve paths;
//   - a *gorm.DB for the state-history audit row written each time
//     the executor enters a pending step;
//   - an optional PendingNotifier for the requester-side ping.
//
// The performer never holds open transactions — each method is its
// own unit of work so a failure in one step (e.g. a notification
// timeout) does not corrupt another. Approve delegates the FSM
// transition + audit to ApproveRequester; MarkPending writes its
// own audit row inline and forwards to the optional notifier.
type ServiceStepPerformer struct {
	db       *gorm.DB
	approver ApproveRequester
	notifier PendingNotifier
	actorID  string
	now      func() time.Time
	newID    func() string
}

// NewServiceStepPerformer builds a production performer. db and
// approver are required; notifier is optional (passing nil disables
// the requester ping). Panics on a nil db / approver because both
// are required for the performer to be useful at all and a nil here
// is a programmer error at boot, not a runtime condition.
func NewServiceStepPerformer(db *gorm.DB, approver ApproveRequester, notifier PendingNotifier) *ServiceStepPerformer {
	if db == nil {
		panic("workflow_engine: ServiceStepPerformer requires non-nil db")
	}
	if approver == nil {
		panic("workflow_engine: ServiceStepPerformer requires non-nil ApproveRequester")
	}
	return &ServiceStepPerformer{
		db:       db,
		approver: approver,
		notifier: notifier,
		actorID:  SystemActorID,
		now:      time.Now,
		newID:    newPerformerULID,
	}
}

// WithActorID overrides the actor string the performer stamps onto
// state-history rows. Useful when an operator wants to attribute
// engine-driven transitions to a service account rather than the
// generic "workflow_engine" tag. Returns the performer so callers
// can chain:
//
//	perf := NewServiceStepPerformer(db, svc, notif).WithActorID("svc:ztna-api")
func (p *ServiceStepPerformer) WithActorID(actor string) *ServiceStepPerformer {
	if actor != "" {
		p.actorID = actor
	}
	return p
}

// SetClock overrides the time hook. Tests use this to pin
// CreatedAt timestamps in audit assertions.
func (p *ServiceStepPerformer) SetClock(now func() time.Time) {
	if now != nil {
		p.now = now
	}
}

// Approve flips the request from requested → approved by delegating
// to the ApproveRequester. The audit trail is written inside
// AccessRequestService.ApproveRequest, so the performer does not
// add its own row here — doing so would double-count the same
// transition.
//
// A nil request is tolerated (replay / dry-run path the executor
// uses when the request row is missing). Approve returns nil in
// that case so the executor can continue the walk.
func (p *ServiceStepPerformer) Approve(ctx context.Context, req *models.AccessRequest, reason string) error {
	if req == nil {
		return nil
	}
	if err := p.approver.ApproveRequest(ctx, req.ID, p.actorID, reason); err != nil {
		return fmt.Errorf("workflow_engine: approve request %s: %w", req.ID, err)
	}
	return nil
}

// MarkPending writes a state-history row recording that the
// supplied step is now waiting on a human, and forwards a
// best-effort notification to the requester so they know their
// request is in flight. The request's State column is left
// untouched — the canonical state for "awaiting review" is
// RequestStateRequested per request_state_machine.go.
//
// Failures are best-effort:
//
//   - A history-row write failure logs and returns nil. The
//     workflow walk halts on pending regardless of whether the
//     audit row landed; surfacing the error here would block the
//     pending decision and strand the request.
//   - A notification failure logs and is swallowed for the same
//     reason.
//
// A nil request is tolerated for replay / dry-run callers.
func (p *ServiceStepPerformer) MarkPending(ctx context.Context, req *models.AccessRequest, stepType, reason string) error {
	if req == nil {
		return nil
	}
	history := &models.AccessRequestStateHistory{
		ID:          p.newID(),
		RequestID:   req.ID,
		FromState:   req.State,
		ToState:     req.State,
		ActorUserID: p.actorID,
		Reason:      fmt.Sprintf("workflow_engine: %s pending — %s", stepType, reason),
		CreatedAt:   p.now(),
	}
	if err := p.db.WithContext(ctx).Create(history).Error; err != nil {
		log.Printf("workflow_engine: write pending audit for request %s step %s: %v", req.ID, stepType, err)
	}
	if p.notifier != nil && req.RequesterUserID != "" {
		msg := fmt.Sprintf("Your access request is awaiting %s.", humanizeStepType(stepType))
		if nerr := p.notifier.NotifyRequester(ctx, req.ID, req.RequesterUserID, msg); nerr != nil {
			log.Printf("workflow_engine: notify requester %s for request %s: %v", req.RequesterUserID, req.ID, nerr)
		}
	}
	return nil
}

// humanizeStepType maps a workflow step type onto an operator-
// friendly string for the requester-facing notification body. Falls
// back to the raw step type for unrecognised values so a future step
// type still produces a readable subject line without a code edit.
func humanizeStepType(stepType string) string {
	switch stepType {
	case models.WorkflowStepManagerApproval:
		return "manager approval"
	case models.WorkflowStepSecurityReview:
		return "security review"
	case models.WorkflowStepMultiLevel:
		return "multi-level approval"
	default:
		return stepType
	}
}

// newPerformerULID generates a 26-character Crockford-base32 ULID
// for the audit row primary key. Mirrors AccessRequestService's
// newULID; duplicated here so the workflow_engine package stays
// dependency-free of the access service for ULID generation.
func newPerformerULID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

var _ StepPerformer = (*ServiceStepPerformer)(nil)
