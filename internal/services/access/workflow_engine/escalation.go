package workflow_engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Escalator is the side-effect interface the EscalationChecker calls
// when an approval step has aged past its configured timeout. The
// production implementation in cmd/access-workflow-engine wires this
// to a notification + state-history writer.
type Escalator interface {
	// Escalate is invoked once per pending request whose oldest
	// approval step has exceeded its timeout. `from` is the role /
	// step type that timed out; `to` is the escalation_target (or
	// the next level role for multi_level).
	Escalate(ctx context.Context, req *models.AccessRequest, wf *models.AccessWorkflow, from, to string) error
}

// EscalationChecker scans pending AccessRequests and triggers
// escalation when an approval step is older than its configured
// timeout_hours. It is a stateless polling worker; cron the Run method
// from the workflow engine binary on a fixed interval (e.g. every
// minute).
//
// The checker takes a Now func so tests can inject a fixed time. In
// production wire it to time.Now.
type EscalationChecker struct {
	db        *gorm.DB
	escalator Escalator
	now       func() time.Time
}

// NewEscalationChecker constructs a checker. now may be nil in which
// case time.Now is used.
func NewEscalationChecker(db *gorm.DB, escalator Escalator, now func() time.Time) *EscalationChecker {
	if now == nil {
		now = time.Now
	}
	return &EscalationChecker{db: db, escalator: escalator, now: now}
}

// Run executes one polling pass: load all access_requests in
// RequestStateRequested whose linked workflow's first non-approved
// step has elapsed past its timeout, and call Escalator.Escalate for
// each.
//
// Run is idempotent in the sense that a second call within the same
// poll window will re-emit the same escalations; the Escalator
// implementation is responsible for de-duping (e.g. by writing a
// state-history row only once per (request, step) pair).
//
// Returns the number of escalations triggered.
func (c *EscalationChecker) Run(ctx context.Context) (int, error) {
	var requests []models.AccessRequest
	if err := c.db.WithContext(ctx).
		Where("state = ? AND workflow_id IS NOT NULL", models.RequestStateRequested).
		Find(&requests).Error; err != nil {
		return 0, fmt.Errorf("workflow_engine: list pending requests: %w", err)
	}

	count := 0
	for i := range requests {
		req := &requests[i]
		if req.WorkflowID == nil {
			continue
		}
		var wf models.AccessWorkflow
		err := c.db.WithContext(ctx).Where("id = ?", *req.WorkflowID).First(&wf).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return count, fmt.Errorf("workflow_engine: load workflow %s: %w", *req.WorkflowID, err)
		}
		from, to, ok, err := c.escalationTargets(req, &wf)
		if err != nil {
			return count, err
		}
		if !ok {
			continue
		}
		if err := c.escalator.Escalate(ctx, req, &wf, from, to); err != nil {
			return count, fmt.Errorf("workflow_engine: escalate %s: %w", req.ID, err)
		}
		count++
	}
	return count, nil
}

// escalationTargets returns (fromRole, toRole, shouldEscalate, error)
// for the given request. It picks the FIRST step in wf.Steps as the
// "currently pending" step (Phase 2/8 only marks the first step
// pending; multi-step pipelines escalate one level at a time).
//
// shouldEscalate is true iff:
//
//  1. the step has a positive timeout_hours, and
//  2. the request's UpdatedAt is older than now - timeout_hours, and
//  3. the step has either an escalation_target or, for multi_level, at
//     least one Level beyond the first.
func (c *EscalationChecker) escalationTargets(req *models.AccessRequest, wf *models.AccessWorkflow) (string, string, bool, error) {
	steps, err := DecodeSteps(wf.Steps)
	if err != nil {
		return "", "", false, err
	}
	if len(steps) == 0 {
		return "", "", false, nil
	}
	step := steps[0]

	if step.Type == models.WorkflowStepMultiLevel {
		if len(step.Levels) < 2 {
			return "", "", false, nil
		}
		first := step.Levels[0]
		next := step.Levels[1]
		if first.TimeoutHours <= 0 {
			return "", "", false, nil
		}
		deadline := req.UpdatedAt.Add(time.Duration(first.TimeoutHours) * time.Hour)
		if c.now().Before(deadline) {
			return "", "", false, nil
		}
		return first.Role, next.Role, true, nil
	}

	if step.TimeoutHours <= 0 || step.EscalationTarget == "" {
		return "", "", false, nil
	}
	deadline := req.UpdatedAt.Add(time.Duration(step.TimeoutHours) * time.Hour)
	if c.now().Before(deadline) {
		return "", "", false, nil
	}
	return step.Type, step.EscalationTarget, true, nil
}
