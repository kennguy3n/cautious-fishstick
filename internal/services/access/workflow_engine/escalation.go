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
// Run is idempotent across polling passes: escalationTargets
// consults each request's LastEscalatedAt + EscalationLevel and skips
// requests that have already been escalated within the current
// timeout window. The Escalator implementation provides a second
// layer of defence with a CAS update on EscalationLevel so concurrent
// pollers (or a manually-triggered Run during a scheduled Run) cannot
// double-emit.
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
// The dedup window is keyed off req.LastEscalatedAt: for the first
// escalation we measure from req.UpdatedAt; for subsequent
// escalations on a multi_level workflow we measure from the previous
// escalation. EscalationLevel is the index of the level the request
// is currently waiting on — 0 means we have not escalated yet, N>0
// means we have already escalated N times and are waiting on
// Levels[N].
//
// shouldEscalate is true iff:
//
//  1. the active level / step has a positive timeout_hours, and
//  2. the time since the last state-changing event (UpdatedAt or
//     LastEscalatedAt) has exceeded that timeout, and
//  3. there is somewhere to escalate to — escalation_target for
//     single-target steps, or Levels[level+1] for multi_level.
func (c *EscalationChecker) escalationTargets(req *models.AccessRequest, wf *models.AccessWorkflow) (string, string, bool, error) {
	steps, err := DecodeSteps(wf.Steps)
	if err != nil {
		return "", "", false, err
	}
	if len(steps) == 0 {
		return "", "", false, nil
	}
	step := steps[0]
	baseTime := req.UpdatedAt
	if req.LastEscalatedAt != nil {
		baseTime = *req.LastEscalatedAt
	}

	if step.Type == models.WorkflowStepMultiLevel {
		levels := step.Levels
		if len(levels) < 2 {
			return "", "", false, nil
		}
		level := req.EscalationLevel
		if level < 0 {
			level = 0
		}
		// We can only escalate from level N to level N+1; if we
		// have already escalated through the last level there is
		// nothing more to do.
		if level >= len(levels)-1 {
			return "", "", false, nil
		}
		current := levels[level]
		next := levels[level+1]
		if current.TimeoutHours <= 0 {
			return "", "", false, nil
		}
		deadline := baseTime.Add(time.Duration(current.TimeoutHours) * time.Hour)
		if c.now().Before(deadline) {
			return "", "", false, nil
		}
		return current.Role, next.Role, true, nil
	}

	if step.TimeoutHours <= 0 || step.EscalationTarget == "" {
		return "", "", false, nil
	}
	// Single-target steps escalate at most once: the request moves
	// from `step.Type` to `step.EscalationTarget` and there is no
	// further hop to take. Re-firing on the next poll would just
	// pile up audit rows.
	if req.EscalationLevel > 0 {
		return "", "", false, nil
	}
	deadline := baseTime.Add(time.Duration(step.TimeoutHours) * time.Hour)
	if c.now().Before(deadline) {
		return "", "", false, nil
	}
	return step.Type, step.EscalationTarget, true, nil
}
