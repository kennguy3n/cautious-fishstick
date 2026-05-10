package workflow_engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// RetryPolicy configures the executor's per-step retry behaviour
// (Phase 8 Task 5). MaxAttempts is inclusive of the first attempt;
// MaxAttempts=1 disables retry. BaseBackoff is the initial sleep
// before the SECOND attempt; subsequent retries double until
// MaxBackoff.
type RetryPolicy struct {
	// MaxAttempts caps the number of attempts per step. Defaults to
	// 3 if zero / negative is supplied.
	MaxAttempts int
	// BaseBackoff is the sleep before retry #2. Defaults to 100ms if
	// zero is supplied.
	BaseBackoff time.Duration
	// MaxBackoff caps exponential growth. Defaults to 5s.
	MaxBackoff time.Duration
}

// DefaultRetryPolicy returns the production retry policy. 3 attempts,
// 100ms → 200ms → 400ms exponential backoff capped at 5s.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 3,
		BaseBackoff: 100 * time.Millisecond,
		MaxBackoff:  5 * time.Second,
	}
}

func (p RetryPolicy) normalised() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 3
	}
	if p.BaseBackoff <= 0 {
		p.BaseBackoff = 100 * time.Millisecond
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = 5 * time.Second
	}
	return p
}

// nextBackoff returns the sleep duration before attempt N (1-indexed,
// so attempt=2 → BaseBackoff). Caps at MaxBackoff. Returns 0 for the
// first attempt.
func (p RetryPolicy) nextBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 0
	}
	d := p.BaseBackoff
	for i := 2; i < attempt; i++ {
		d *= 2
		if d > p.MaxBackoff {
			return p.MaxBackoff
		}
	}
	return d
}

// SetRetryPolicy overrides the executor's retry policy. Tests use
// this to pin attempt counts; production wires this only when the
// default 3-attempt policy is too aggressive (e.g. very chatty
// downstream).
func (e *WorkflowExecutor) SetRetryPolicy(p RetryPolicy) {
	e.retryPolicy = p.normalised()
}

// SetSleeper overrides the time.Sleep equivalent used between retry
// attempts. Tests pin this to a no-op so retry tests don't actually
// sleep; production leaves it nil to use the real time.Sleep.
func (e *WorkflowExecutor) SetSleeper(fn func(time.Duration)) {
	e.sleep = fn
}

// runStepWithRetry wraps runStep with the configured retry policy.
// Errors are retried up to MaxAttempts; the executor sleeps
// BaseBackoff * 2^(attempt-2) between attempts (capped at MaxBackoff).
//
// Returns the LAST observed error after exhausting attempts, or
// (decision, reason, nil) on the first successful attempt. The
// attempt count is recorded on the step-history row by the caller via
// updateStepHistoryAttempts so operator dashboards can surface
// flapping steps.
func (e *WorkflowExecutor) runStepWithRetry(
	ctx context.Context,
	req *models.AccessRequest,
	step models.WorkflowStepDefinition,
) (StepDecision, string, int, error) {
	policy := e.effectiveRetryPolicy()
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if attempt > 1 {
			delay := policy.nextBackoff(attempt)
			if delay > 0 {
				if e.sleep != nil {
					e.sleep(delay)
				} else {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return "", "", attempt, ctx.Err()
					}
				}
			}
		}
		decision, reason, err := e.runStep(ctx, req, step)
		if err == nil {
			return decision, reason, attempt, nil
		}
		// Unknown step type is a configuration error, not a
		// transient downstream failure; do not retry.
		if errors.Is(err, ErrStepUnknown) {
			return "", "", attempt, err
		}
		lastErr = err
		log.Printf("workflow_engine: step %s attempt %d/%d failed: %v", step.Type, attempt, policy.MaxAttempts, err)
	}
	return "", "", policy.MaxAttempts, fmt.Errorf("workflow_engine: step %s exhausted %d attempts: %w", step.Type, policy.MaxAttempts, lastErr)
}

func (e *WorkflowExecutor) effectiveRetryPolicy() RetryPolicy {
	if e.retryPolicy.MaxAttempts == 0 {
		return DefaultRetryPolicy()
	}
	return e.retryPolicy
}

// ListFailedSteps returns the most recent failed step rows for the
// supplied request, newest first. Operators query this to triage
// stuck workflow runs (Phase 8 Task 5: DLQ).
//
// limit caps the number of rows returned (defaults to 50 if zero or
// negative). The rows are ordered by started_at DESC so the most
// recent failure is first.
func (e *WorkflowExecutor) ListFailedSteps(ctx context.Context, requestID string, limit int) ([]models.AccessWorkflowStepHistory, error) {
	if requestID == "" {
		return nil, fmt.Errorf("workflow_engine: ListFailedSteps: empty request_id")
	}
	if limit <= 0 {
		limit = 50
	}
	var rows []models.AccessWorkflowStepHistory
	err := e.db.WithContext(ctx).
		Where("request_id = ? AND status = ?", requestID, models.WorkflowStepStatusFailed).
		Order("started_at DESC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("workflow_engine: list failed steps for %s: %w", requestID, err)
	}
	return rows, nil
}

// ListAllFailedSteps returns the most recent failed step rows across
// every request. Used by the operator-facing dashboard to surface
// platform-wide DLQ depth. limit caps the number of rows; defaults to
// 100.
func (e *WorkflowExecutor) ListAllFailedSteps(ctx context.Context, limit int) ([]models.AccessWorkflowStepHistory, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows []models.AccessWorkflowStepHistory
	err := e.db.WithContext(ctx).
		Where("status = ?", models.WorkflowStepStatusFailed).
		Order("started_at DESC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("workflow_engine: list all failed steps: %w", err)
	}
	return rows, nil
}

// startStepHistory inserts a pending row into
// access_workflow_step_history capturing the executor entering the
// supplied step. Returns the row ID so subsequent updates can mutate
// status/completed_at/notes on the same row.
//
// Errors are surfaced (history is the durable record of a workflow
// run, so a failure to start the row is a bug operators must see).
// Empty requestID is tolerated and the function returns "" — the
// executor uses this for replay/dry-run paths.
func (e *WorkflowExecutor) startStepHistory(
	ctx context.Context,
	requestID, workflowID string,
	stepIndex int,
	stepType string,
) (string, error) {
	if requestID == "" {
		return "", nil
	}
	row := &models.AccessWorkflowStepHistory{
		ID:         newPerformerULID(),
		RequestID:  requestID,
		WorkflowID: workflowID,
		StepIndex:  stepIndex,
		StepType:   stepType,
		Status:     models.WorkflowStepStatusPending,
		StartedAt:  time.Now().UTC(),
		Attempts:   1,
		CreatedAt:  time.Now().UTC(),
	}
	if err := e.db.WithContext(ctx).Create(row).Error; err != nil {
		return "", fmt.Errorf("workflow_engine: insert step history: %w", err)
	}
	return row.ID, nil
}

// finishStepHistory updates the supplied step-history row to its
// final state. status MUST be one of the WorkflowStepStatus*
// constants. notes is the human-visible reason / error string.
//
// A blank rowID is tolerated so callers (replay / dry-run) can call
// finishStepHistory unconditionally.
func (e *WorkflowExecutor) finishStepHistory(
	ctx context.Context,
	rowID string,
	status, notes string,
	attempts int,
) error {
	if rowID == "" {
		return nil
	}
	updates := map[string]interface{}{
		"status":       status,
		"completed_at": time.Now().UTC(),
		"notes":        notes,
		"attempts":     attempts,
	}
	if err := e.db.WithContext(ctx).
		Model(&models.AccessWorkflowStepHistory{}).
		Where("id = ?", rowID).
		Updates(updates).Error; err != nil {
		// Best-effort: log and swallow. The pending row is already
		// in the table; an operator can find it even with stale
		// status. Returning here would mask the underlying step
		// outcome.
		log.Printf("workflow_engine: finish step history %s: %v", rowID, err)
	}
	return nil
}

// stepHistoryAvailable returns true when the executor's DB has an
// access_workflow_step_history table. Some executor unit tests only
// migrate the bare AccessRequest / AccessWorkflow tables; we want the
// executor to skip the audit-row write in that case rather than fail
// the whole step.
func (e *WorkflowExecutor) stepHistoryAvailable() bool {
	if e == nil || e.db == nil {
		return false
	}
	if e.stepHistoryChecked {
		return e.stepHistoryOK
	}
	e.stepHistoryChecked = true
	e.stepHistoryOK = e.db.Migrator().HasTable(&models.AccessWorkflowStepHistory{})
	return e.stepHistoryOK
}

// SilenceLogs is intentionally unused. Documented as a no-op hook so
// future logging refactors that gate test output can flip the
// executor's verbosity without touching call sites.
func (e *WorkflowExecutor) SilenceLogs(_ bool) {}
