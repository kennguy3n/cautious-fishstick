package workflow_engine

import (
	"context"
	"fmt"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stepAutoApprove implements the auto_approve step. It calls
// Performer.Approve (which production wires to AccessRequestService) and
// returns StepApprove. A nil request is tolerated — Performer is
// expected to no-op on nil.
func (e *WorkflowExecutor) stepAutoApprove(ctx context.Context, req *models.AccessRequest) (StepDecision, string, error) {
	if err := e.performer.Approve(ctx, req, "auto-approved by workflow engine"); err != nil {
		return "", "", fmt.Errorf("auto_approve: %w", err)
	}
	return StepApprove, "", nil
}

// stepManagerApproval implements the manager_approval step: mark the
// request pending so the manager UI picks it up, and return
// StepPending. The executor halts the walk on pending.
func (e *WorkflowExecutor) stepManagerApproval(ctx context.Context, req *models.AccessRequest) (StepDecision, string, error) {
	if err := e.performer.MarkPending(ctx, req, models.WorkflowStepManagerApproval, "awaiting manager approval"); err != nil {
		return "", "", fmt.Errorf("manager_approval: %w", err)
	}
	return StepPending, "awaiting manager approval", nil
}

// stepSecurityReview implements the security_review step: identical
// shape to manager_approval but visible to the security review queue
// instead of the manager queue.
func (e *WorkflowExecutor) stepSecurityReview(ctx context.Context, req *models.AccessRequest) (StepDecision, string, error) {
	if err := e.performer.MarkPending(ctx, req, models.WorkflowStepSecurityReview, "awaiting security review"); err != nil {
		return "", "", fmt.Errorf("security_review: %w", err)
	}
	return StepPending, "awaiting security review", nil
}

// stepMultiLevel implements the multi_level step. The Phase 8 executor
// only marks the FIRST level pending; subsequent levels are
// runtime-evaluated by EscalationChecker on timeout. Returning
// StepPending is intentional — the request stays in
// RequestStateRequested until either the level approves or its timeout
// fires, at which point EscalationChecker advances to the next level.
func (e *WorkflowExecutor) stepMultiLevel(ctx context.Context, req *models.AccessRequest, step models.WorkflowStepDefinition) (StepDecision, string, error) {
	if len(step.Levels) == 0 {
		return "", "", fmt.Errorf("multi_level: no levels configured")
	}
	first := step.Levels[0]
	reason := fmt.Sprintf("awaiting %s approval (multi_level level 1/%d)", first.Role, len(step.Levels))
	if err := e.performer.MarkPending(ctx, req, models.WorkflowStepMultiLevel, reason); err != nil {
		return "", "", fmt.Errorf("multi_level: %w", err)
	}
	return StepPending, reason, nil
}
