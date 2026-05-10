package workflow_engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// StepDecision is the outcome of executing a single workflow step.
// Strings are stable across versions and may appear in audit logs.
type StepDecision string

const (
	// StepApprove means the step approved the request. The executor
	// stops walking subsequent steps and the caller is expected to
	// flip the request to RequestStateApproved.
	StepApprove StepDecision = "approve"
	// StepDeny means the step rejected the request. Terminal —
	// subsequent steps do NOT run.
	StepDeny StepDecision = "deny"
	// StepEscalate means this step's timeout elapsed and the request
	// was bumped to escalation_target (or the next multi_level
	// level). The executor returns the escalate decision so the
	// EscalationChecker can record it; subsequent steps in the
	// current step list do NOT run.
	StepEscalate StepDecision = "escalate"
	// StepPending means the step is awaiting human input and the
	// request stays in RequestStateRequested. Subsequent steps do NOT
	// run; this is a normal "halt and wait" state.
	StepPending StepDecision = "pending"
)

// ExecutionResult is what WorkflowExecutor.Execute returns: the final
// StepDecision and the index of the step that produced it.
type ExecutionResult struct {
	Decision  StepDecision `json:"decision"`
	StepIndex int          `json:"step_index"`
	StepType  string       `json:"step_type"`
	// Reason is a free-form human-readable string. Populated for
	// errors and for escalate decisions; empty otherwise.
	Reason string `json:"reason,omitempty"`
}

// ErrWorkflowNotFound is returned when Execute cannot locate the
// requested workflow row.
var ErrWorkflowNotFound = errors.New("workflow_engine: workflow not found")

// ErrStepUnknown is returned when a workflow contains a step type the
// executor doesn't recognise.
var ErrStepUnknown = errors.New("workflow_engine: unknown step type")

// ErrInvalidRequest is returned when Execute is called with a missing /
// blank workflow_id.
var ErrInvalidRequest = errors.New("workflow_engine: invalid execute request")

// StepPerformer is the small contract the executor needs from the
// outside world to actually act on a decision. The cmd binary wires
// this to AccessRequestService.ApproveRequest etc; tests inject a fake
// that records calls in a slice.
//
// All methods take a context, the AccessRequest being acted on, and a
// human-visible reason. The executor never persists state itself — it
// delegates so request state-history rows are written by the same
// service that owns the AccessRequest table.
type StepPerformer interface {
	// Approve flips the request to RequestStateApproved. Called for
	// auto_approve and on manager_approval / security_review steps
	// that pre-evaluate to approve (e.g. bulk-approval).
	Approve(ctx context.Context, req *models.AccessRequest, reason string) error
	// MarkPending leaves the request in RequestStateRequested and
	// records that we're waiting on humans. The default no-op
	// implementation is fine for most callers; production wires this
	// to a notification side-effect.
	MarkPending(ctx context.Context, req *models.AccessRequest, stepType, reason string) error
}

// WorkflowExecutor loads an AccessWorkflow row, walks its steps, and
// returns the resulting ExecutionResult. The executor short-circuits on
// the first non-approve decision: approve advances, deny / escalate /
// pending stop and propagate.
//
// The Phase 8 executor handles step types:
//
//	auto_approve     → calls Performer.Approve, returns approve.
//	manager_approval → calls Performer.MarkPending, returns pending.
//	security_review  → calls Performer.MarkPending, returns pending.
//	multi_level      → walks the configured Levels; the FIRST level is
//	                   marked pending (manager) and subsequent levels
//	                   are executed by EscalationChecker on timeout.
//
// Each step type is implemented as a method on the executor returning
// (StepDecision, error) — see step_*.go in the same package.
type WorkflowExecutor struct {
	db        *gorm.DB
	performer StepPerformer
}

// NewWorkflowExecutor returns an executor backed by db and performer.
// performer must be non-nil (use NoOpPerformer in tests).
func NewWorkflowExecutor(db *gorm.DB, performer StepPerformer) *WorkflowExecutor {
	if performer == nil {
		performer = NoOpPerformer{}
	}
	return &WorkflowExecutor{db: db, performer: performer}
}

// ExecuteRequest is the inbound shape from POST /workflows/execute.
// Context carries arbitrary key/value pairs (resource tags, requester
// metadata, etc.); the executor only inspects WorkflowID + RequestID.
type ExecuteRequest struct {
	RequestID  string                 `json:"request_id"`
	WorkflowID string                 `json:"workflow_id"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// Validate returns an error if the request is missing required fields.
func (r *ExecuteRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: request body is required", ErrInvalidRequest)
	}
	if r.WorkflowID == "" {
		return fmt.Errorf("%w: workflow_id is required", ErrInvalidRequest)
	}
	return nil
}

// Execute loads the workflow_id'd row from the DB and walks its steps.
// The matched AccessRequest is loaded only when RequestID is non-empty;
// step bodies that don't need it (auto_approve in tests) tolerate a nil
// request.
func (e *WorkflowExecutor) Execute(ctx context.Context, req *ExecuteRequest) (*ExecutionResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	var wf models.AccessWorkflow
	tx := e.db.WithContext(ctx).Where("id = ?", req.WorkflowID).First(&wf)
	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrWorkflowNotFound, req.WorkflowID)
	}
	if tx.Error != nil {
		return nil, fmt.Errorf("workflow_engine: load workflow %s: %w", req.WorkflowID, tx.Error)
	}

	var areq *models.AccessRequest
	if req.RequestID != "" {
		var loaded models.AccessRequest
		if err := e.db.WithContext(ctx).Where("id = ?", req.RequestID).First(&loaded).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// A missing request row is not fatal — the
				// caller may be replaying a workflow definition
				// in a test/dry-run context. Continue with nil.
				areq = nil
			} else {
				return nil, fmt.Errorf("workflow_engine: load request %s: %w", req.RequestID, err)
			}
		} else {
			areq = &loaded
		}
	}

	steps, err := DecodeSteps(wf.Steps)
	if err != nil {
		return nil, err
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("%w: workflow %s has no steps", ErrStepUnknown, wf.ID)
	}

	for i, step := range steps {
		decision, reason, err := e.runStep(ctx, areq, step)
		if err != nil {
			return nil, fmt.Errorf("workflow_engine: step %d (%s): %w", i, step.Type, err)
		}
		if decision == StepApprove {
			continue
		}
		// Any non-approve decision halts the walk.
		return &ExecutionResult{
			Decision:  decision,
			StepIndex: i,
			StepType:  step.Type,
			Reason:    reason,
		}, nil
	}
	// All steps approved.
	return &ExecutionResult{
		Decision:  StepApprove,
		StepIndex: len(steps) - 1,
		StepType:  steps[len(steps)-1].Type,
	}, nil
}

// DecodeSteps unmarshals AccessWorkflow.Steps into a typed slice.
// Exported because EscalationChecker also needs it.
func DecodeSteps(raw []byte) ([]models.WorkflowStepDefinition, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var steps []models.WorkflowStepDefinition
	if err := json.Unmarshal(raw, &steps); err != nil {
		return nil, fmt.Errorf("workflow_engine: decode steps: %w", err)
	}
	return steps, nil
}

// runStep dispatches one step to its handler. Lives on WorkflowExecutor
// so step handlers can reuse e.performer.
func (e *WorkflowExecutor) runStep(ctx context.Context, req *models.AccessRequest, step models.WorkflowStepDefinition) (StepDecision, string, error) {
	switch step.Type {
	case models.WorkflowStepAutoApprove:
		return e.stepAutoApprove(ctx, req)
	case models.WorkflowStepManagerApproval:
		return e.stepManagerApproval(ctx, req)
	case models.WorkflowStepSecurityReview:
		return e.stepSecurityReview(ctx, req)
	case models.WorkflowStepMultiLevel:
		return e.stepMultiLevel(ctx, req, step)
	default:
		return "", "", fmt.Errorf("%w: %q", ErrStepUnknown, step.Type)
	}
}

// NoOpPerformer is a StepPerformer that records nothing — useful for
// tests that don't care about side-effects.
type NoOpPerformer struct{}

// Approve is a no-op.
func (NoOpPerformer) Approve(_ context.Context, _ *models.AccessRequest, _ string) error {
	return nil
}

// MarkPending is a no-op.
func (NoOpPerformer) MarkPending(_ context.Context, _ *models.AccessRequest, _, _ string) error {
	return nil
}

var _ StepPerformer = NoOpPerformer{}
