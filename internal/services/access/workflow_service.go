package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// WorkflowService is the Phase 2 routing layer that decides what happens
// after a request enters RequestStateRequested. Two responsibilities:
//
//   - ResolveWorkflow finds the first AccessWorkflow whose match_rule
//     matches the request. Falls through to nil if no rule matches; the
//     caller's policy then decides whether "no workflow" means
//     auto-deny, manager-approval, or queue for AI scoring.
//   - ExecuteWorkflow runs the matched workflow's steps. Phase 2 supports
//     two step types — auto_approve and manager_approval — which is
//     enough to power self-service and single-step manager flows.
//
// WorkflowService depends on RequestApprover (an interface satisfied by
// AccessRequestService) so tests can inject a fake without spinning up the
// full request service.
type WorkflowService struct {
	db         *gorm.DB
	requestSvc RequestApprover
}

// RequestApprover is the subset of AccessRequestService that
// WorkflowService actually calls. Defining it here keeps the dependency
// loose and lets tests stub the service with a one-liner.
type RequestApprover interface {
	ApproveRequest(ctx context.Context, requestID, actorUserID, reason string) error
}

// NewWorkflowService returns a service backed by db. requestSvc is the
// approver — typically an *AccessRequestService.
func NewWorkflowService(db *gorm.DB, requestSvc RequestApprover) *WorkflowService {
	return &WorkflowService{db: db, requestSvc: requestSvc}
}

// SensitiveResourceRiskFactor is the canonical RiskFactors entry the
// AI agent emits when a request targets a resource tagged sensitive.
// Phase 8 risk routing treats this factor as a forced escalation to
// security_review regardless of risk score (mirrors workflow_engine.SensitiveTag).
const SensitiveResourceRiskFactor = "sensitive_resource"

// WorkflowResolution is the result of risk-aware workflow resolution.
// One of `Workflow` (a row in access_workflows) or `SyntheticType` is
// populated; the latter encodes "no DB workflow matched, but risk
// routing has spoken — synthesize a workflow of this type at execute
// time".
type WorkflowResolution struct {
	// Workflow is the matched access_workflows row, or nil.
	Workflow *models.AccessWorkflow
	// SyntheticType is the step type a fall-through risk router
	// suggested when no DB workflow matched. Empty when Workflow is
	// non-nil.
	SyntheticType string
	// Reason is a human-readable string explaining the resolution
	// (e.g. "matched workflow X", "risk=high → security_review").
	Reason string
}

// matchRule encodes the JSON shape understood by Phase 2's matcher. All
// fields are optional; an empty rule matches every request in the
// workspace.
//
// Phase 4 may extend this to include risk_score buckets and group
// membership; until then keep this struct in lockstep with
// docs/ARCHITECTURE.md §10.
type matchRule struct {
	ConnectorID     string `json:"connector_id,omitempty"`
	Role            string `json:"role,omitempty"`
	ResourcePattern string `json:"resource_pattern,omitempty"`
}

// workflowStep is one entry in AccessWorkflow.Steps. Phase 2 only cares
// about the type column; Phase 5+ may add fields like approver_pool_id,
// timeout_seconds, etc.
type workflowStep struct {
	Type string `json:"type"`
}

// ErrWorkflowExecution is returned when ExecuteWorkflow fails to act on
// the matched workflow (e.g. manager_approval cannot be expressed yet, or
// the steps JSON is malformed).
var ErrWorkflowExecution = errors.New("access: workflow execution failed")

// ResolveWorkflow finds the first active workflow in the request's
// workspace whose match_rule matches the request. Returns (nil, nil) when
// no workflow matches — that is a valid result and means "no auto-routing
// rule applies, escalate per default policy".
//
// Workflows are evaluated in CreatedAt order (oldest first) and the
// FIRST match wins. This is strictly chronological — there is no
// priority/specificity scoring in Phase 2. Admins who want a narrower
// rule to override a broader, older one MUST either:
//
//   - delete the older workflow, or
//   - deactivate it (IsActive = false) so the query skips it.
//
// Inserting a more specific workflow LATER does NOT override an earlier
// broad rule, because the older row is found first and the loop returns
// on first match. Phase 4 will introduce explicit priority/specificity
// ordering (longest-prefix-match style); until then ResolveWorkflow's
// behaviour is "oldest active matching rule wins, full stop".
func (s *WorkflowService) ResolveWorkflow(ctx context.Context, request *models.AccessRequest) (*models.AccessWorkflow, error) {
	if request == nil {
		return nil, fmt.Errorf("%w: request is required", ErrValidation)
	}

	var workflows []models.AccessWorkflow
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND is_active = ?", request.WorkspaceID, true).
		Order("created_at asc").
		Find(&workflows).Error; err != nil {
		return nil, fmt.Errorf("access: list access_workflows: %w", err)
	}

	for i := range workflows {
		wf := &workflows[i]
		match, err := workflowMatches(wf, request)
		if err != nil {
			return nil, err
		}
		if match {
			return wf, nil
		}
	}
	return nil, nil
}

// ResolveWorkflowWithRisk wraps ResolveWorkflow with the Phase 8 risk
// router: when no DB workflow matches, the router classifies the
// request by RiskScore + RiskFactors and picks a synthetic step type.
//
// Routing table (mirrors workflow_engine.RiskRouter.Route):
//
//	risk_factors contains "sensitive_resource"  → security_review (forced)
//	risk_score = "high"                         → security_review
//	risk_score = "medium" or unknown            → manager_approval (fail-safe)
//	risk_score = "low"                          → auto_approve   (self_service)
//
// Returns a WorkflowResolution. Callers ExecuteWorkflow against
// resolution.Workflow when non-nil; otherwise they synthesize a
// single-step workflow with type = resolution.SyntheticType.
func (s *WorkflowService) ResolveWorkflowWithRisk(ctx context.Context, request *models.AccessRequest) (*WorkflowResolution, error) {
	wf, err := s.ResolveWorkflow(ctx, request)
	if err != nil {
		return nil, err
	}
	if wf != nil {
		return &WorkflowResolution{
			Workflow: wf,
			Reason:   fmt.Sprintf("matched workflow %s", wf.ID),
		}, nil
	}
	if request == nil {
		return nil, fmt.Errorf("%w: request is required", ErrValidation)
	}
	tags := decodeRiskFactors(request.RiskFactors)
	stepType, reason := riskRoute(request.RiskScore, tags)
	return &WorkflowResolution{
		SyntheticType: stepType,
		Reason:        reason,
	}, nil
}

// decodeRiskFactors safely decodes AccessRequest.RiskFactors into a
// []string. Empty / malformed payloads decode to nil.
func decodeRiskFactors(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var factors []string
	if err := json.Unmarshal(raw, &factors); err != nil {
		return nil
	}
	return factors
}

// riskRoute maps (riskScore, factors) to the workflow step type the
// Phase 8 router would choose. Kept package-internal so external
// callers go through ResolveWorkflowWithRisk.
//
// The string returned is one of:
//   - models.WorkflowStepAutoApprove     (low → self_service)
//   - models.WorkflowStepManagerApproval (medium / unknown)
//   - models.WorkflowStepSecurityReview  (high or sensitive)
func riskRoute(riskScore string, factors []string) (string, string) {
	for _, f := range factors {
		if strings.EqualFold(strings.TrimSpace(f), SensitiveResourceRiskFactor) {
			return models.WorkflowStepSecurityReview, "risk_factor=sensitive_resource → security_review"
		}
	}
	switch strings.TrimSpace(strings.ToLower(riskScore)) {
	case models.RequestRiskLow:
		return models.WorkflowStepAutoApprove, "risk=low → self_service"
	case models.RequestRiskHigh:
		return models.WorkflowStepSecurityReview, "risk=high → security_review"
	case models.RequestRiskMedium:
		return models.WorkflowStepManagerApproval, "risk=medium → manager_approval"
	default:
		return models.WorkflowStepManagerApproval, "risk=unknown → manager_approval (fail-safe)"
	}
}

// ExecuteWorkflow runs the matched workflow's first step. Phase 2 only
// honours auto_approve and manager_approval; an unrecognised step type
// returns ErrWorkflowExecution so misconfigured workflows fail loudly.
//
// Behaviour table:
//
//	workflow == nil                  → call ApproveRequest (caller chose auto)
//	first step == auto_approve       → call ApproveRequest
//	first step == manager_approval   → no-op, request stays in "requested"
//	first step is anything else      → ErrWorkflowExecution
//
// actorUserID and reason are forwarded to ApproveRequest. Callers should
// pass the auto-approver's "system" user ID and a reason like
// "auto-approved by workflow <id>".
func (s *WorkflowService) ExecuteWorkflow(
	ctx context.Context,
	request *models.AccessRequest,
	workflow *models.AccessWorkflow,
	actorUserID string,
	reason string,
) error {
	if request == nil {
		return fmt.Errorf("%w: request is required", ErrValidation)
	}

	// No matching workflow → fall back to auto-approve. This is the
	// "self-service when a policy match exists, but if no policy at all
	// exists default to letting it through" behaviour the caller asked
	// for. Callers that want a different fallback (e.g. auto-deny) can
	// inspect ResolveWorkflow's nil return and implement their own
	// policy without calling ExecuteWorkflow.
	if workflow == nil {
		return s.requestSvc.ApproveRequest(ctx, request.ID, actorUserID, reason)
	}

	step, err := firstStepType(workflow)
	if err != nil {
		return err
	}

	switch step {
	case models.WorkflowStepAutoApprove:
		return s.requestSvc.ApproveRequest(ctx, request.ID, actorUserID, reason)
	case models.WorkflowStepManagerApproval,
		models.WorkflowStepSecurityReview,
		models.WorkflowStepMultiLevel:
		// Leave the request in RequestStateRequested. The manager,
		// security reviewer, or first multi_level approver will flip
		// it via API when they act. Phase 8 introduces escalation
		// timers that may rewrite this row later via
		// EscalationChecker, but ExecuteWorkflow is synchronous and
		// has nothing to do here.
		return nil
	default:
		return fmt.Errorf("%w: unknown step type %q", ErrWorkflowExecution, step)
	}
}

// workflowMatches reports whether wf.MatchRule applies to request.
// Empty / unset fields in the rule are wildcards. Returns an error if the
// match_rule JSON is malformed — callers treat that as a hard error
// (better than silently skipping the workflow).
func workflowMatches(wf *models.AccessWorkflow, request *models.AccessRequest) (bool, error) {
	rule, err := parseMatchRule(wf.MatchRule)
	if err != nil {
		return false, fmt.Errorf("%w: workflow %s match_rule: %v", ErrWorkflowExecution, wf.ID, err)
	}
	if rule.ConnectorID != "" && rule.ConnectorID != request.ConnectorID {
		return false, nil
	}
	if rule.Role != "" && rule.Role != request.Role {
		return false, nil
	}
	if rule.ResourcePattern != "" {
		matched, perr := path.Match(rule.ResourcePattern, request.ResourceExternalID)
		if perr != nil {
			return false, fmt.Errorf("%w: workflow %s resource_pattern %q: %v", ErrWorkflowExecution, wf.ID, rule.ResourcePattern, perr)
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

// parseMatchRule unmarshals the bytes (which may be nil or empty for a
// "match everything" workflow) into a matchRule struct.
func parseMatchRule(raw []byte) (matchRule, error) {
	if len(raw) == 0 {
		return matchRule{}, nil
	}
	var rule matchRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return rule, err
	}
	return rule, nil
}

// firstStepType returns the "type" field of the first entry in
// wf.Steps. An empty Steps array or malformed JSON is a hard error.
func firstStepType(wf *models.AccessWorkflow) (string, error) {
	if len(wf.Steps) == 0 {
		return "", fmt.Errorf("%w: workflow %s has no steps", ErrWorkflowExecution, wf.ID)
	}
	var steps []workflowStep
	if err := json.Unmarshal(wf.Steps, &steps); err != nil {
		return "", fmt.Errorf("%w: workflow %s steps: %v", ErrWorkflowExecution, wf.ID, err)
	}
	if len(steps) == 0 {
		return "", fmt.Errorf("%w: workflow %s steps array is empty", ErrWorkflowExecution, wf.ID)
	}
	return steps[0].Type, nil
}
