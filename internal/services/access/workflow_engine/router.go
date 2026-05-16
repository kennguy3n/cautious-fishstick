// Package workflow_engine implements the Phase 8 LangGraph-style
// workflow orchestration host: risk-based routing, multi-step
// execution, and timeout-driven escalation.
//
// The engine is a separate package (rather than living in
// internal/services/access) so the access-workflow-engine binary can
// pull in the orchestration code without dragging in the full
// connector registry's network surface, and so the executor's
// dependencies (a "step performer" interface) stay loose enough for
// tests to substitute.
package workflow_engine

import (
	"strings"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// RiskBucket is the coarse risk classification the engine uses to pick a
// workflow type. Mirrors models.RequestRiskLow / Medium / High but
// declared here as a typed alias to make the routing API self-contained.
type RiskBucket string

const (
	// RiskLow maps to the self_service workflow (auto-approve).
	RiskLow RiskBucket = "low"
	// RiskMedium maps to the manager_approval workflow.
	RiskMedium RiskBucket = "medium"
	// RiskHigh maps to the security_review workflow.
	RiskHigh RiskBucket = "high"
)

// WorkflowType is the result of risk routing. Strings are stable across
// versions and may be persisted to logs / audit rows.
type WorkflowType string

const (
	// WorkflowSelfService routes a low-risk request straight to
	// auto-approve. No human is in the loop.
	WorkflowSelfService WorkflowType = "self_service"
	// WorkflowManagerApproval routes a medium-risk request to the
	// requester's manager. One approver, one decision.
	WorkflowManagerApproval WorkflowType = "manager_approval"
	// WorkflowSecurityReview routes a high-risk OR resource-tagged-
	// sensitive request to the security review queue. Always involves
	// the security team regardless of who else needs to sign off.
	WorkflowSecurityReview WorkflowType = "security_review"
)

// SensitiveTag is the canonical tag the engine looks for when deciding
// whether a request must be force-routed to security_review regardless
// of risk score. Matches the AI agent's "sensitive_resource" risk
// factor (see request_service_ai_test.go).
const SensitiveTag = "sensitive_resource"

// RiskRouter maps a (risk bucket, resource tags) tuple to the
// appropriate WorkflowType per docs/architecture.md §8.
//
// Decision table:
//
//	tag="sensitive_resource" present  → security_review (overrides risk)
//	risk = high                       → security_review
//	risk = medium                     → manager_approval
//	risk = low                        → self_service
//	risk = "" or unknown              → manager_approval (fail-safe)
//
// The router is stateless and pure-functional; share one instance
// across the process.
type RiskRouter struct{}

// NewRiskRouter returns a fresh router. Provided for symmetry with the
// other engine services even though the zero value is fine.
func NewRiskRouter() *RiskRouter { return &RiskRouter{} }

// Route returns the workflow type for the given risk bucket / tags.
// Tags are compared case-insensitively against SensitiveTag.
func (r *RiskRouter) Route(risk RiskBucket, tags []string) WorkflowType {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), SensitiveTag) {
			return WorkflowSecurityReview
		}
	}
	switch risk {
	case RiskLow:
		return WorkflowSelfService
	case RiskHigh:
		return WorkflowSecurityReview
	case RiskMedium:
		return WorkflowManagerApproval
	default:
		// Unknown risk → fail safe. Manager approval is the
		// least-surprising default; never auto-approve and never
		// blanket-escalate to security on a missing risk score.
		return WorkflowManagerApproval
	}
}

// RouteRequest is a convenience that pulls RiskScore + RiskFactors out
// of an AccessRequest and returns the workflow type. Returns
// WorkflowManagerApproval for a nil request rather than panicking; that
// matches Route's fail-safe contract.
func (r *RiskRouter) RouteRequest(req *models.AccessRequest, tags []string) WorkflowType {
	if req == nil {
		return WorkflowManagerApproval
	}
	return r.Route(RiskBucket(req.RiskScore), tags)
}

// StepTypeFor returns the AccessWorkflow step type that corresponds to a
// given WorkflowType. Useful when the engine needs to construct a
// synthetic workflow definition (e.g. when no DB workflow matched but
// risk routing has spoken).
func StepTypeFor(t WorkflowType) string {
	switch t {
	case WorkflowSelfService:
		return models.WorkflowStepAutoApprove
	case WorkflowManagerApproval:
		return models.WorkflowStepManagerApproval
	case WorkflowSecurityReview:
		return models.WorkflowStepSecurityReview
	default:
		return models.WorkflowStepManagerApproval
	}
}
