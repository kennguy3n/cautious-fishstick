package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessWorkflow mirrors the access_workflows table per
// docs/architecture.md §10. Encodes a configurable approval chain: which
// requests should match it (MatchRule) and what to do once they do (Steps).
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - WorkspaceID is the multi-tenant scoping dimension; workflows from one
//     workspace must never match a request from another. WorkflowService
//     enforces this with a WHERE clause.
//   - MatchRule is a JSON object. The Phase 2 matcher understands:
//
//       { "connector_id": "...", "role": "...", "resource_pattern": "..." }
//
//     Future phases may add risk_score buckets, group membership, etc.
//   - Steps is a JSON array describing the approval pipeline. Phase 2 only
//     understands two shapes:
//
//       [ {"type": "auto_approve"} ]
//       [ {"type": "manager_approval"} ]
//
//     Multi-step pipelines and named approver pools land in Phase 5+.
//   - IsActive defaults to true; soft-disable a workflow without deleting
//     it by setting it to false.
//   - DeletedAt is the GORM soft-delete column.
type AccessWorkflow struct {
	ID          string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	MatchRule   datatypes.JSON `gorm:"type:jsonb" json:"match_rule,omitempty"`
	Steps       datatypes.JSON `gorm:"type:jsonb" json:"steps,omitempty"`
	IsActive    bool           `gorm:"not null;default:true" json:"is_active"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// access_workflows (matching the migration and ARCHITECTURE §10).
func (AccessWorkflow) TableName() string {
	return "access_workflows"
}

// WorkflowStepType enumerates the values that may appear under the "type"
// key of an entry in AccessWorkflow.Steps. Strings are stable across
// versions; renaming any of them is a database migration.
const (
	// WorkflowStepAutoApprove auto-approves a request as soon as the
	// workflow matches.
	WorkflowStepAutoApprove = "auto_approve"
	// WorkflowStepManagerApproval routes the request to the requester's
	// manager and leaves it in RequestStateRequested until the manager
	// acts via API.
	WorkflowStepManagerApproval = "manager_approval"
	// WorkflowStepSecurityReview routes high-risk or sensitive resource
	// requests to the security review queue. The request stays in
	// RequestStateRequested until a security reviewer acts via the API.
	WorkflowStepSecurityReview = "security_review"
	// WorkflowStepMultiLevel chains multiple approval stages — manager,
	// then security, then resource owner — into a single step that
	// evaluates each level in order until one approves or denies.
	WorkflowStepMultiLevel = "multi_level"
)

// WorkflowStepDefinition is the canonical, decoded shape of one entry in
// AccessWorkflow.Steps. Phase 8 widens the schema beyond `{type:...}` to
// carry timeout / escalation metadata and ordered approver levels for the
// `multi_level` step type.
//
//	[
//	  {
//	    "type": "manager_approval",
//	    "timeout_hours": 24,
//	    "escalation_target": "security_review"
//	  },
//	  {
//	    "type": "multi_level",
//	    "levels": [
//	      {"role": "manager",          "timeout_hours": 24},
//	      {"role": "security_review",  "timeout_hours": 48},
//	      {"role": "resource_owner",   "timeout_hours": 72}
//	    ]
//	  }
//	]
//
// Backward-compatibility: the Phase 2 short form `[{"type": "..."}]` still
// decodes cleanly because every new field is optional.
//
// Phase 10 (DAG runtime) adds two more optional fields:
//
//   - `Next`: a list of step indices (0-based) that must run after this step
//     completes successfully. When omitted, the executor falls back to the
//     legacy linear semantics (step `i` is followed by step `i+1`). When
//     `Next` has multiple entries, those branches are launched in parallel.
//   - `Join`: a list of step indices that MUST complete (with status
//     `completed`) before this step is allowed to start. The executor uses
//     `Join` to implement fan-in / synchronisation barriers in DAG
//     workflows.
//
// Both fields are honoured only by the new DAG executor path; the linear
// executor ignores them, so an existing linear workflow keeps working
// unchanged.
type WorkflowStepDefinition struct {
	Type             string               `json:"type"`
	TimeoutHours     int                  `json:"timeout_hours,omitempty"`
	EscalationTarget string               `json:"escalation_target,omitempty"`
	Levels           []WorkflowStepLevel  `json:"levels,omitempty"`
	// Next is the optional fan-out list of step indices that should run
	// after this step finishes. Defaults to the implicit i+1 successor
	// when omitted (Phase 2 / linear semantics).
	Next []int `json:"next,omitempty"`
	// Join is the optional fan-in list of step indices that must
	// complete before this step is allowed to start. Defaults to the
	// implicit i-1 predecessor when omitted (Phase 2 / linear
	// semantics).
	Join []int `json:"join,omitempty"`
}

// WorkflowStepLevel is one stage in a multi-level approval chain.
// `Role` is a free-form string (manager, security_review, resource_owner,
// etc.) that downstream services map to a real approver pool.
type WorkflowStepLevel struct {
	Role         string `json:"role"`
	TimeoutHours int    `json:"timeout_hours,omitempty"`
}
