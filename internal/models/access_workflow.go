package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessWorkflow mirrors the access_workflows table per
// docs/ARCHITECTURE.md §10. Encodes a configurable approval chain: which
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
)
