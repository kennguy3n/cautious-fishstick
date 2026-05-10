package models

import "time"

// Status constants for AccessWorkflowStepHistory.Status. Strings are
// stable across versions and may appear in audit logs / dashboards.
const (
	// WorkflowStepStatusPending means the executor has entered the
	// step and is waiting on a human or external system.
	WorkflowStepStatusPending = "pending"
	// WorkflowStepStatusCompleted means the step finished
	// successfully (e.g. auto_approve emitted Approve).
	WorkflowStepStatusCompleted = "completed"
	// WorkflowStepStatusFailed means the step exhausted its retry
	// budget and the executor surfaced the underlying error to the
	// caller. Operators query for this state via
	// WorkflowExecutor.ListFailedSteps to triage stuck workflows.
	WorkflowStepStatusFailed = "failed"
	// WorkflowStepStatusEscalated means the EscalationChecker bumped
	// the step to its escalation_target (or the next multi_level
	// level).
	WorkflowStepStatusEscalated = "escalated"
	// WorkflowStepStatusDenied means the step explicitly rejected the
	// request. Terminal — subsequent steps do NOT run.
	WorkflowStepStatusDenied = "denied"
)

// AccessWorkflowStepHistory mirrors the access_workflow_step_history
// table per docs/PHASES.md Phase 8 Task 4. One row per workflow step
// the executor walks; rows are append-only and the executor never
// rewrites a previously-emitted row.
//
// The (request_id, step_index) pair is unique per workflow run.
// Because a single AccessRequest can be re-driven through its
// workflow more than once (e.g. retry-after-escalation), we do NOT
// declare a unique index on the pair — instead operators query by
// (request_id, started_at DESC) to see the latest run.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - RequestID is *not* a FOREIGN KEY (per SN360 database-index
//     rule); it is a plain indexed string column. Joins are
//     application-side.
//   - WorkflowID may be empty in the rare case the executor failed
//     before loading the workflow; the row still gets written so
//     operators can see the failure.
//   - Status is one of the WorkflowStepStatus* constants above.
//   - StartedAt is set when the row is created. CompletedAt is set
//     when the step transitions out of pending — nil while still
//     pending.
//   - ActorUserID may be empty for system-driven steps (auto_approve,
//     escalation timeouts).
//   - There is no UpdatedAt and no DeletedAt — the executor mutates
//     (Status, CompletedAt, Notes) on a pending row in place via
//     gorm.Updates. The audit trail is append-only at the
//     (request_id, step_index) granularity.
//
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria).
type AccessWorkflowStepHistory struct {
	ID          string     `gorm:"primaryKey;type:varchar(26)" json:"id"`
	RequestID   string     `gorm:"type:varchar(26);not null;index:idx_access_workflow_step_history_request,priority:1" json:"request_id"`
	WorkflowID  string     `gorm:"type:varchar(26);index" json:"workflow_id,omitempty"`
	StepIndex   int        `gorm:"not null;index:idx_access_workflow_step_history_request,priority:2" json:"step_index"`
	StepType    string     `gorm:"type:varchar(50);not null" json:"step_type"`
	Status      string     `gorm:"type:varchar(20);not null;index" json:"status"`
	StartedAt   time.Time  `gorm:"not null" json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ActorUserID string     `gorm:"type:varchar(64)" json:"actor_user_id,omitempty"`
	Notes       string     `gorm:"type:text" json:"notes,omitempty"`
	Attempts    int        `gorm:"not null;default:1" json:"attempts"`
	CreatedAt   time.Time  `json:"created_at"`
}

// TableName overrides the default plural so the table name is
// exactly access_workflow_step_history (matching the migration).
func (AccessWorkflowStepHistory) TableName() string {
	return "access_workflow_step_history"
}
