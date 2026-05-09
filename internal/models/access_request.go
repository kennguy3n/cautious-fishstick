package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessRequest mirrors the access_requests table per docs/PROPOSAL.md §9.1
// and docs/ARCHITECTURE.md §10. One row per "user X asks for role Y on
// resource Z" lifecycle. The state column is the source of truth for where
// the request is in the request_state_machine.go FSM; access_request_state_history
// keeps the audit trail of every transition.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string) — same convention as AccessConnector.
//   - There are no FOREIGN KEY constraints (per SN360 database-index rule).
//     Referential integrity to workspaces, users, and access_connectors is
//     enforced at the service layer.
//   - State defaults to RequestStateRequested on insert. Mutations go through
//     AccessRequestService so the FSM is consulted.
//   - RiskScore is a coarse bucket ("low" / "medium" / "high"), populated by
//     the AI agent after the row is written. Never set by the user.
//   - WorkflowID is nullable: if no workflow matches, the request stays in
//     RequestStateRequested and a manager has to act.
//   - DeletedAt is the GORM soft-delete column. Tombstoned rows stay readable
//     so the audit trail does not get rewritten when an admin "deletes" a
//     request.
type AccessRequest struct {
	ID                 string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID        string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	RequesterUserID    string         `gorm:"type:varchar(26);not null;index" json:"requester_user_id"`
	TargetUserID       string         `gorm:"type:varchar(26);not null" json:"target_user_id"`
	ConnectorID        string         `gorm:"type:varchar(26);not null" json:"connector_id"`
	ResourceExternalID string         `gorm:"type:varchar(255);not null" json:"resource_external_id"`
	Role               string         `gorm:"type:varchar(100);not null" json:"role"`
	Justification      string         `gorm:"type:text" json:"justification,omitempty"`
	State              string         `gorm:"type:varchar(50);not null;default:'requested';index" json:"state"`
	RiskScore          string         `gorm:"type:varchar(20)" json:"risk_score,omitempty"`
	RiskFactors        datatypes.JSON `gorm:"type:jsonb" json:"risk_factors,omitempty"`
	WorkflowID         *string        `gorm:"type:varchar(26)" json:"workflow_id,omitempty"`
	ExpiresAt          *time.Time     `json:"expires_at,omitempty"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// access_requests (matching the migration and ARCHITECTURE §10).
func (AccessRequest) TableName() string {
	return "access_requests"
}

// RequestState enumerates the values stored in AccessRequest.State. Strings
// are operator-visible in the admin UI and stable across versions; renaming
// any of them is a database migration, not a refactor.
//
// Transitions between states are validated by request_state_machine.go.
const (
	// RequestStateRequested is the initial state set by CreateRequest.
	RequestStateRequested = "requested"
	// RequestStateApproved means an actor (manager / auto-approver) approved
	// the request; provisioning has not yet started.
	RequestStateApproved = "approved"
	// RequestStateDenied is a terminal state — the request was refused.
	RequestStateDenied = "denied"
	// RequestStateCancelled is a terminal state — the requester or an
	// admin withdrew the request before provisioning completed.
	RequestStateCancelled = "cancelled"
	// RequestStateProvisioning means AccessProvisioningService has the
	// request in flight against the connector.
	RequestStateProvisioning = "provisioning"
	// RequestStateProvisioned means ProvisionAccess returned success but
	// the AccessGrant row has not yet been activated. Tests and code may
	// flip this to RequestStateActive in the same transaction.
	RequestStateProvisioned = "provisioned"
	// RequestStateProvisionFailed is a recoverable failure — the request
	// can be retried back into RequestStateProvisioning.
	RequestStateProvisionFailed = "provision_failed"
	// RequestStateActive means the access is granted and live.
	RequestStateActive = "active"
	// RequestStateRevoked is a terminal state — access was rescinded.
	RequestStateRevoked = "revoked"
	// RequestStateExpired is a terminal state — access aged out via the
	// ExpiresAt column.
	RequestStateExpired = "expired"
)

// RequestRiskScore enumerates the buckets stored in AccessRequest.RiskScore.
// These are intentionally coarse (low / medium / high) — finer-grained
// numeric scoring is a Phase 4 AI-agent concern.
const (
	RequestRiskLow    = "low"
	RequestRiskMedium = "medium"
	RequestRiskHigh   = "high"
)
