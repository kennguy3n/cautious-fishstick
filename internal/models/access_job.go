package models

import (
	"time"

	"gorm.io/datatypes"
)

// AccessJob mirrors the access_jobs table per docs/ARCHITECTURE.md
// §10. One row per worker job run — sync_identities,
// provision_access, revoke_access, list_entitlements. The Phase 6
// scaffold persists the job lifecycle in this table; a future
// Phase wires Redis-backed queueing on top, but the on-disk
// representation stays the same so the worker can be restarted
// from the database alone if the queue is wiped.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - ConnectorID is the access_connectors.ID this job runs against.
//   - JobType is one of the four canonical worker job types
//     (AccessJobType*). Storing it as a varchar means the Go side
//     owns the enum without an SQL CHECK constraint.
//   - Status is the machine-readable state of the job lifecycle
//     (AccessJobStatus*). pending → running → completed | failed.
//   - Payload is the worker-specific input blob — for
//     provision_access it carries (UserID, ResourceExternalID,
//     Role); for sync_identities it can carry an explicit
//     checkpoint override; for list_entitlements it carries the
//     filter shape.
//   - StartedAt is set when the worker picks the job up; nil for
//     pending jobs and unchanged for failed pickups.
//   - CompletedAt is set when the worker terminates (success or
//     failure); nil while running.
//   - LastError captures the last error message surfaced by the
//     worker — empty on success.
//
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria); referential integrity to access_connectors is
// enforced at the service layer.
type AccessJob struct {
	ID          string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	ConnectorID string         `gorm:"type:varchar(26);not null;index:idx_access_jobs_connector_status,priority:1" json:"connector_id"`
	JobType     string         `gorm:"type:varchar(50);not null;index:idx_access_jobs_connector_status,priority:2" json:"job_type"`
	Status      string         `gorm:"type:varchar(20);not null;default:pending;index:idx_access_jobs_connector_status,priority:3" json:"status"`
	Payload     datatypes.JSON `gorm:"type:jsonb" json:"payload,omitempty"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	LastError   string         `gorm:"type:text" json:"last_error,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name matches
// docs/ARCHITECTURE.md §10.
func (AccessJob) TableName() string {
	return "access_jobs"
}

// Job-type enumeration. Values match the connector capabilities
// registry (sync_identity, provision_access, ...) collapsed onto
// the worker handler dispatcher.
const (
	AccessJobTypeSyncIdentities    = "sync_identities"
	AccessJobTypeProvisionAccess   = "provision_access"
	AccessJobTypeRevokeAccess      = "revoke_access"
	AccessJobTypeListEntitlements  = "list_entitlements"
)

// Status enumeration. The lifecycle is pending → running →
// completed | failed; a failed job MAY be retried by inserting a
// fresh row (the worker does NOT mutate completed_at back to nil).
const (
	AccessJobStatusPending   = "pending"
	AccessJobStatusRunning   = "running"
	AccessJobStatusCompleted = "completed"
	AccessJobStatusFailed    = "failed"
)
