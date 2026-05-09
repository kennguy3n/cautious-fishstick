package models

import (
	"time"

	"gorm.io/gorm"
)

// AccessGrant mirrors the access_grants table per docs/ARCHITECTURE.md §10.
// One row per (user, resource, role) entitlement that is currently or was
// previously live. The lifecycle column is the pair (RevokedAt, ExpiresAt):
// a grant is "active" iff RevokedAt is nil and (ExpiresAt is nil or in the
// future).
//
// Note: this is the persisted GORM model. There is also an in-memory DTO
// named access.AccessGrant (see internal/services/access/types.go) used by
// the AccessConnector.ProvisionAccess / RevokeAccess methods. They are
// related but distinct types — service code converts one to the other.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index rule).
//     RequestID, UserID, WorkspaceID, ConnectorID are all indexed strings;
//     application code is responsible for referential integrity.
//   - RequestID is nullable: out-of-band grants (JML automation, manual
//     admin grants) may have no originating access_request.
//   - DeletedAt is the GORM soft-delete column. Tombstoned rows stay
//     readable for audit and review-campaign continuity.
type AccessGrant struct {
	ID                 string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID        string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	UserID             string         `gorm:"type:varchar(26);not null;index" json:"user_id"`
	ConnectorID        string         `gorm:"type:varchar(26);not null;index" json:"connector_id"`
	ResourceExternalID string         `gorm:"type:varchar(255);not null" json:"resource_external_id"`
	Role               string         `gorm:"type:varchar(100);not null" json:"role"`
	RequestID          *string        `gorm:"type:varchar(26)" json:"request_id,omitempty"`
	GrantedAt          time.Time      `gorm:"not null" json:"granted_at"`
	ExpiresAt          *time.Time     `json:"expires_at,omitempty"`
	LastUsedAt         *time.Time     `json:"last_used_at,omitempty"`
	RevokedAt          *time.Time     `gorm:"index" json:"revoked_at,omitempty"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// access_grants (matching the migration and ARCHITECTURE §10).
func (AccessGrant) TableName() string {
	return "access_grants"
}

// IsActive reports whether the grant is currently live. A grant is live iff
// it has not been revoked and has not yet expired. Service code uses this
// before sending a connector ProvisionAccess / RevokeAccess RPC and before
// computing entitlement diffs.
func (g AccessGrant) IsActive(now time.Time) bool {
	if g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
		return false
	}
	return true
}
