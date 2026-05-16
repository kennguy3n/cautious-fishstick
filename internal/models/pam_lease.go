package models

import (
	"time"

	"gorm.io/gorm"
)

// PAMLease mirrors the pam_leases table per docs/pam/architecture.md.
// One row per Just-In-Time (JIT) entitlement that lets a user broker
// a session against a (PAMAsset, PAMAccount) target for a bounded
// window. Backed by an access_requests row (linked through RequestID)
// so the existing approval state machine, audit trail, and workflow
// engine all participate.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints; WorkspaceID / UserID /
//     AssetID / AccountID / RequestID are indexed strings; application
//     code enforces referential integrity.
//   - GrantedAt is nullable — set when the lease is approved and the
//     JIT clock starts.
//   - ExpiresAt is nullable until the lease is approved; after
//     approval it is non-nil and the expiry-cron uses it to bulk-
//     revoke leases.
//   - RevokedAt is the terminal-state marker. revoked_at != nil
//     implies the lease is no longer usable regardless of expires_at.
//   - ApprovedBy stores the approver's user ID for the audit trail;
//     empty until approval lands.
type PAMLease struct {
	ID          string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID string         `gorm:"type:varchar(26);not null;index:idx_pam_leases_workspace_user,priority:1" json:"workspace_id"`
	UserID      string         `gorm:"type:varchar(26);not null;index:idx_pam_leases_workspace_user,priority:2" json:"user_id"`
	AssetID     string         `gorm:"type:varchar(26);not null;index" json:"asset_id"`
	AccountID   string         `gorm:"type:varchar(26);not null" json:"account_id"`
	RequestID   string         `gorm:"type:varchar(26);index" json:"request_id,omitempty"`
	GrantedAt   *time.Time     `json:"granted_at,omitempty"`
	ExpiresAt   *time.Time     `gorm:"index" json:"expires_at,omitempty"`
	RevokedAt   *time.Time     `json:"revoked_at,omitempty"`
	ApprovedBy  string         `gorm:"type:varchar(26)" json:"approved_by,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_leases.
func (PAMLease) TableName() string {
	return "pam_leases"
}

// IsActive reports whether the lease is currently live. A lease is
// live iff it has been granted, has not been revoked, and has not
// yet expired.
func (l PAMLease) IsActive(now time.Time) bool {
	if l.GrantedAt == nil {
		return false
	}
	if l.RevokedAt != nil {
		return false
	}
	if l.ExpiresAt != nil && !l.ExpiresAt.After(now) {
		return false
	}
	return true
}
