package models

import (
	"time"

	"gorm.io/gorm"
)

// AccessGrantEntitlement mirrors the access_grant_entitlements
// table. Each row captures one effective entitlement returned by
// AccessConnector.ListEntitlements for the (connector_id,
// user_external_id) pair. The table is refreshed transactionally
// per list_entitlements worker job (delete old rows for the pair,
// then insert the fresh batch).
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - (ConnectorID, UserExternalID, ResourceExternalID, Role) is
//     UNIQUE — the same entitlement is never duplicated for one
//     user on one provider.
//   - Source describes how the upstream provider classified the
//     entitlement (e.g. "direct", "group", "role"). It is
//     connector-supplied verbatim.
//   - LastUsedAt is provider-supplied; many providers leave it nil.
//   - RiskScore is populated downstream by the AI agent — Phase 6
//     leaves it nil.
//
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria); referential integrity to access_connectors is
// enforced at the service layer.
type AccessGrantEntitlement struct {
	ID                 string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	ConnectorID        string         `gorm:"type:varchar(26);not null;uniqueIndex:idx_access_grant_entitlements_unique,priority:1" json:"connector_id"`
	UserExternalID     string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_access_grant_entitlements_unique,priority:2" json:"user_external_id"`
	ResourceExternalID string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_access_grant_entitlements_unique,priority:3" json:"resource_external_id"`
	Role               string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_access_grant_entitlements_unique,priority:4" json:"role"`
	Source             string         `gorm:"type:varchar(64)" json:"source,omitempty"`
	LastUsedAt         *time.Time     `json:"last_used_at,omitempty"`
	RiskScore          *int           `json:"risk_score,omitempty"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name matches
// docs/architecture.md §11.
func (AccessGrantEntitlement) TableName() string {
	return "access_grant_entitlements"
}
