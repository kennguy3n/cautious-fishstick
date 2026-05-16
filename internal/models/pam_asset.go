package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// PAMAsset mirrors the pam_assets table per docs/pam/architecture.md.
// One row per managed privileged target (SSH host, K8s cluster,
// database instance, Windows server) that a privileged user can
// broker a session through.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string) — same convention as
//     AccessConnector / AccessRequest.
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rules). Referential integrity to workspaces and users is
//     enforced at the service layer.
//   - Protocol is one of (ssh, rdp, k8s, postgres, mysql) — validated
//     by IsValidPAMProtocol before insert.
//   - Criticality is one of (low, medium, high, critical) — validated
//     by IsValidPAMCriticality before insert; drives risk routing
//     in the lease workflow templates.
//   - Status is one of (active, inactive, archived). Archived rows
//     stay queryable for audit but are excluded from the asset
//     picker. Soft-delete via status=archived is preferred over
//     hard delete so historical pam_sessions can still join.
//   - DeletedAt is the GORM soft-delete column; it is reserved for
//     rare hard-delete operations (e.g. a test workspace wipe). The
//     normal "remove from inventory" path is status=archived.
type PAMAsset struct {
	ID           string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID  string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	Name         string         `gorm:"type:varchar(255);not null" json:"name"`
	Protocol     string         `gorm:"type:varchar(32);not null" json:"protocol"`
	Host         string         `gorm:"type:varchar(255);not null" json:"host"`
	Port         int            `gorm:"not null" json:"port"`
	Criticality  string         `gorm:"type:varchar(32);not null;default:'medium'" json:"criticality"`
	OwnerUserID  string         `gorm:"type:varchar(26)" json:"owner_user_id,omitempty"`
	Config       datatypes.JSON `gorm:"type:jsonb" json:"config,omitempty"`
	Status       string         `gorm:"type:varchar(32);not null;default:'active'" json:"status"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_assets (matching the migration and docs/pam/architecture.md).
func (PAMAsset) TableName() string {
	return "pam_assets"
}

// PAM protocol enums. Strings are operator-visible in the admin UI
// and stable across versions; renaming any of them is a database
// migration, not a refactor.
const (
	PAMProtocolSSH      = "ssh"
	PAMProtocolRDP      = "rdp"
	PAMProtocolK8s      = "k8s"
	PAMProtocolPostgres = "postgres"
	PAMProtocolMySQL    = "mysql"
)

// PAM criticality enums. Drives lease workflow routing —
// low → auto-approve, medium → manager_approval, high/critical →
// security_review + manager_approval.
const (
	PAMCriticalityLow      = "low"
	PAMCriticalityMedium   = "medium"
	PAMCriticalityHigh     = "high"
	PAMCriticalityCritical = "critical"
)

// PAM asset status enums.
const (
	PAMAssetStatusActive   = "active"
	PAMAssetStatusInactive = "inactive"
	PAMAssetStatusArchived = "archived"
)

// IsValidPAMProtocol reports whether protocol is one of the five
// supported values. Used by PAMAssetService.CreateAsset /
// UpdateAsset to reject typos before they reach the DB layer.
func IsValidPAMProtocol(protocol string) bool {
	switch protocol {
	case PAMProtocolSSH, PAMProtocolRDP, PAMProtocolK8s, PAMProtocolPostgres, PAMProtocolMySQL:
		return true
	}
	return false
}

// IsValidPAMCriticality reports whether criticality is one of the
// four buckets. Used by PAMAssetService validation.
func IsValidPAMCriticality(criticality string) bool {
	switch criticality {
	case PAMCriticalityLow, PAMCriticalityMedium, PAMCriticalityHigh, PAMCriticalityCritical:
		return true
	}
	return false
}

// IsValidPAMAssetStatus reports whether status is one of the three
// asset statuses.
func IsValidPAMAssetStatus(status string) bool {
	switch status {
	case PAMAssetStatusActive, PAMAssetStatusInactive, PAMAssetStatusArchived:
		return true
	}
	return false
}
