package models

import (
	"time"

	"gorm.io/gorm"
)

// AccessOrphanAccount is one row per (connector, upstream user_external_id)
// pair where the SaaS app reports a user that the identity provider does
// NOT recognise. Orphan accounts are the Phase 11 ShieldNet 360 surface
// area for the “unused app account” workflow described in
// docs/architecture.md §13 — operators see them in the connector health
// page and can either auto-revoke or dismiss.
//
// Status state machine:
//
//	detected      → new orphan; default after reconciliation.
//	auto_revoked  → reconciler triggered RevokeAccess on the SaaS row.
//	acknowledged  → operator dismissed the orphan (handled out-of-band).
//	dismissed     → orphan suppressed (e.g. shared service account); no
//	                further alerts until detection re-runs.
//
// There are no FOREIGN KEY constraints (per SN360 database-index rule
// and docs/PHASES.md cross-cutting criteria). Referential integrity to
// access_connectors and workspaces is enforced at the service layer.
type AccessOrphanAccount struct {
	ID             string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID    string         `gorm:"type:varchar(26);not null;index:idx_orphan_workspace_status,priority:1" json:"workspace_id"`
	ConnectorID    string         `gorm:"type:varchar(26);not null;index" json:"connector_id"`
	UserExternalID string         `gorm:"type:varchar(255);not null;index:idx_orphan_connector_user,priority:2" json:"user_external_id"`
	Email          string         `gorm:"type:varchar(255)" json:"email,omitempty"`
	DisplayName    string         `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	Status         string         `gorm:"type:varchar(50);not null;default:'detected';index:idx_orphan_workspace_status,priority:2" json:"status"`
	DetectedAt     time.Time      `json:"detected_at"`
	ResolvedAt     *time.Time     `json:"resolved_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName overrides the default plural form so the table is exactly
// access_orphan_accounts.
func (AccessOrphanAccount) TableName() string { return "access_orphan_accounts" }

// Valid AccessOrphanAccount.Status values.
const (
	OrphanStatusDetected     = "detected"
	OrphanStatusAutoRevoked  = "auto_revoked"
	OrphanStatusAcknowledged = "acknowledged"
	OrphanStatusDismissed    = "dismissed"
)
