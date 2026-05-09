// Package models holds GORM-mapped database structs for the ShieldNet 360
// Access Platform.
package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessConnector mirrors the access_connectors table per docs/PROPOSAL.md
// §9.1. One row per (workspace, provider, connector_type) tuple — the
// duplicate-check index lives on that triple.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string), not a numeric PK. The ULID also doubles
//     as the AAD when encrypting Credentials, so changing the ID after a row
//     is written makes Credentials undecryptable on purpose.
//   - There are no FOREIGN KEY constraints — referential integrity is
//     enforced in application code. This mirrors the SN360 database-index
//     rule (no FKs).
//   - Config is operator-visible JSON (tenant_id, domain, ...). Credentials
//     is AES-GCM ciphertext over the secrets JSON; KeyVersion pins which
//     org DEK version was used.
//   - DeletedAt is the GORM soft-delete column. Tombstoned rows stay
//     readable to reconcile audit history.
type AccessConnector struct {
	ID                    string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID           string         `gorm:"type:varchar(26);not null;index:idx_access_connectors_workspace_provider_type,priority:1" json:"workspace_id"`
	Provider              string         `gorm:"type:varchar(100);not null;index:idx_access_connectors_workspace_provider_type,priority:2" json:"provider"`
	ConnectorType         string         `gorm:"type:varchar(50);not null;index:idx_access_connectors_workspace_provider_type,priority:3" json:"connector_type"`
	Config                datatypes.JSON `gorm:"type:jsonb" json:"config"`
	Credentials           string         `gorm:"type:text" json:"-"`
	KeyVersion            int            `gorm:"not null;default:1" json:"key_version"`
	Status                string         `gorm:"type:varchar(50);not null;default:'disconnected'" json:"status"`
	CredentialExpiredTime *time.Time     `json:"credential_expired_time,omitempty"`
	DeletedAt             gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// access_connectors (matching the migration and PROPOSAL.md §9.1).
func (AccessConnector) TableName() string {
	return "access_connectors"
}

// ConnectorStatus enumerates the values stored in AccessConnector.Status. The
// strings are operator-visible in the admin UI translation table.
const (
	StatusDisconnected = "disconnected"
	StatusConnected    = "connected"
	StatusError        = "error"
	StatusExpired      = "expired"
)
