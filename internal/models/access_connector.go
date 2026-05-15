// Package models holds GORM-mapped database structs for the ShieldNet 360
// Access Platform.
package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessConnector mirrors the access_connectors table per docs/overview.md
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
	// AccessMode classifies how the platform reaches the connector
	// per docs/overview.md §13 (Hybrid Access Model). One of:
	//   - "tunnel"   — private / self-hosted resource fronted by an
	//                  OpenZiti dataplane tunnel.
	//   - "sso_only" — SaaS app federated through Keycloak; no API
	//                  push and no tunnel required.
	//   - "api_only" — SaaS app reachable directly via the connector's
	//                  REST API; default for connectors with no native
	//                  SSO metadata and no private dataplane.
	// The mode is auto-classified at Connect time and may be
	// overridden via PATCH /access/connectors/:id. PolicyService.Promote
	// surfaces this value so the ZTNA business layer can skip the
	// OpenZiti ServicePolicy write when the resource is sso_only /
	// api_only.
	AccessMode            string         `gorm:"column:access_mode;type:varchar(20);not null;default:'api_only'" json:"access_mode"`
	CredentialExpiredTime *time.Time     `json:"credential_expired_time,omitempty"`
	DeletedAt             gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// access_connectors (matching the migration and docs/overview.md §9.1).
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

// AccessMode enumerates the values stored in AccessConnector.AccessMode per
// docs/overview.md §13 (Hybrid Access Model).
const (
	// AccessModeTunnel marks the connector as a private / self-hosted
	// resource fronted by an OpenZiti dataplane tunnel. PolicyService
	// promotions for tunnel-mode connectors write the corresponding
	// OpenZiti ServicePolicy; sso_only / api_only modes skip it.
	AccessModeTunnel = "tunnel"
	// AccessModeSSOOnly marks the connector as a SaaS app federated
	// through Keycloak. No OpenZiti policy is written; no per-grant
	// API push is required. The connector still participates in
	// identity sync, access reviews, and the leaver kill switch.
	AccessModeSSOOnly = "sso_only"
	// AccessModeAPIOnly marks the connector as a SaaS app reachable
	// directly via the connector's REST API. No OpenZiti policy is
	// written. This is the safe default for connectors without
	// native SSO metadata and without a private dataplane.
	AccessModeAPIOnly = "api_only"
)

// IsValidAccessMode reports whether mode is one of the three values
// defined in docs/overview.md §13. Used by the admin PATCH endpoint
// to reject typos before they reach the DB layer.
func IsValidAccessMode(mode string) bool {
	switch mode {
	case AccessModeTunnel, AccessModeSSOOnly, AccessModeAPIOnly:
		return true
	default:
		return false
	}
}
