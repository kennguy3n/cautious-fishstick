package models

import (
	"time"
)

// AccessSyncState persists the per-(connector, kind) delta-link
// cursor the access-connector-worker uses to resume incremental
// sync. Per docs/overview.md §9.1 and docs/architecture.md §3 each
// connector tracks one cursor per sync kind:
//
//   - "identity" — cursor for the IdentityDeltaSyncer pipeline
//   - "group"    — cursor for the GroupDeltaSyncer pipeline
//   - "audit"    — cursor for the AccessAuditor pipeline
//
// When a delta-link expires the connector returns ErrDeltaTokenExpired
// and the worker falls back to a full resync, which then writes a
// fresh cursor here.
//
// Notable invariants:
//
//   - ConnectorID is the access_connectors.ID this cursor belongs to.
//   - Kind is one of the three strings above; lower-case to match
//     the connector capability registry.
//   - DeltaLink is opaque to the access platform — it is the
//     provider-specific token (Microsoft Graph @odata.deltaLink,
//     Okta /api/v1/logs since-cursor, ...). Stored verbatim.
//   - UpdatedAt tracks the last successful write so admins can spot
//     stalled sync pipelines (no UpdatedAt advance => no progress).
//   - The (connector_id, kind) tuple is UNIQUE; a single connector
//     never has two open cursors of the same kind.
//
// No FOREIGN KEY constraints (per docs/internal/PHASES.md cross-cutting
// criteria); referential integrity to access_connectors is enforced
// at the service layer.
type AccessSyncState struct {
	ID          string `gorm:"primaryKey;type:varchar(26)" json:"id"`
	ConnectorID string `gorm:"type:varchar(26);not null;uniqueIndex:idx_access_sync_state_connector_kind,priority:1" json:"connector_id"`
	Kind        string `gorm:"type:varchar(32);not null;uniqueIndex:idx_access_sync_state_connector_kind,priority:2" json:"kind"`
	DeltaLink   string `gorm:"type:text" json:"delta_link"`
	// IdentityCount records the number of identities observed by the
	// last successful sync. Used by the tombstone safety threshold —
	// a fresh sync whose total identity count is below 70% of the
	// previously observed count aborts to protect against a runaway
	// directory-side deletion (per docs/internal/PHASES.md Phase 6 sync rules).
	IdentityCount int       `gorm:"not null;default:0" json:"identity_count"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TableName overrides the default plural so the table name matches
// docs/overview.md §9.1.
func (AccessSyncState) TableName() string {
	return "access_sync_state"
}

// Sync state Kind enumeration. Values are lower-case to match the
// connector capability registry (sync_identity, sync_group,
// fetch_audit_logs all collapse to the kind here).
const (
	SyncStateKindIdentity = "identity"
	SyncStateKindGroup    = "group"
	SyncStateKindAudit    = "audit"
)
