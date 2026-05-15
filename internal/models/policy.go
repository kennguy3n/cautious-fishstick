package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Policy mirrors the policies table per docs/overview.md §6 and
// docs/architecture.md §5. The table holds both draft and live policies;
// IsDraft is the discriminator. Drafts are platform-side abstractions
// only — no OpenZiti ServicePolicy is created until Promote flips
// IsDraft to false.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string), same convention as the other Phase
//     0–2 models.
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rule). Referential integrity to workspaces, teams, resources, and
//     users is enforced by the service layer.
//   - AttributesSelector is a JSON object that targets Teams via their
//     attributes column. The Phase 3 matcher understands a flat
//     {"key": "value"} shape; phase-3 ImpactResolver does the matching.
//   - ResourceSelector is a JSON object that targets resources via their
//     external_id, category, or tags. Phase 3 supports a small subset
//     ({"external_id": "..."}, {"category": "..."}, {"tag": "value"}).
//   - Action is "allow" or "deny" — a deny policy contributes a negative
//     edge in the access graph and surfaces as a "contradictory"
//     conflict against an existing allow on the same (member, resource)
//     pair.
//   - IsDraft defaults to true; CreateDraft never inserts a row with
//     IsDraft=false. Promote flips it inside a transaction.
//   - DraftImpact is the persisted ImpactReport from the most recent
//     Simulate call. Promote refuses to flip IsDraft if DraftImpact is
//     nil (per PROPOSAL §6.5: simulate-before-promote).
//   - PromotedAt / PromotedBy are nil until Promote runs. After
//     promotion the row is the live policy of record.
//   - IsActive lets admins disable a live policy without deleting it.
//   - DeletedAt is the GORM soft-delete column. Tombstoned drafts and
//     live policies stay readable for audit.
type Policy struct {
	ID                 string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID        string         `gorm:"type:varchar(26);not null;index:idx_policies_workspace_draft,priority:1;index:idx_policies_workspace_active,priority:1" json:"workspace_id"`
	Name               string         `gorm:"type:varchar(255);not null" json:"name"`
	Description        string         `gorm:"type:text" json:"description,omitempty"`
	AttributesSelector datatypes.JSON `gorm:"type:jsonb" json:"attributes_selector,omitempty"`
	ResourceSelector   datatypes.JSON `gorm:"type:jsonb" json:"resource_selector,omitempty"`
	Action             string         `gorm:"type:varchar(10);not null;default:'allow'" json:"action"`
	IsDraft            bool           `gorm:"not null;default:true;index:idx_policies_workspace_draft,priority:2" json:"is_draft"`
	DraftImpact        datatypes.JSON `gorm:"type:jsonb" json:"draft_impact,omitempty"`
	PromotedAt         *time.Time     `json:"promoted_at,omitempty"`
	PromotedBy         *string        `gorm:"type:varchar(26)" json:"promoted_by,omitempty"`
	IsActive           bool           `gorm:"not null;default:true;index:idx_policies_workspace_active,priority:2" json:"is_active"`
	// Stale is flipped to true by cron.DraftPolicyStalenessChecker
	// when a draft policy's CreatedAt is older than the configured
	// staleness threshold. Surfaced to the operator admin UI so
	// authors know to promote / delete / refresh the draft.
	Stale     bool           `gorm:"not null;default:false;index" json:"stale"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// policies (matching the migration and PROPOSAL §9.2).
func (Policy) TableName() string {
	return "policies"
}

// PolicyAction enumerates the values stored in Policy.Action. The
// strings are operator-visible in the admin UI translation table; renaming
// any of them is a database migration, not a refactor.
const (
	// PolicyActionAllow grants the (member, resource) pair access.
	PolicyActionAllow = "allow"
	// PolicyActionDeny revokes the (member, resource) pair access; a
	// deny on the same pair as an existing allow surfaces as a
	// "contradictory" conflict during simulation.
	PolicyActionDeny = "deny"
)

// IsDraftPolicy reports whether the row is still a draft (i.e. has not
// yet been promoted). Service code consults this to gate Simulate /
// Promote / TestAccess on a per-policy basis.
func (p Policy) IsDraftPolicy() bool {
	return p.IsDraft
}

// IsPromoted reports whether the policy has gone through Promote and is
// now the live policy of record. A promoted policy's PromotedAt is
// non-nil by construction.
func (p Policy) IsPromoted() bool {
	return !p.IsDraft && p.PromotedAt != nil
}
