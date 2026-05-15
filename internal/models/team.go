package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Team mirrors the teams table per docs/architecture.md §11.
// Teams are the unit of attribute-based
// targeting for Phase 3 policy simulation: a draft policy's
// AttributesSelector matches Teams via Team.Attributes, and the
// matched Teams are then expanded to their members.
//
// Phase 3 introduces only a thin stub of the teams table — just enough
// for ImpactResolver to walk attribute selectors. Full Team management
// (rename, archive, hierarchy, attribute mutation) lives outside this
// repo and will reuse the same table once it lands.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rule). WorkspaceID is the multi-tenant scoping dimension.
//   - Attributes is a JSON object mapping arbitrary string keys to
//     string values (e.g. {"department": "engineering", "level": "L4"}).
//     Phase 3 matchers do flat key-equality matching against this map.
//   - DeletedAt is the GORM soft-delete column. Tombstoned teams stay
//     readable so audit reports and historical impact diffs can render.
type Team struct {
	ID          string `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID string `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	Name        string `gorm:"type:varchar(255);not null" json:"name"`
	// ExternalID is the upstream provider-side group identifier the
	// connector sync pipeline uses to map directory groups onto
	// teams rows. Optional for legacy rows; populated by the
	// identity-sync worker for connectors that yield
	// IdentityTypeGroup records.
	ExternalID string `gorm:"type:varchar(255);index" json:"external_id,omitempty"`
	// ConnectorID is the access_connectors.ID that produced this
	// row's external mapping. Empty for legacy rows; populated by
	// the identity-sync worker.
	ConnectorID string         `gorm:"type:varchar(26);index" json:"connector_id,omitempty"`
	Attributes  datatypes.JSON `gorm:"type:jsonb" json:"attributes,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// teams (matching the migration and PROPOSAL §9).
func (Team) TableName() string {
	return "teams"
}

// TeamMember mirrors the team_members table — the join row between
// Team and the workspace user directory. Phase 3's ImpactResolver
// expands matched Teams to their members through this table.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints; TeamID and UserID are both
//     indexed strings, application code enforces referential integrity.
//   - DeletedAt is the GORM soft-delete column.
type TeamMember struct {
	ID     string `gorm:"primaryKey;type:varchar(26)" json:"id"`
	TeamID string `gorm:"type:varchar(26);not null;index" json:"team_id"`
	UserID string `gorm:"type:varchar(26);not null;index" json:"user_id"`
	// ExternalID is the upstream provider-side user identifier the
	// connector sync pipeline uses to map directory users onto
	// team_members rows (e.g. Okta `sub`, Microsoft Graph `oid`).
	// Optional for legacy rows; populated by the identity-sync
	// worker.
	ExternalID string `gorm:"type:varchar(255);index" json:"external_id,omitempty"`
	// ConnectorID is the access_connectors.ID that produced this
	// row's external mapping. Empty for legacy rows; populated by
	// the identity-sync worker so the manager-link resolution pass
	// can scope its lookup correctly.
	ConnectorID string `gorm:"type:varchar(26);index" json:"connector_id,omitempty"`
	// ManagerID is the team_members.ID of the user's manager.
	// Populated by the identity-sync worker's manager-link
	// resolution pass after the full identity batch is upserted.
	ManagerID   string         `gorm:"type:varchar(26);index" json:"manager_id,omitempty"`
	DisplayName string         `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	Email       string         `gorm:"type:varchar(255)" json:"email,omitempty"`
	Status      string         `gorm:"type:varchar(50)" json:"status,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// team_members (matching the migration and PROPOSAL §9).
func (TeamMember) TableName() string {
	return "team_members"
}
