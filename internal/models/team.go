package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Team mirrors the teams table per docs/PROPOSAL.md §9 and
// docs/ARCHITECTURE.md §5. Teams are the unit of attribute-based
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
	ID          string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
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
	ID        string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	TeamID    string         `gorm:"type:varchar(26);not null;index" json:"team_id"`
	UserID    string         `gorm:"type:varchar(26);not null;index" json:"user_id"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// team_members (matching the migration and PROPOSAL §9).
func (TeamMember) TableName() string {
	return "team_members"
}
