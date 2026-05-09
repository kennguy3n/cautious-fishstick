package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Resource mirrors the resources table per docs/PROPOSAL.md §9 and
// docs/ARCHITECTURE.md §5. Resources are the targets of access policies:
// a draft policy's ResourceSelector matches Resources via ExternalID,
// Category, or Tags, and the matched Resources are listed in the
// ImpactReport's AffectedResources field.
//
// Phase 3 introduces only a thin stub of the resources table — just
// enough for ImpactResolver to walk resource selectors. Full resource
// catalogue management (sync from connectors, tag editing, category
// taxonomy) lives outside this repo and will reuse the same table once
// it lands.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rule). WorkspaceID is the multi-tenant scoping dimension.
//   - ExternalID is the provider-side identifier (e.g. an AWS ARN, a
//     Google Drive folder ID, a GitHub repo full-name). It is unique
//     per (workspace, connector) but the Phase 3 stub does not enforce
//     uniqueness — that is a Phase 6+ concern.
//   - Category is a coarse taxonomy bucket ("database", "ssh-host",
//     "saas-app", ...) so policies can target whole classes of
//     resource without enumerating IDs.
//   - Tags is a JSON object of arbitrary key-value labels for richer
//     selectors (e.g. {"env": "prod", "tier": "1"}).
//   - DeletedAt is the GORM soft-delete column.
type Resource struct {
	ID          string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	ExternalID  string         `gorm:"type:varchar(255);not null" json:"external_id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	Category    string         `gorm:"type:varchar(100)" json:"category,omitempty"`
	Tags        datatypes.JSON `gorm:"type:jsonb" json:"tags,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// resources (matching the migration and PROPOSAL §9).
func (Resource) TableName() string {
	return "resources"
}
