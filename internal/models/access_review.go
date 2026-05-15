package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessReview mirrors the access_reviews table per docs/architecture.md
// §11 and docs/architecture.md §7. One row per access-review campaign;
// each campaign holds many AccessReviewDecision rows (one per
// access_grant in scope).
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rule). WorkspaceID is the multi-tenant scoping dimension.
//   - ScopeFilter is a JSON object describing which access_grants are
//     enrolled when the campaign starts (e.g.
//     {"connector_id": "...", "category": "ssh-host"}).
//     The filter is evaluated once at StartCampaign time; the
//     enumerated grants are pinned to the campaign through
//     AccessReviewDecision rows so later grant churn does not change
//     the decision set.
//   - DueAt is the timestamp by which all reviewers should have
//     submitted decisions. CloseCampaign uses it (via configurable
//     auto-revoke-after-due policies in Phase 6+) but Phase 5 just
//     stores it for surface in the admin UI.
//   - State follows the small FSM open → (closed | cancelled). A
//     cancelled review can be reopened in Phase 6+ but Phase 5 treats
//     cancellation as terminal.
//   - AutoCertifyEnabled gates the AI auto-certification path. When
//     false, every grant gets a "pending" decision and must be
//     reviewed manually.
//   - DeletedAt is the GORM soft-delete column.
type AccessReview struct {
	ID                 string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID        string         `gorm:"type:varchar(26);not null;index:idx_access_reviews_workspace_state,priority:1" json:"workspace_id"`
	Name               string         `gorm:"type:varchar(255);not null" json:"name"`
	ScopeFilter        datatypes.JSON `gorm:"type:jsonb" json:"scope_filter,omitempty"`
	DueAt              time.Time      `gorm:"not null" json:"due_at"`
	State              string         `gorm:"type:varchar(20);not null;default:'open';index:idx_access_reviews_workspace_state,priority:2" json:"state"`
	AutoCertifyEnabled bool           `gorm:"not null;default:true" json:"auto_certify_enabled"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// TableName overrides the default plural so the table name is exactly
// access_reviews (matching the migration and docs/architecture.md §11).
func (AccessReview) TableName() string {
	return "access_reviews"
}

// ReviewState enumerates the legal values of AccessReview.State.
// Strings are operator-visible in the admin UI translation table;
// renaming any of them is a database migration, not a refactor.
const (
	// ReviewStateOpen is a campaign that has been started but not yet
	// closed. Reviewers may submit decisions while the campaign is
	// open.
	ReviewStateOpen = "open"
	// ReviewStateClosed is a campaign that has been finalised. No
	// further decisions are accepted; AutoRevoke must run before close
	// (or as part of close) so revoke decisions are realised.
	ReviewStateClosed = "closed"
	// ReviewStateCancelled is a campaign that has been abandoned. All
	// outstanding decisions are tombstoned; no revocations happen.
	ReviewStateCancelled = "cancelled"
)
