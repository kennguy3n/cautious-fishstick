package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AccessCampaignSchedule mirrors the access_campaign_schedules table
// per docs/PROPOSAL.md §9 (Phase 5 scheduled campaigns) and
// docs/ARCHITECTURE.md §6. One row per recurring access-review
// (access check-up) schedule. The internal/cron CampaignScheduler
// scans this table for rows whose NextRunAt has elapsed and starts
// a fresh AccessReview for each — bumping NextRunAt by FrequencyDays
// after a successful start.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - WorkspaceID is the multi-tenant scoping dimension; schedules
//     never cross workspaces.
//   - ScopeFilter is the same JSON shape AccessReview.ScopeFilter
//     accepts. The scheduler passes it straight through to
//     AccessReviewService.StartCampaign.
//   - FrequencyDays is the cadence between runs. Operator-friendly
//     unit (admins set "every 90 days", not "every 7776000 seconds").
//   - NextRunAt is the timestamp the scheduler compares against the
//     wall clock. The Phase 5 CampaignScheduler updates this column
//     in the SAME database transaction that inserts the new
//     AccessReview row (see cron.CampaignScheduler.runOne and
//     access.AccessReviewService.StartCampaignTx) so a crash or DB
//     error between the two writes rolls back BOTH — never just one.
//     This is what guarantees a transient scheduler crash cannot
//     double-fire a campaign.
//   - IsActive is a soft-disable knob; operators can pause a schedule
//     without deleting it (and losing the historical NextRunAt).
//   - DeletedAt is the GORM soft-delete column.
//
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria); referential integrity to workspaces is enforced at the
// service layer.
type AccessCampaignSchedule struct {
	ID            string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID   string         `gorm:"type:varchar(26);not null;index:idx_access_campaign_schedules_workspace_active,priority:1" json:"workspace_id"`
	Name          string         `gorm:"type:varchar(255);not null" json:"name"`
	ScopeFilter   datatypes.JSON `gorm:"type:jsonb" json:"scope_filter,omitempty"`
	FrequencyDays int            `gorm:"not null" json:"frequency_days"`
	NextRunAt     time.Time      `gorm:"not null;index:idx_access_campaign_schedules_next_run_at" json:"next_run_at"`
	// SkipDates is a JSON array of "YYYY-MM-DD" strings (UTC). When
	// CampaignScheduler.Run sees today in this list, it bumps
	// NextRunAt forward by FrequencyDays WITHOUT starting a new
	// campaign. Operators populate this with company holidays /
	// freeze-window dates. Empty / unset means "never skip".
	//
	// Stored as JSON rather than a separate table because the list
	// is short (a few dates per year) and the cron only ever reads
	// the row holistically. The string format is RFC 3339 date-only
	// so cross-timezone interpretation is unambiguous.
	SkipDates datatypes.JSON `gorm:"type:jsonb" json:"skip_dates,omitempty"`
	IsActive  bool           `gorm:"not null;default:true;index:idx_access_campaign_schedules_workspace_active,priority:2" json:"is_active"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// SkipDateLayout is the canonical format for entries in
// AccessCampaignSchedule.SkipDates. Operators write
// "2026-12-25" / "2027-01-01" etc.
const SkipDateLayout = "2006-01-02"

// TableName overrides the default plural so the table name is exactly
// access_campaign_schedules (matching the migration and the schema in
// docs/PROPOSAL.md §9).
func (AccessCampaignSchedule) TableName() string {
	return "access_campaign_schedules"
}
