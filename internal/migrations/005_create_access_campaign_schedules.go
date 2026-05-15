package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration005CreateAccessCampaignSchedules creates the
// access_campaign_schedules table per docs/overview.md §9 (Phase 5
// scheduled campaigns) using GORM AutoMigrate. The composite index
// on (workspace_id, is_active) and the standalone next_run_at index
// are declared on the model struct tags and materialised here.
//
// No FOREIGN KEY constraints (per docs/internal/PHASES.md cross-cutting
// criteria); referential integrity to the workspaces table is
// enforced at the service layer.
func Migration005CreateAccessCampaignSchedules(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessCampaignSchedule{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_campaign_schedules: %w", err)
	}
	return nil
}

// migration005 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration005 = Migration{
	ID:   "005",
	Name: "create_access_campaign_schedules",
	Up:   Migration005CreateAccessCampaignSchedules,
}
