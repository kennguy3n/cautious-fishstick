package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration014CreateAccessOrphanAccounts creates the Phase 11
// access_orphan_accounts table per docs/architecture.md §13 using
// GORM AutoMigrate.
//
// All indexes are declared on the AccessOrphanAccount struct tags
// and materialised here. No FOREIGN KEY constraints (per SN360
// database-index rule and docs/PHASES.md cross-cutting criteria);
// referential integrity to access_connectors and workspaces is
// enforced at the service layer.
//
// AutoMigrate is idempotent across runs.
func Migration014CreateAccessOrphanAccounts(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_orphan_accounts: %w", err)
	}
	return nil
}

// migration014 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration014 = Migration{
	ID:   "014",
	Name: "create_access_orphan_accounts",
	Up:   Migration014CreateAccessOrphanAccounts,
}
