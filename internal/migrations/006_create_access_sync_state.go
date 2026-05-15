package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration006CreateAccessSyncState creates the access_sync_state
// table per docs/architecture.md §11 + docs/architecture.md §3 using
// GORM AutoMigrate. The unique composite index on (connector_id,
// kind) is declared on the model struct tags and materialised here
// — a single connector never holds two open cursors of the same
// kind (identity / group / audit).
//
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria); referential integrity to access_connectors is enforced
// at the service layer.
func Migration006CreateAccessSyncState(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_sync_state: %w", err)
	}
	return nil
}

// migration006 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration006 = Migration{
	ID:   "006",
	Name: "create_access_sync_state",
	Up:   Migration006CreateAccessSyncState,
}
