package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration002CreateAccessRequestTables creates the four Phase 2 tables
// (access_requests, access_request_state_history, access_grants,
// access_workflows) per docs/architecture.md §10 using GORM AutoMigrate.
//
// All indexes are declared on the model struct tags and materialised here.
// No FOREIGN KEY constraints (per SN360 database-index rules and
// docs/internal/PHASES.md cross-cutting criteria); referential integrity to the
// workspaces, users, and access_connectors tables is enforced at the
// service layer.
//
// AutoMigrate is idempotent across runs and across the four models. If a
// future migration needs to add a column, it should be a new
// Migration00N file rather than mutating this one.
func Migration002CreateAccessRequestTables(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}

	// AutoMigrate each model in dependency-free order. There are no FKs,
	// so the order is purely cosmetic — kept matching docs/architecture.md
	// §10 for readability.
	tables := []interface{}{
		&models.AccessRequest{},
		&models.AccessRequestStateHistory{},
		&models.AccessGrant{},
		&models.AccessWorkflow{},
	}
	if err := db.AutoMigrate(tables...); err != nil {
		return fmt.Errorf("migrations: auto migrate access request tables: %w", err)
	}

	return nil
}

// migration002 is appended to All() in 001_create_access_connectors.go so
// the runner sees migrations in declaration order. Adding a new migration
// is a new file plus one append in All().
var migration002 = Migration{
	ID:   "002",
	Name: "create_access_request_tables",
	Up:   Migration002CreateAccessRequestTables,
}
