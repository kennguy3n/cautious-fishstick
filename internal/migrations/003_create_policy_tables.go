package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration003CreatePolicyTables creates the four Phase 3 tables
// (policies, teams, team_members, resources) per docs/architecture.md §11
// using GORM AutoMigrate.
//
// All indexes are declared on the model struct tags and materialised
// here. No FOREIGN KEY constraints (per SN360 database-index rule and
// docs/PHASES.md cross-cutting criteria); referential integrity to the
// workspaces, users, and connectors tables is enforced at the service
// layer.
//
// AutoMigrate is idempotent across runs and across the four models. If a
// future migration needs to add a column, it should be a new
// Migration00N file rather than mutating this one.
func Migration003CreatePolicyTables(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}

	// AutoMigrate each model in dependency-free order. There are no FKs,
	// so the order is purely cosmetic — kept matching docs/architecture.md
	// §11 for readability.
	tables := []interface{}{
		&models.Policy{},
		&models.Team{},
		&models.TeamMember{},
		&models.Resource{},
	}
	if err := db.AutoMigrate(tables...); err != nil {
		return fmt.Errorf("migrations: auto migrate policy tables: %w", err)
	}

	return nil
}

// migration003 is appended to All() in 001_create_access_connectors.go so
// the runner sees migrations in declaration order. Adding a new migration
// is a new file plus one append in All().
var migration003 = Migration{
	ID:   "003",
	Name: "create_policy_tables",
	Up:   Migration003CreatePolicyTables,
}
