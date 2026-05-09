// Package migrations contains GORM-based schema migrations for the ShieldNet
// 360 Access Platform. Migrations are functions that take a *gorm.DB and
// either AutoMigrate models or apply targeted ALTERs through the GORM
// migrator. No raw SQL — see docs/PHASES.md cross-cutting criteria.
package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration001CreateAccessConnectors creates the access_connectors table per
// docs/PROPOSAL.md §9.1 using GORM AutoMigrate. The composite index on
// (workspace_id, provider, connector_type) is declared on the model and
// materialised here.
//
// No FOREIGN KEY constraints (per SN360 database-index-rules and
// docs/PHASES.md cross-cutting criteria). Referential integrity to the
// workspaces table is enforced at the service layer.
func Migration001CreateAccessConnectors(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}

	// AutoMigrate creates the table, all indexes declared on the struct
	// tags, and the soft-delete column. It is idempotent across runs.
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_connectors: %w", err)
	}

	return nil
}

// Migration is the minimal interface the wider runner expects. Every
// migration in this package satisfies it so they can be enumerated and run
// in order by a future `cmd/access-migrate` binary.
type Migration struct {
	ID   string
	Name string
	Up   func(db *gorm.DB) error
}

// All returns the ordered list of migrations defined in this package. New
// migrations append to the end; never reorder existing entries.
func All() []Migration {
	return []Migration{
		{
			ID:   "001",
			Name: "create_access_connectors",
			Up:   Migration001CreateAccessConnectors,
		},
		migration002,
		migration003,
		migration004,
		migration005,
		migration006,
		migration007,
	}
}
