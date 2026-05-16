package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration016CreatePAMTables creates the eight Privileged Access
// Management tables per docs/pam/architecture.md using GORM
// AutoMigrate. The composite and single-column indexes declared on
// the model struct tags are materialised here; this migration also
// installs the supplementary indexes called out in the milestone-1
// task list (e.g. pam_leases(workspace_id, user_id)).
//
// No FOREIGN KEY constraints (per SN360 database-index rules and
// docs/architecture.md cross-cutting criteria). Referential integrity
// to the workspaces / users / access_requests tables is enforced at
// the service layer.
//
// AutoMigrate is idempotent across runs and across the eight models.
// Adding a column or a new table is a new Migration0NN file rather
// than mutating this one.
func Migration016CreatePAMTables(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}

	tables := []interface{}{
		&models.PAMAsset{},
		&models.PAMAccount{},
		&models.PAMSecret{},
		&models.PAMSession{},
		&models.PAMSessionCommand{},
		&models.PAMLease{},
		&models.PAMCommandPolicy{},
		&models.PAMRotationSchedule{},
	}
	if err := db.AutoMigrate(tables...); err != nil {
		return fmt.Errorf("migrations: auto migrate pam tables: %w", err)
	}

	// Supplementary indexes the model tags do not declare. These are
	// per-dialect-safe (GORM emits IF NOT EXISTS where supported) and
	// idempotent across runs.
	supplementary := []struct {
		table   string
		name    string
		columns string
	}{
		{"pam_sessions", "idx_pam_sessions_user_id", "user_id"},
		{"pam_sessions", "idx_pam_sessions_workspace_id", "workspace_id"},
		{"pam_leases", "idx_pam_leases_expires_at", "expires_at"},
		{"pam_assets", "idx_pam_assets_workspace_id", "workspace_id"},
		{"pam_accounts", "idx_pam_accounts_asset_id", "asset_id"},
	}
	for _, ix := range supplementary {
		// Use GORM's migrator to install the index — translates to the
		// correct dialect-specific CREATE INDEX. Skip when the index
		// already exists (AutoMigrate may have created it from the
		// struct tag).
		if db.Migrator().HasIndex(ix.table, ix.name) {
			continue
		}
		if err := db.Exec(
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s)", ix.name, ix.table, ix.columns),
		).Error; err != nil {
			return fmt.Errorf("migrations: create supplementary index %s: %w", ix.name, err)
		}
	}

	return nil
}

// migration016 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration016 = Migration{
	ID:   "016",
	Name: "create_pam_tables",
	Up:   Migration016CreatePAMTables,
}
