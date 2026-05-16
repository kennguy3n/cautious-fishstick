package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration013AddAccessModeColumn materialises the access_mode column
// on the access_connectors table declared on the AccessConnector
// model. Phase 11 (Hybrid Access Model) introduces the column to
// classify connectors into one of three modes:
//
//   - "tunnel"   — private resource fronted by an OpenZiti dataplane.
//   - "sso_only" — SaaS app federated through Keycloak.
//   - "api_only" — SaaS app reachable via the REST API directly.
//
// AutoMigrate on AccessConnector is idempotent — on a fresh DB it
// creates the table with the column; on an existing DB at migration
// 012 it issues a single ALTER TABLE ... ADD COLUMN with the
// declared default of 'api_only'. No FOREIGN KEY constraints (per
// docs/architecture.md cross-cutting criteria) and no raw SQL.
func Migration013AddAccessModeColumn(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_connectors access_mode column: %w", err)
	}
	return nil
}

// migration013 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration013 = Migration{
	ID:   "013",
	Name: "add_access_mode_column",
	Up:   Migration013AddAccessModeColumn,
}
