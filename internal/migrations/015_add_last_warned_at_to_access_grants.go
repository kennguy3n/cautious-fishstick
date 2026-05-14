package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration015AddLastWarnedAtToAccessGrants materialises the
// last_warned_at column on the access_grants table declared on
// the AccessGrant model. Phase 11 batch 6 round-7 introduces the
// column to dedup grant-expiry warning notifications: the
// cron.GrantExpiryEnforcer.RunWarning sweep stamps this field
// after each successful "your access expires in N hours"
// notification, and skips grants whose LastWarnedAt is within
// the configured warning window (ACCESS_GRANT_EXPIRY_WARNING_HOURS).
//
// Without this dedup, a grant 12h from expiry would receive up to
// 12 duplicate notifications under the default
// ACCESS_GRANT_EXPIRY_CHECK_INTERVAL=1h cadence.
//
// AutoMigrate on AccessGrant is idempotent — on a fresh DB it
// creates the table with the column; on an existing DB at
// migration 014 it issues a single ALTER TABLE ... ADD COLUMN.
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria) and no raw SQL.
func Migration015AddLastWarnedAtToAccessGrants(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessGrant{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_grants last_warned_at column: %w", err)
	}
	return nil
}

// migration015 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration015 = Migration{
	ID:   "015",
	Name: "add_last_warned_at_to_access_grants",
	Up:   Migration015AddLastWarnedAtToAccessGrants,
}
