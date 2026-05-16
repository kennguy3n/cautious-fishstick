package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration004CreateAccessReviewTables creates the two Phase 5 tables
// (access_reviews, access_review_decisions) per docs/architecture.md §11
// and docs/architecture.md §7 using GORM AutoMigrate.
//
// All indexes are declared on the model struct tags and materialised
// here. No FOREIGN KEY constraints (per SN360 database-index rule and
// docs/architecture.md cross-cutting criteria); referential integrity to the
// workspaces, access_grants, and users tables is enforced at the
// service layer.
//
// AutoMigrate is idempotent across runs and across the two models. If
// a future migration needs to add a column, it should be a new
// Migration00N file rather than mutating this one.
func Migration004CreateAccessReviewTables(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	tables := []interface{}{
		&models.AccessReview{},
		&models.AccessReviewDecision{},
	}
	if err := db.AutoMigrate(tables...); err != nil {
		return fmt.Errorf("migrations: auto migrate access review tables: %w", err)
	}
	return nil
}

// migration004 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order. Adding a new
// migration is a new file plus one append in All().
var migration004 = Migration{
	ID:   "004",
	Name: "create_access_review_tables",
	Up:   Migration004CreateAccessReviewTables,
}
