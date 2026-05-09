package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration007CreateAccessJobs creates the access_jobs table per
// docs/ARCHITECTURE.md §10 using GORM AutoMigrate. The composite
// index on (connector_id, job_type, status) is declared on the
// model struct tags and materialised here — workers query for "my
// pending jobs" via a (status, job_type) prefix scan.
//
// No FOREIGN KEY constraints (per docs/PHASES.md cross-cutting
// criteria); referential integrity to access_connectors is
// enforced at the service layer.
func Migration007CreateAccessJobs(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessJob{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_jobs: %w", err)
	}
	return nil
}

// migration007 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration007 = Migration{
	ID:   "007",
	Name: "create_access_jobs",
	Up:   Migration007CreateAccessJobs,
}
