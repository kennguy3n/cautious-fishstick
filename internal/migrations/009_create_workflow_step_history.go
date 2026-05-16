package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration009CreateWorkflowStepHistory creates the
// access_workflow_step_history table per docs/architecture.md Phase 8
// Task 4. The composite (request_id, step_index) index on the model
// is materialised here so operators can query the per-step audit
// trail for a single request in O(steps) without a full scan.
//
// No FOREIGN KEY constraints (per docs/architecture.md cross-cutting
// criteria); referential integrity to access_requests / access_workflows
// is enforced at the service layer.
func Migration009CreateWorkflowStepHistory(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessWorkflowStepHistory{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_workflow_step_history: %w", err)
	}
	return nil
}

// migration009 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration009 = Migration{
	ID:   "009",
	Name: "create_workflow_step_history",
	Up:   Migration009CreateWorkflowStepHistory,
}
