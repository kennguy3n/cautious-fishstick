package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration011AddRequestEscalationTracking adds the
// last_escalated_at (nullable timestamp) and escalation_level
// (integer, default 0) columns to access_requests.
//
// These columns are written by NotifyingEscalator.Escalate and read
// by EscalationChecker.escalationTargets so a request that has
// already timed out is not escalated twice on subsequent polling
// passes (the EscalationChecker contract requires the Escalator
// implementation to de-dupe). The pair also drives multi_level
// advancement: each escalation increments escalation_level so the
// next pass picks Levels[level] → Levels[level+1].
//
// AutoMigrate is idempotent — for a fresh DB it creates the columns;
// for an existing DB at migration 010 it issues an ALTER TABLE that
// adds the two new columns without rewriting existing rows. No
// FOREIGN KEY constraints (per docs/internal/PHASES.md cross-cutting
// criteria).
func Migration011AddRequestEscalationTracking(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessRequest{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_requests escalation columns: %w", err)
	}
	return nil
}

// migration011 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration011 = Migration{
	ID:   "011",
	Name: "add_request_escalation_tracking",
	Up:   Migration011AddRequestEscalationTracking,
}
