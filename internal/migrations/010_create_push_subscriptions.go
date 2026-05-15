package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration010CreatePushSubscriptions creates the push_subscriptions
// table per docs/internal/PHASES.md Phase 5 Task 10. The composite
// (workspace_id, user_id) index defined on the model is materialised
// here so the WebPushNotifier resolver can fetch a user's
// subscriptions in O(1) lookups.
//
// No FOREIGN KEY constraints (per docs/internal/PHASES.md cross-cutting
// criteria); referential integrity to workspaces / users is enforced
// at the service layer.
func Migration010CreatePushSubscriptions(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.PushSubscription{}); err != nil {
		return fmt.Errorf("migrations: auto migrate push_subscriptions: %w", err)
	}
	return nil
}

var migration010 = Migration{
	ID:   "010",
	Name: "create_push_subscriptions",
	Up:   Migration010CreatePushSubscriptions,
}
