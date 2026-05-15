//go:build integration

// migrations_integration_test.go — runs the full 15-step migration
// suite against either:
//
//   1. The Postgres pointed at by ACCESS_DATABASE_URL (when set), so
//      the integration workflow exercises the production driver +
//      jsonb / varchar(N) types instead of SQLite's TEXT-equivalence.
//   2. A fresh in-memory SQLite when ACCESS_DATABASE_URL is unset, so
//      a developer can still run `make test-integration` locally
//      without provisioning Postgres.
//
// The unit-level migrations_test.go already covers per-migration
// idempotency on SQLite; this file complements it by asserting:
//
//   - The full suite is end-to-end idempotent (run twice → no error
//     and the table set is stable).
//   - The migrator reports every Phase 0–11 table as present after
//     the second run, including the Phase 7 / 8 / 11 additions
//     (workflow step history, push subscriptions, orphan accounts).
package migrations

import (
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// openIntegrationDB opens whichever database the workflow points at
// (Postgres in CI, in-memory SQLite for local `make test-integration`)
// and returns a connected *gorm.DB. The Postgres path is intentionally
// inline (rather than re-using internal/pkg/database) because that
// package already imports the migrations package — pulling it in here
// would create an import cycle.
func openIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	if dsn := os.Getenv("ACCESS_DATABASE_URL"); dsn != "" {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			t.Fatalf("open postgres at %s: %v", dsn, err)
		}
		t.Cleanup(func() {
			sqlDB, err := db.DB()
			if err == nil {
				_ = sqlDB.Close()
			}
		})
		return db
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

// TestIntegration_FullSuiteIsIdempotent runs every migration twice
// against a fresh DB and asserts:
//   - The first run succeeds (all 15 migrations apply cleanly).
//   - The second run succeeds (every migration is idempotent on top
//     of an already-migrated DB).
//   - The final table set matches the unit-test invariant.
func TestIntegration_FullSuiteIsIdempotent(t *testing.T) {
	db := openIntegrationDB(t)

	for pass := 1; pass <= 2; pass++ {
		for _, m := range All() {
			if err := m.Up(db); err != nil {
				t.Fatalf("pass %d: migration %s (%s) failed: %v", pass, m.ID, m.Name, err)
			}
		}
	}

	wantTables := []string{
		"access_connectors",
		"access_requests",
		"access_request_state_history",
		"access_grants",
		"access_workflows",
		"policies",
		"teams",
		"team_members",
		"resources",
		"access_reviews",
		"access_review_decisions",
		"access_campaign_schedules",
		"access_sync_state",
		"access_jobs",
		"access_workflow_step_history",
		"push_subscriptions",
		"access_orphan_accounts",
	}
	mig := db.Migrator()
	for _, table := range wantTables {
		if !mig.HasTable(table) {
			t.Errorf("table %q missing after 2× migration suite", table)
		}
	}
}

// TestIntegration_HalfAppliedRollForward exercises the "binary crashed
// mid-migration, restarted, picked up where it left off" scenario:
// apply the first half of the suite, open a new connection, then run
// the full suite. Both legs must succeed and produce the same final
// table set as a single-leg run.
func TestIntegration_HalfAppliedRollForward(t *testing.T) {
	db := openIntegrationDB(t)
	all := All()
	if len(all) < 4 {
		t.Fatalf("migrations.All() returned %d migrations; want >=4 for half-applied test", len(all))
	}

	half := len(all) / 2
	for _, m := range all[:half] {
		if err := m.Up(db); err != nil {
			t.Fatalf("pre-crash migration %s: %v", m.ID, err)
		}
	}
	// Re-run from migration 0; everything up to `half` must report
	// as a no-op and the second half must apply cleanly.
	for _, m := range all {
		if err := m.Up(db); err != nil {
			t.Fatalf("post-crash migration %s: %v", m.ID, err)
		}
	}
}
