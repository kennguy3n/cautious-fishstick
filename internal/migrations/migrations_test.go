package migrations

import (
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// jsonUnmarshal is a thin wrapper around encoding/json.Unmarshal that
// accepts a datatypes.JSON column directly so the migration tests can
// inspect the seeded Steps payload without a re-cast at every callsite.
func jsonUnmarshal(raw datatypes.JSON, into interface{}) error {
	return json.Unmarshal([]byte(raw), into)
}

// openTestDB opens a fresh in-memory SQLite database for one test case.
// SQLite has dynamic typing so the postgres-flavoured `type:jsonb` and
// `varchar(N)` tags on the model structs are accepted as TEXT-equivalent;
// AutoMigrate still creates the indexes declared on the struct tags.
//
// Each call returns an isolated DB so tests can run in parallel.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

// TestAll_ReturnsAllMigrations asserts that the ordered All() list contains
// every migration declared in this package, in the expected order. This
// catches "added the file but forgot to wire it into All()" wiring bugs.
func TestAll_ReturnsAllMigrations(t *testing.T) {
	got := All()
	want := []string{"001", "002", "003", "004", "005", "006", "007", "008", "009", "010", "011", "012"}
	if len(got) != len(want) {
		t.Fatalf("All() returned %d migrations; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Errorf("All()[%d].ID = %q; want %q", i, got[i].ID, want[i])
		}
		if got[i].Up == nil {
			t.Errorf("All()[%d].Up is nil", i)
		}
	}
}

// TestRunAll_AutoMigratesEveryTable runs every migration in order against
// a fresh in-memory SQLite DB and asserts that the expected tables exist
// afterwards. It is intentionally agnostic to the underlying SQL flavour
// — we only care that AutoMigrate succeeds and the migrator reports each
// table as present.
func TestRunAll_AutoMigratesEveryTable(t *testing.T) {
	db := openTestDB(t)

	for _, m := range All() {
		if err := m.Up(db); err != nil {
			t.Fatalf("migration %s (%s) failed: %v", m.ID, m.Name, err)
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
	}
	mig := db.Migrator()
	for _, table := range wantTables {
		if !mig.HasTable(table) {
			t.Errorf("expected table %q to exist after migrations", table)
		}
	}
}

// TestMigration002_IsIdempotent asserts that running the Phase 2 migration
// a second time is a no-op. AutoMigrate is idempotent by contract; we
// regression-test it because losing that property silently is one of the
// scarier ways a migration can go wrong in production.
func TestMigration002_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration001CreateAccessConnectors(db); err != nil {
		t.Fatalf("migration 001 failed: %v", err)
	}
	if err := Migration002CreateAccessRequestTables(db); err != nil {
		t.Fatalf("first run of migration 002 failed: %v", err)
	}
	if err := Migration002CreateAccessRequestTables(db); err != nil {
		t.Fatalf("second run of migration 002 was not idempotent: %v", err)
	}
}

// TestMigration002_RejectsNilDB exercises the defensive guard so we are
// notified if a future refactor accidentally drops it.
func TestMigration002_RejectsNilDB(t *testing.T) {
	if err := Migration002CreateAccessRequestTables(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration003_IsIdempotent asserts that running the Phase 3 migration
// a second time is a no-op. AutoMigrate is idempotent by contract; we
// regression-test it because losing that property silently is one of the
// scarier ways a migration can go wrong in production.
func TestMigration003_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration001CreateAccessConnectors(db); err != nil {
		t.Fatalf("migration 001 failed: %v", err)
	}
	if err := Migration002CreateAccessRequestTables(db); err != nil {
		t.Fatalf("migration 002 failed: %v", err)
	}
	if err := Migration003CreatePolicyTables(db); err != nil {
		t.Fatalf("first run of migration 003 failed: %v", err)
	}
	if err := Migration003CreatePolicyTables(db); err != nil {
		t.Fatalf("second run of migration 003 was not idempotent: %v", err)
	}
}

// TestMigration003_RejectsNilDB exercises the defensive guard so we are
// notified if a future refactor accidentally drops it.
func TestMigration003_RejectsNilDB(t *testing.T) {
	if err := Migration003CreatePolicyTables(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration004_IsIdempotent asserts that running the Phase 5
// migration a second time is a no-op. AutoMigrate is idempotent by
// contract; we regression-test it because losing that property
// silently is one of the scarier ways a migration can go wrong in
// production.
func TestMigration004_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration001CreateAccessConnectors(db); err != nil {
		t.Fatalf("migration 001 failed: %v", err)
	}
	if err := Migration002CreateAccessRequestTables(db); err != nil {
		t.Fatalf("migration 002 failed: %v", err)
	}
	if err := Migration003CreatePolicyTables(db); err != nil {
		t.Fatalf("migration 003 failed: %v", err)
	}
	if err := Migration004CreateAccessReviewTables(db); err != nil {
		t.Fatalf("first run of migration 004 failed: %v", err)
	}
	if err := Migration004CreateAccessReviewTables(db); err != nil {
		t.Fatalf("second run of migration 004 was not idempotent: %v", err)
	}
}

// TestMigration004_RejectsNilDB exercises the defensive guard so we are
// notified if a future refactor accidentally drops it.
func TestMigration004_RejectsNilDB(t *testing.T) {
	if err := Migration004CreateAccessReviewTables(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration005_IsIdempotent asserts that running the Phase 5
// scheduled-campaigns migration a second time is a no-op.
func TestMigration005_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration005CreateAccessCampaignSchedules(db); err != nil {
		t.Fatalf("first run of migration 005 failed: %v", err)
	}
	if err := Migration005CreateAccessCampaignSchedules(db); err != nil {
		t.Fatalf("second run of migration 005 was not idempotent: %v", err)
	}
}

// TestMigration005_RejectsNilDB exercises the defensive guard.
func TestMigration005_RejectsNilDB(t *testing.T) {
	if err := Migration005CreateAccessCampaignSchedules(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration006_IsIdempotent asserts that running the Phase 6
// access_sync_state migration a second time is a no-op.
func TestMigration006_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration006CreateAccessSyncState(db); err != nil {
		t.Fatalf("first run of migration 006 failed: %v", err)
	}
	if err := Migration006CreateAccessSyncState(db); err != nil {
		t.Fatalf("second run of migration 006 was not idempotent: %v", err)
	}
}

// TestMigration006_RejectsNilDB exercises the defensive guard.
func TestMigration006_RejectsNilDB(t *testing.T) {
	if err := Migration006CreateAccessSyncState(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration007_IsIdempotent asserts that running the Phase 6
// access_jobs migration a second time is a no-op.
func TestMigration007_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration007CreateAccessJobs(db); err != nil {
		t.Fatalf("first run of migration 007 failed: %v", err)
	}
	if err := Migration007CreateAccessJobs(db); err != nil {
		t.Fatalf("second run of migration 007 was not idempotent: %v", err)
	}
}

// TestMigration007_RejectsNilDB exercises the defensive guard.
func TestMigration007_RejectsNilDB(t *testing.T) {
	if err := Migration007CreateAccessJobs(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration008_SeedsAllTemplates asserts that running the
// Phase 8 seed migration creates the four canonical workflow
// templates with valid step JSON.
func TestMigration008_SeedsAllTemplates(t *testing.T) {
	db := openTestDB(t)
	if err := Migration002CreateAccessRequestTables(db); err != nil {
		t.Fatalf("migration 002: %v", err)
	}
	if err := Migration008SeedWorkflowTemplates(db); err != nil {
		t.Fatalf("migration 008: %v", err)
	}
	wantNames := []string{
		WorkflowTemplateNewHireOnboarding,
		WorkflowTemplateContractorOnboard,
		WorkflowTemplateRoleChange,
		WorkflowTemplateProjectAccess,
	}
	for _, name := range wantNames {
		var wf models.AccessWorkflow
		if err := db.Where("name = ?", name).First(&wf).Error; err != nil {
			t.Fatalf("template %q not seeded: %v", name, err)
		}
		if !wf.IsActive {
			t.Errorf("template %q: IsActive false", name)
		}
		if len(wf.Steps) == 0 {
			t.Errorf("template %q: empty Steps", name)
		}
		// Steps decodes as valid JSON.
		var steps []models.WorkflowStepDefinition
		if err := jsonUnmarshal(wf.Steps, &steps); err != nil {
			t.Errorf("template %q: steps not valid JSON: %v", name, err)
		}
		if len(steps) == 0 {
			t.Errorf("template %q: zero decoded steps", name)
		}
	}
}

// TestMigration008_IsIdempotent asserts that re-running the seed is a no-op.
func TestMigration008_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration002CreateAccessRequestTables(db); err != nil {
		t.Fatalf("migration 002: %v", err)
	}
	if err := Migration008SeedWorkflowTemplates(db); err != nil {
		t.Fatalf("first run: %v", err)
	}
	var beforeCount int64
	if err := db.Model(&models.AccessWorkflow{}).Count(&beforeCount).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if err := Migration008SeedWorkflowTemplates(db); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var afterCount int64
	if err := db.Model(&models.AccessWorkflow{}).Count(&afterCount).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if beforeCount != afterCount {
		t.Errorf("template count changed on re-run: %d → %d", beforeCount, afterCount)
	}
}

// TestMigration008_RejectsNilDB exercises the defensive guard.
func TestMigration008_RejectsNilDB(t *testing.T) {
	if err := Migration008SeedWorkflowTemplates(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration009_IsIdempotent asserts that running the Phase 8
// step-history migration a second time is a no-op.
func TestMigration009_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration009CreateWorkflowStepHistory(db); err != nil {
		t.Fatalf("first run of migration 009 failed: %v", err)
	}
	if err := Migration009CreateWorkflowStepHistory(db); err != nil {
		t.Fatalf("second run of migration 009 was not idempotent: %v", err)
	}
	if !db.Migrator().HasTable(&models.AccessWorkflowStepHistory{}) {
		t.Error("step history table missing after migration")
	}
}

// TestMigration009_RejectsNilDB exercises the defensive guard.
func TestMigration009_RejectsNilDB(t *testing.T) {
	if err := Migration009CreateWorkflowStepHistory(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestMigration010_IsIdempotent asserts that running the Phase 5
// push subscription migration a second time is a no-op.
func TestMigration010_IsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migration010CreatePushSubscriptions(db); err != nil {
		t.Fatalf("first run of migration 010 failed: %v", err)
	}
	if err := Migration010CreatePushSubscriptions(db); err != nil {
		t.Fatalf("second run of migration 010 was not idempotent: %v", err)
	}
	if !db.Migrator().HasTable(&models.PushSubscription{}) {
		t.Error("push_subscriptions table missing")
	}
}

// TestMigration010_RejectsNilDB exercises the defensive guard.
func TestMigration010_RejectsNilDB(t *testing.T) {
	if err := Migration010CreatePushSubscriptions(nil); err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestModelTableNames pins the TableName() overrides so accidental renames
// surface as a unit-test failure instead of an at-runtime migration mismatch.
func TestModelTableNames(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"access_request", (models.AccessRequest{}).TableName(), "access_requests"},
		{"state_history", (models.AccessRequestStateHistory{}).TableName(), "access_request_state_history"},
		{"access_grant", (models.AccessGrant{}).TableName(), "access_grants"},
		{"access_workflow", (models.AccessWorkflow{}).TableName(), "access_workflows"},
		{"policy", (models.Policy{}).TableName(), "policies"},
		{"team", (models.Team{}).TableName(), "teams"},
		{"team_member", (models.TeamMember{}).TableName(), "team_members"},
		{"resource", (models.Resource{}).TableName(), "resources"},
		{"access_review", (models.AccessReview{}).TableName(), "access_reviews"},
		{"access_review_decision", (models.AccessReviewDecision{}).TableName(), "access_review_decisions"},
		{"access_campaign_schedule", (models.AccessCampaignSchedule{}).TableName(), "access_campaign_schedules"},
		{"access_sync_state", (models.AccessSyncState{}).TableName(), "access_sync_state"},
		{"access_job", (models.AccessJob{}).TableName(), "access_jobs"},
		{"access_workflow_step_history", (models.AccessWorkflowStepHistory{}).TableName(), "access_workflow_step_history"},
		{"push_subscription", (models.PushSubscription{}).TableName(), "push_subscriptions"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: TableName() = %q; want %q", tc.name, tc.got, tc.want)
		}
	}
}
