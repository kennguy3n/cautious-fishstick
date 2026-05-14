package cron

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newIdentitySchedulerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}, &models.AccessSyncState{}, &models.AccessJob{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedIdentityConnector(t *testing.T, db *gorm.DB, id string) {
	t.Helper()
	row := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01HWORKSPACE0000000000000A",
		Provider:      "test_provider",
		ConnectorType: "directory",
		Status:        models.StatusConnected,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
}

func seedSyncState(t *testing.T, db *gorm.DB, id, connID string, updatedAt time.Time) {
	t.Helper()
	row := &models.AccessSyncState{
		ID:          id,
		ConnectorID: connID,
		Kind:        models.SyncStateKindIdentity,
		DeltaLink:   "cp",
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed state: %v", err)
	}
	// SQLite ignores `default:CURRENT_TIMESTAMP`; force the
	// timestamp explicitly so the staleness probe sees what we
	// want.
	if err := db.Model(&models.AccessSyncState{}).Where("id = ?", id).Update("updated_at", updatedAt).Error; err != nil {
		t.Fatalf("set updated_at: %v", err)
	}
}

func TestIdentitySyncScheduler_EnqueuesStaleConnector(t *testing.T) {
	db := newIdentitySchedulerDB(t)
	const stale = "01HCONN0STALE000000000000A"
	const fresh = "01HCONN0FRESH000000000000A"
	const never = "01HCONN0NEVER000000000000A"
	seedIdentityConnector(t, db, stale)
	seedIdentityConnector(t, db, fresh)
	seedIdentityConnector(t, db, never)
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	seedSyncState(t, db, "01HSYNC0STALE00000000000A", stale, now.Add(-48*time.Hour))
	seedSyncState(t, db, "01HSYNC0FRESH00000000000A", fresh, now.Add(-1*time.Hour))

	s := NewIdentitySyncScheduler(db, 24*time.Hour)
	s.SetClock(func() time.Time { return now })

	enqueued, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if enqueued != 2 {
		t.Errorf("enqueued = %d; want 2 (stale + never)", enqueued)
	}

	// Verify real DB rows.
	var jobs []models.AccessJob
	if err := db.Find(&jobs).Error; err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d access_jobs rows; want 2", len(jobs))
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.ConnectorID] = true
		if j.JobType != models.AccessJobTypeSyncIdentities {
			t.Errorf("job %s type = %q; want sync_identities", j.ID, j.JobType)
		}
		if j.Status != models.AccessJobStatusPending {
			t.Errorf("job %s status = %q; want pending", j.ID, j.Status)
		}
	}
	if !seen[stale] || !seen[never] {
		t.Errorf("enqueued connectors = %v; want stale + never", seen)
	}
	if seen[fresh] {
		t.Error("fresh connector was enqueued; expected to skip")
	}
}

func TestIdentitySyncScheduler_SkipsDeletedConnector(t *testing.T) {
	db := newIdentitySchedulerDB(t)
	const deleted = "01HCONN0DELETED0000000000A"
	seedIdentityConnector(t, db, deleted)
	// Soft-delete.
	if err := db.Delete(&models.AccessConnector{}, "id = ?", deleted).Error; err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	s := NewIdentitySyncScheduler(db, 24*time.Hour)
	enqueued, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if enqueued != 0 {
		t.Errorf("enqueued = %d; want 0 (deleted connectors must be skipped)", enqueued)
	}
}
