package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newSyncStateDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// TestSyncStateService_GetMissingReturnsEmpty asserts that a Get on
// a connector / kind pair without a row surfaces an empty cursor +
// nil error. Callers treat this as "no cursor; do a full sync".
func TestSyncStateService_GetMissingReturnsEmpty(t *testing.T) {
	svc := NewSyncStateService(newSyncStateDB(t))
	got, err := svc.Get(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindIdentity)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Errorf("Get = %q; want empty string", got)
	}
}

// TestSyncStateService_SetThenGetRoundTrip asserts a delta link
// written via Set is read back via Get verbatim.
func TestSyncStateService_SetThenGetRoundTrip(t *testing.T) {
	svc := NewSyncStateService(newSyncStateDB(t))
	const wantLink = "https://graph.microsoft.com/v1.0/users/delta?$skiptoken=ABC123"

	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindIdentity, wantLink); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := svc.Get(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindIdentity)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != wantLink {
		t.Errorf("Get = %q; want %q", got, wantLink)
	}
}

// TestSyncStateService_SetUpsertsExistingRow asserts a second Set
// for the same (connector_id, kind) overwrites the delta_link in
// place rather than inserting a duplicate row.
func TestSyncStateService_SetUpsertsExistingRow(t *testing.T) {
	db := newSyncStateDB(t)
	svc := NewSyncStateService(db)

	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindGroup, "cursor-v1"); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindGroup, "cursor-v2"); err != nil {
		t.Fatalf("Set v2: %v", err)
	}

	got, err := svc.Get(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindGroup)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "cursor-v2" {
		t.Errorf("Get = %q; want cursor-v2 (Set must upsert)", got)
	}

	var count int64
	if err := db.Model(&models.AccessSyncState{}).
		Where("connector_id = ? AND kind = ?", "01HCONNECTOR000000000000A1", models.SyncStateKindGroup).
		Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("row count = %d; want exactly 1 (no duplicate inserts)", count)
	}
}

// TestSyncStateService_SetEmptyConnectorIDValidationError asserts
// that a missing connector_id surfaces as an ErrValidation-wrapped
// error before any DB I/O.
func TestSyncStateService_SetEmptyConnectorIDValidationError(t *testing.T) {
	svc := NewSyncStateService(newSyncStateDB(t))
	err := svc.Set(context.Background(), "", models.SyncStateKindIdentity, "x")
	if err == nil {
		t.Fatal("Set returned nil; want validation error")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want ErrValidation", err)
	}
}

// TestSyncStateService_SetUnknownKindValidationError asserts that a
// kind outside the canonical set surfaces as ErrValidation.
func TestSyncStateService_SetUnknownKindValidationError(t *testing.T) {
	svc := NewSyncStateService(newSyncStateDB(t))
	err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", "bogus", "x")
	if err == nil {
		t.Fatal("Set returned nil; want validation error")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want ErrValidation", err)
	}
}

// TestSyncStateService_GetUnknownKindValidationError mirrors the
// Set check on the read path so callers that pass a typo get a
// surfaced error rather than a silent empty-cursor return.
func TestSyncStateService_GetUnknownKindValidationError(t *testing.T) {
	svc := NewSyncStateService(newSyncStateDB(t))
	_, err := svc.Get(context.Background(), "01HCONNECTOR000000000000A1", "bogus")
	if err == nil {
		t.Fatal("Get returned nil; want validation error")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want ErrValidation", err)
	}
}

// TestSyncStateService_SetUpdatesUpdatedAt asserts that re-writing
// a cursor advances UpdatedAt while preserving CreatedAt — admins
// rely on UpdatedAt to spot stalled sync pipelines.
func TestSyncStateService_SetUpdatesUpdatedAt(t *testing.T) {
	db := newSyncStateDB(t)
	svc := NewSyncStateService(db)
	t0 := time.Date(2025, 11, 1, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)

	svc.SetClock(func() time.Time { return t0 })
	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindAudit, "v1"); err != nil {
		t.Fatalf("Set t0: %v", err)
	}

	svc.SetClock(func() time.Time { return t1 })
	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindAudit, "v2"); err != nil {
		t.Fatalf("Set t1: %v", err)
	}

	var row models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", "01HCONNECTOR000000000000A1", models.SyncStateKindAudit).First(&row).Error; err != nil {
		t.Fatalf("readback: %v", err)
	}
	if !row.UpdatedAt.Equal(t1) {
		t.Errorf("UpdatedAt = %v; want %v", row.UpdatedAt, t1)
	}
	if !row.CreatedAt.Equal(t0) {
		t.Errorf("CreatedAt = %v; want %v (must not advance on upsert)", row.CreatedAt, t0)
	}
}

// TestSyncStateService_PerKindIsolated asserts the (connector_id,
// kind) uniqueness boundary: writing the identity cursor does not
// touch the group cursor for the same connector.
func TestSyncStateService_PerKindIsolated(t *testing.T) {
	svc := NewSyncStateService(newSyncStateDB(t))
	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindIdentity, "ident-cursor"); err != nil {
		t.Fatalf("Set identity: %v", err)
	}
	if err := svc.Set(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindGroup, "group-cursor"); err != nil {
		t.Fatalf("Set group: %v", err)
	}

	gotIdent, err := svc.Get(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindIdentity)
	if err != nil {
		t.Fatalf("Get identity: %v", err)
	}
	if gotIdent != "ident-cursor" {
		t.Errorf("identity cursor = %q; want ident-cursor", gotIdent)
	}
	gotGroup, err := svc.Get(context.Background(), "01HCONNECTOR000000000000A1", models.SyncStateKindGroup)
	if err != nil {
		t.Fatalf("Get group: %v", err)
	}
	if gotGroup != "group-cursor" {
		t.Errorf("group cursor = %q; want group-cursor", gotGroup)
	}
}
