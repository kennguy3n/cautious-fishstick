package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestAccessAudit_Integration_CursorPersistsAcrossRuns drives
// HandleAccessAudit twice and asserts that the second run picks up
// where the first stopped — proving the cursor round-trips through
// access_sync_state without losing events.
func TestAccessAudit_Integration_CursorPersistsAcrossRuns(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	connectorID := "01HZZCONN00000000000000A1"
	seedTestConnector(t, db, connectorID, "okta")

	tA := time.Date(2024, 5, 1, 9, 0, 0, 0, time.UTC)
	tB := tA.Add(time.Hour)
	tC := tA.Add(2 * time.Hour)

	// Run 1: server returns two events, advancing cursor to tB.
	var runSawSince time.Time
	mockA := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, since map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			runSawSince = since[access.DefaultAuditPartition]
			return handler([]*access.AuditLogEntry{
				{EventID: "evA", Timestamp: tA},
				{EventID: "evB", Timestamp: tB},
			}, tB, access.DefaultAuditPartition)
		},
	}
	producer := &access.NoOpAuditProducer{}
	jc := JobContext{
		DB: db, Resolve: stubResolve(mockA), LoadConn: DefaultLoadConnector,
		Now: time.Now, AuditProducer: producer,
	}
	seedJob(t, db, "job-int-1", connectorID, "access_audit_log", nil)
	if err := AccessAudit(context.Background(), jc, "job-int-1"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if !runSawSince.IsZero() {
		t.Errorf("run 1 since = %s; want zero (fresh backfill)", runSawSince)
	}
	if producer.EntriesPublished() != 2 {
		t.Errorf("run 1 entries = %d; want 2", producer.EntriesPublished())
	}

	// Run 2: connector must observe `since == tB` (the persisted cursor).
	mockB := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, since map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			runSawSince = since[access.DefaultAuditPartition]
			return handler([]*access.AuditLogEntry{{EventID: "evC", Timestamp: tC}}, tC, access.DefaultAuditPartition)
		},
	}
	jc.Resolve = stubResolve(mockB)
	seedJob(t, db, "job-int-2", connectorID, "access_audit_log", nil)
	if err := AccessAudit(context.Background(), jc, "job-int-2"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if !runSawSince.Equal(tB) {
		t.Errorf("run 2 since = %s; want %s", runSawSince, tB)
	}

	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).First(&state).Error; err != nil {
		t.Fatalf("readback sync state: %v", err)
	}
	cursors := decodeAuditCursors(state.DeltaLink)
	if got, ok := cursors[access.DefaultAuditPartition]; !ok || !got.Equal(tC) {
		t.Errorf("persisted cursor = %v; want %s", cursors, tC)
	}
}

// TestAccessAudit_Integration_MultiPartitionCursorsIndependent
// asserts that a connector emitting two partitions (Microsoft Graph
// directoryAudits + signIns) advances each cursor independently.
// A regression in the single-cursor design previously caused a
// faster partition to shadow a slower one, dropping events.
func TestAccessAudit_Integration_MultiPartitionCursorsIndependent(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	connectorID := "01HZZCONN00000000000000B2"
	seedTestConnector(t, db, connectorID, "microsoft")

	dirAuditsAt := time.Date(2024, 5, 1, 9, 0, 0, 0, time.UTC)
	signInsAt := time.Date(2024, 5, 1, 13, 0, 0, 0, time.UTC)

	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			if err := handler([]*access.AuditLogEntry{{EventID: "dir-1", Timestamp: dirAuditsAt}}, dirAuditsAt, "directoryAudits"); err != nil {
				return err
			}
			return handler([]*access.AuditLogEntry{{EventID: "sig-1", Timestamp: signInsAt}}, signInsAt, "signIns")
		},
	}
	jc := JobContext{
		DB: db, Resolve: stubResolve(mock), LoadConn: DefaultLoadConnector,
		Now: time.Now, AuditProducer: &access.NoOpAuditProducer{},
	}
	seedJob(t, db, "job-int-3", connectorID, "access_audit_log", nil)
	if err := AccessAudit(context.Background(), jc, "job-int-3"); err != nil {
		t.Fatalf("run: %v", err)
	}
	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).First(&state).Error; err != nil {
		t.Fatalf("readback sync state: %v", err)
	}
	cursors := decodeAuditCursors(state.DeltaLink)
	if got, ok := cursors["directoryAudits"]; !ok || !got.Equal(dirAuditsAt) {
		t.Errorf("directoryAudits cursor = %v; want %s", cursors, dirAuditsAt)
	}
	if got, ok := cursors["signIns"]; !ok || !got.Equal(signInsAt) {
		t.Errorf("signIns cursor = %v; want %s", cursors, signInsAt)
	}
	// The DeltaLink must be a JSON object, not a bare timestamp.
	if !strings.HasPrefix(strings.TrimSpace(state.DeltaLink), "{") {
		t.Errorf("DeltaLink not JSON object: %q", state.DeltaLink)
	}
}

// TestAccessAudit_Integration_LegacyCursorMigrates seeds an
// access_sync_state row using the legacy bare-RFC3339 cursor format
// and verifies the worker migrates it transparently into the
// `{DefaultAuditPartition: ts}` JSON shape after the first run.
func TestAccessAudit_Integration_LegacyCursorMigrates(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	connectorID := "01HZZCONN00000000000000C3"
	seedTestConnector(t, db, connectorID, "okta")

	legacyAt := time.Date(2024, 5, 1, 9, 0, 0, 0, time.UTC)
	legacyRow := models.AccessSyncState{
		ID:          "01HZZSTATELEGACY00000000",
		ConnectorID: connectorID,
		Kind:        models.SyncStateKindAudit,
		DeltaLink:   legacyAt.Format(time.RFC3339),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := db.Create(&legacyRow).Error; err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	var sawSince time.Time
	tNext := legacyAt.Add(time.Hour)
	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, since map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			sawSince = since[access.DefaultAuditPartition]
			return handler([]*access.AuditLogEntry{{EventID: "ev1", Timestamp: tNext}}, tNext, access.DefaultAuditPartition)
		},
	}
	jc := JobContext{
		DB: db, Resolve: stubResolve(mock), LoadConn: DefaultLoadConnector,
		Now: time.Now, AuditProducer: &access.NoOpAuditProducer{},
	}
	seedJob(t, db, "job-int-4", connectorID, "access_audit_log", nil)
	if err := AccessAudit(context.Background(), jc, "job-int-4"); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Legacy cursor was migrated and surfaced to the connector.
	if !sawSince.Equal(legacyAt) {
		t.Errorf("legacy cursor not surfaced: since = %s; want %s", sawSince, legacyAt)
	}
	// After the run the DeltaLink is now JSON, not bare RFC3339.
	var refreshed models.AccessSyncState
	if err := db.Where("id = ?", legacyRow.ID).First(&refreshed).Error; err != nil {
		t.Fatalf("readback: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(refreshed.DeltaLink), "{") {
		t.Errorf("DeltaLink still in legacy format: %q", refreshed.DeltaLink)
	}
	// Round-trip parses cleanly.
	var encoded map[string]string
	if err := json.Unmarshal([]byte(refreshed.DeltaLink), &encoded); err != nil {
		t.Fatalf("decode migrated cursor: %v", err)
	}
	if encoded[access.DefaultAuditPartition] == "" {
		t.Errorf("migrated cursor missing default partition: %+v", encoded)
	}
}
