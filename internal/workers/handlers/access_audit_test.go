package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// auditMockConnector wraps access.MockAccessConnector with the
// AccessAuditor optional interface. The base mock doesn't include
// FuncFetchAccessAuditLogs, so we attach it here.
type auditMockConnector struct {
	access.MockAccessConnector
	fetch func(ctx context.Context, cfg, secrets map[string]interface{}, sincePartitions map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error
}

func (a *auditMockConnector) FetchAccessAuditLogs(
	ctx context.Context,
	cfg, secrets map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	return a.fetch(ctx, cfg, secrets, sincePartitions, handler)
}

func TestAccessAudit_HappyPath_PublishesAndPersistsCursor(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	connectorID := "conn-1"
	seedTestConnector(t, db, connectorID, "okta")
	seedJob(t, db, "job-aud-1", connectorID, "access_audit_log", nil)

	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)

	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			if err := handler([]*access.AuditLogEntry{{EventID: "e1", Timestamp: t0}, {EventID: "e2", Timestamp: t1}}, t1, access.DefaultAuditPartition); err != nil {
				return err
			}
			return handler([]*access.AuditLogEntry{{EventID: "e3", Timestamp: t2}}, t2, access.DefaultAuditPartition)
		},
	}

	producer := &access.NoOpAuditProducer{}
	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: producer,
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-1"); err != nil {
		t.Fatalf("AccessAudit: %v", err)
	}
	if producer.BatchesPublished() != 2 || producer.EntriesPublished() != 3 {
		t.Errorf("publisher = %d batches / %d entries", producer.BatchesPublished(), producer.EntriesPublished())
	}
	job := readJob(t, db, "job-aud-1")
	if job.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %s", job.Status)
	}
	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).First(&state).Error; err != nil {
		t.Fatalf("readback sync state: %v", err)
	}
	cursors := decodeAuditCursors(state.DeltaLink)
	parsed, ok := cursors[access.DefaultAuditPartition]
	if !ok {
		t.Fatalf("cursor missing for default partition; got %v", cursors)
	}
	if !parsed.Equal(t2) {
		t.Errorf("cursor = %s, want %s", parsed, t2)
	}
}

func TestAccessAudit_ConnectorMissingAuditor_CompletesCleanly(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	seedTestConnector(t, db, "conn-1", "okta")
	seedJob(t, db, "job-aud-2", "conn-1", "access_audit_log", nil)
	mock := &access.MockAccessConnector{}
	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: &access.NoOpAuditProducer{},
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-2"); err != nil {
		t.Fatalf("AccessAudit: %v", err)
	}
	job := readJob(t, db, "job-aud-2")
	if job.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %s", job.Status)
	}
}

func TestAccessAudit_FetchFails_JobFailedButCursorAdvanced(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	seedTestConnector(t, db, "conn-1", "okta")
	seedJob(t, db, "job-aud-3", "conn-1", "access_audit_log", nil)
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	wantErr := errors.New("upstream blew up after page 1")
	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			if err := handler([]*access.AuditLogEntry{{EventID: "e1", Timestamp: t0}}, t0, access.DefaultAuditPartition); err != nil {
				return err
			}
			return wantErr
		},
	}
	producer := &access.NoOpAuditProducer{}
	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: producer,
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-3"); err == nil {
		t.Fatal("expected error from upstream failure")
	}
	if producer.EntriesPublished() != 1 {
		t.Errorf("publisher = %d entries", producer.EntriesPublished())
	}
	job := readJob(t, db, "job-aud-3")
	if job.Status != models.AccessJobStatusFailed {
		t.Errorf("status = %s", job.Status)
	}
	// cursor should still have advanced to t0 (partial-progress)
	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", "conn-1", models.SyncStateKindAudit).First(&state).Error; err != nil {
		t.Fatalf("readback sync state: %v", err)
	}
}

func TestAccessAudit_ResumesFromCursor(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	seedTestConnector(t, db, "conn-1", "okta")
	seedJob(t, db, "job-aud-4", "conn-1", "access_audit_log", nil)
	cursor := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := models.AccessSyncState{
		ID:          "aud-old",
		ConnectorID: "conn-1",
		Kind:        models.SyncStateKindAudit,
		DeltaLink:   cursor.Format(time.RFC3339Nano),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := db.Create(&prev).Error; err != nil {
		t.Fatalf("seed sync state: %v", err)
	}
	var seenSince time.Time
	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, sincePartitions map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			seenSince = sincePartitions[access.DefaultAuditPartition]
			return handler(nil, seenSince, access.DefaultAuditPartition)
		},
	}
	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: &access.NoOpAuditProducer{},
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-4"); err != nil {
		t.Fatalf("AccessAudit: %v", err)
	}
	if !seenSince.Equal(cursor) {
		t.Errorf("since = %s, want %s", seenSince, cursor)
	}
}

// TestAccessAudit_CursorPerPartitionOnPartialFailure is the regression
// guard for the bug Devin Review flagged on commit 9387989: even after
// the Microsoft connector resets `cursor := since` per endpoint, the
// worker collapses each endpoint's nextSince into a single max(...)
// cursor. After signIns publishes at 13:00 and directoryAudits publishes
// at 10:00, a partial failure mid-directoryAudit must NOT persist 13:00
// for the directoryAudits partition — otherwise the retry's
// `$filter ge 13:00` skips the 09:00–13:00 directoryAudit events
// permanently. With partition-keyed cursors, each partition advances
// independently.
func TestAccessAudit_CursorPerPartitionOnPartialFailure(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	seedTestConnector(t, db, "conn-1", "microsoft")
	seedJob(t, db, "job-aud-6", "conn-1", "access_audit_log", nil)

	signInPart := "microsoft/signIns"
	dirAuditPart := "microsoft/directoryAudits"
	signInMax := time.Date(2024, 1, 1, 13, 0, 0, 0, time.UTC)
	dirAuditMax := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	wantErr := errors.New("upstream blew up after directoryAudits page 1")

	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			// signIns batch completes successfully at 13:00.
			if err := handler(
				[]*access.AuditLogEntry{{EventID: "si-1", Timestamp: signInMax}},
				signInMax, signInPart,
			); err != nil {
				return err
			}
			// directoryAudit batch completes successfully at 10:00,
			// but a later page fails.
			if err := handler(
				[]*access.AuditLogEntry{{EventID: "da-1", Timestamp: dirAuditMax}},
				dirAuditMax, dirAuditPart,
			); err != nil {
				return err
			}
			return wantErr
		},
	}

	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: &access.NoOpAuditProducer{},
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-6"); err == nil {
		t.Fatal("expected error from upstream failure")
	}

	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", "conn-1", models.SyncStateKindAudit).First(&state).Error; err != nil {
		t.Fatalf("readback sync state: %v", err)
	}
	cursors := decodeAuditCursors(state.DeltaLink)
	if len(cursors) != 2 {
		t.Fatalf("expected 2 partition cursors; got %d (%v)", len(cursors), cursors)
	}
	if got := cursors[signInPart]; !got.Equal(signInMax) {
		t.Errorf("signIns cursor = %s; want %s", got, signInMax)
	}
	if got := cursors[dirAuditPart]; !got.Equal(dirAuditMax) {
		t.Errorf("directoryAudits cursor = %s; want %s (signIn max %s leaked into slower partition)",
			got, dirAuditMax, signInMax)
	}
}

func TestAccessAudit_SoftSkipsErrAuditNotAvailable(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	seedTestConnector(t, db, "conn-1", "slack")
	seedJob(t, db, "job-aud-5", "conn-1", "access_audit_log", nil)
	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ map[string]time.Time, _ func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			return access.ErrAuditNotAvailable
		},
	}
	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: &access.NoOpAuditProducer{},
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-5"); err != nil {
		t.Fatalf("AccessAudit: %v", err)
	}
	job := readJob(t, db, "job-aud-5")
	if job.Status != models.AccessJobStatusCompleted {
		t.Errorf("status = %s", job.Status)
	}
}

// TestAccessAudit_NewCursorIDFitsVarchar26 is the regression test for
// the original aud-{connectorID}-{unixNano} format which produced
// 30-50+ character IDs and silently passed on SQLite while breaking
// on PostgreSQL (where AccessSyncState.ID is varchar(26)). Each new
// row must be a valid 26-character ULID.
func TestAccessAudit_NewCursorIDFitsVarchar26(t *testing.T) {
	// Run the function under test many times so a regression that
	// occasionally fits inside 26 chars can't sneak through.
	for i := 0; i < 256; i++ {
		id := newAuditCursorID()
		if len(id) != 26 {
			t.Fatalf("newAuditCursorID() len = %d, want 26 (id=%q); AccessSyncState.ID is varchar(26)", len(id), id)
		}
		if _, err := ulid.ParseStrict(id); err != nil {
			t.Fatalf("newAuditCursorID() not a valid ULID: %v (id=%q)", err, id)
		}
	}
}

// TestAccessAudit_PersistedCursorRowIDIsULID drives the full worker
// path end-to-end and asserts that the access_sync_state row created
// for a brand-new connector carries a 26-char ULID. This catches the
// case where a fmt.Sprintf-based ID generator is reintroduced — even
// SQLite (which silently accepts over-long varchar values) would
// then surface the regression via this length check.
func TestAccessAudit_PersistedCursorRowIDIsULID(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	// A long-ish connector ID is what makes the legacy format
	// blow past 26 chars; use the canonical 26-char-ULID style id
	// the rest of the codebase emits.
	connectorID := "01HMRX7Q4P0VAW6V2N3M8K9Z01"
	seedTestConnector(t, db, connectorID, "okta")
	seedJob(t, db, "job-aud-id-1", connectorID, "access_audit_log", nil)

	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ map[string]time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error) error {
			return handler([]*access.AuditLogEntry{{EventID: "e1", Timestamp: t0}}, t0, access.DefaultAuditPartition)
		},
	}
	jc := JobContext{
		DB:            db,
		Resolve:       stubResolve(mock),
		LoadConn:      DefaultLoadConnector,
		Now:           time.Now,
		AuditProducer: &access.NoOpAuditProducer{},
	}
	if err := AccessAudit(context.Background(), jc, "job-aud-id-1"); err != nil {
		t.Fatalf("AccessAudit: %v", err)
	}

	var state models.AccessSyncState
	if err := db.Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).First(&state).Error; err != nil {
		t.Fatalf("readback sync state: %v", err)
	}
	if len(state.ID) != 26 {
		t.Errorf("persisted sync_state.id len = %d, want 26 (id=%q); column is varchar(26) — PostgreSQL would reject the INSERT",
			len(state.ID), state.ID)
	}
	if _, err := ulid.ParseStrict(state.ID); err != nil {
		t.Errorf("persisted sync_state.id is not a valid ULID: %v (id=%q)", err, state.ID)
	}
}
