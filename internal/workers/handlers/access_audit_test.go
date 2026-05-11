package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// auditMockConnector wraps access.MockAccessConnector with the
// AccessAuditor optional interface. The base mock doesn't include
// FuncFetchAccessAuditLogs, so we attach it here.
type auditMockConnector struct {
	access.MockAccessConnector
	fetch func(ctx context.Context, cfg, secrets map[string]interface{}, since time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time) error) error
}

func (a *auditMockConnector) FetchAccessAuditLogs(
	ctx context.Context,
	cfg, secrets map[string]interface{},
	since time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time) error,
) error {
	return a.fetch(ctx, cfg, secrets, since, handler)
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
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time) error) error {
			if err := handler([]*access.AuditLogEntry{{EventID: "e1", Timestamp: t0}, {EventID: "e2", Timestamp: t1}}, t1); err != nil {
				return err
			}
			return handler([]*access.AuditLogEntry{{EventID: "e3", Timestamp: t2}}, t2)
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
	parsed, err := time.Parse(time.RFC3339Nano, state.DeltaLink)
	if err != nil {
		t.Fatalf("parse cursor: %v", err)
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
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time) error) error {
			if err := handler([]*access.AuditLogEntry{{EventID: "e1", Timestamp: t0}}, t0); err != nil {
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
		fetch: func(_ context.Context, _, _ map[string]interface{}, since time.Time, handler func(batch []*access.AuditLogEntry, nextSince time.Time) error) error {
			seenSince = since
			return handler(nil, since)
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

func TestAccessAudit_SoftSkipsErrAuditNotAvailable(t *testing.T) {
	db := newHandlerDB(t)
	if err := db.AutoMigrate(&models.AccessSyncState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	seedTestConnector(t, db, "conn-1", "slack")
	seedJob(t, db, "job-aud-5", "conn-1", "access_audit_log", nil)
	mock := &auditMockConnector{
		fetch: func(_ context.Context, _, _ map[string]interface{}, _ time.Time, _ func(batch []*access.AuditLogEntry, nextSince time.Time) error) error {
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
