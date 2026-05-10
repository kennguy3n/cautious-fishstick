package workflow_engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// escalatorTestDB extends newTestDB with the state-history table so
// the escalator's audit-row writes can be inspected.
func escalatorTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.AccessRequestStateHistory{}); err != nil {
		t.Fatalf("migrate state history: %v", err)
	}
	return db
}

// insertEscalatorRequest writes a plain AccessRequest row so the
// CAS-protected update inside NotifyingEscalator.Escalate has
// something to match. Tests construct the in-memory req struct
// independently so they can pass it through Escalate; this helper
// simply persists a row with the same primary key.
func insertEscalatorRequest(t *testing.T, db *gorm.DB, req *models.AccessRequest) {
	t.Helper()
	row := *req
	if row.WorkspaceID == "" {
		row.WorkspaceID = "01HWORKSPACE0000000000000A"
	}
	if row.TargetUserID == "" {
		row.TargetUserID = row.RequesterUserID
	}
	if row.ConnectorID == "" {
		row.ConnectorID = "01HCONN0000000000000000000"
	}
	if row.ResourceExternalID == "" {
		row.ResourceExternalID = "res-1"
	}
	if row.Role == "" {
		row.Role = "viewer"
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("insert request: %v", err)
	}
}

func TestNotifyingEscalator_WritesAuditAndNotifies(t *testing.T) {
	db := escalatorTestDB(t)
	notifier := &stubRequesterNotifier{}
	fixed := time.Date(2026, 5, 10, 18, 30, 0, 0, time.UTC)
	esc := NewNotifyingEscalator(db, notifier)
	esc.SetClock(func() time.Time { return fixed })

	req := &models.AccessRequest{
		ID:              "01HREQESC00000000000000001",
		State:           models.RequestStateRequested,
		RequesterUserID: "01HUSER000000000000000000A",
	}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000000000"}
	insertEscalatorRequest(t, db, req)

	if err := esc.Escalate(context.Background(), req, wf, "manager", "admin"); err != nil {
		t.Fatalf("Escalate: %v", err)
	}

	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("history rows = %d; want 1", len(rows))
	}
	row := rows[0]
	if row.FromState != models.RequestStateRequested || row.ToState != models.RequestStateRequested {
		t.Errorf("row states = %q→%q; want stay in requested", row.FromState, row.ToState)
	}
	if row.ActorUserID != SystemActorID {
		t.Errorf("actor = %q; want %q", row.ActorUserID, SystemActorID)
	}
	if row.Reason == "" {
		t.Error("reason empty")
	}
	if !row.CreatedAt.Equal(fixed) {
		t.Errorf("created_at = %v; want %v", row.CreatedAt, fixed)
	}

	if len(notifier.calls) != 1 {
		t.Fatalf("notifier calls = %d; want 1", len(notifier.calls))
	}

	// Escalation tracking columns advanced and the in-memory req
	// reflects the post-CAS state.
	var got models.AccessRequest
	if err := db.First(&got, "id = ?", req.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.EscalationLevel != 1 {
		t.Errorf("db escalation_level = %d; want 1", got.EscalationLevel)
	}
	if got.LastEscalatedAt == nil || !got.LastEscalatedAt.Equal(fixed) {
		t.Errorf("db last_escalated_at = %v; want %v", got.LastEscalatedAt, fixed)
	}
	if req.EscalationLevel != 1 {
		t.Errorf("in-memory escalation_level = %d; want 1", req.EscalationLevel)
	}
	if req.LastEscalatedAt == nil || !req.LastEscalatedAt.Equal(fixed) {
		t.Errorf("in-memory last_escalated_at = %v; want %v", req.LastEscalatedAt, fixed)
	}
}

func TestNotifyingEscalator_NotifyFailureDoesNotRollBackAudit(t *testing.T) {
	db := escalatorTestDB(t)
	notifier := &stubRequesterNotifier{err: errors.New("smtp 500")}
	esc := NewNotifyingEscalator(db, notifier)

	req := &models.AccessRequest{
		ID:              "01HREQESC00000000000000002",
		State:           models.RequestStateRequested,
		RequesterUserID: "01HUSER000000000000000000B",
	}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000000001"}
	insertEscalatorRequest(t, db, req)

	// Notification failure must NOT propagate as an Escalate error.
	if err := esc.Escalate(context.Background(), req, wf, "manager", "security"); err != nil {
		t.Fatalf("Escalate must swallow notifier errors; got %v", err)
	}
	// Audit row still persisted and CAS still bumped the level.
	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("audit rows = %d; want 1", len(rows))
	}
	var got models.AccessRequest
	if err := db.First(&got, "id = ?", req.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.EscalationLevel != 1 {
		t.Errorf("escalation_level = %d; want 1 (notify failure must not roll back CAS)", got.EscalationLevel)
	}
}

func TestNotifyingEscalator_NoNotifierOK(t *testing.T) {
	db := escalatorTestDB(t)
	esc := NewNotifyingEscalator(db, nil)

	req := &models.AccessRequest{ID: "01HREQESC00000000000000003", State: models.RequestStateRequested, RequesterUserID: "01HUSER000000000000000000C"}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000000002"}
	insertEscalatorRequest(t, db, req)
	if err := esc.Escalate(context.Background(), req, wf, "manager", "admin"); err != nil {
		t.Fatalf("Escalate: %v", err)
	}
	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows = %d; want 1 (audit row required even without notifier)", len(rows))
	}
}

func TestNotifyingEscalator_NilArgsTolerated(t *testing.T) {
	db := escalatorTestDB(t)
	esc := NewNotifyingEscalator(db, nil)
	if err := esc.Escalate(context.Background(), nil, nil, "from", "to"); err != nil {
		t.Fatalf("Escalate(nil,nil): %v", err)
	}
}

func TestNotifyingEscalator_PanicsOnNilDB(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil db")
		}
	}()
	NewNotifyingEscalator(nil, nil)
}

func TestNotifyingEscalator_WithActorID(t *testing.T) {
	db := escalatorTestDB(t)
	esc := NewNotifyingEscalator(db, nil).WithActorID("svc:cron")
	req := &models.AccessRequest{ID: "01HREQESC00000000000000004", State: models.RequestStateRequested, RequesterUserID: "01HUSER000000000000000000D"}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000000003"}
	insertEscalatorRequest(t, db, req)
	if err := esc.Escalate(context.Background(), req, wf, "a", "b"); err != nil {
		t.Fatalf("Escalate: %v", err)
	}
	var row models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).First(&row).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.ActorUserID != "svc:cron" {
		t.Errorf("actor = %q; want svc:cron", row.ActorUserID)
	}
}

// TestNotifyingEscalator_IsIdempotent regresses the bug Devin Review
// flagged on PR #20: prior to wiring CAS-protected escalation
// tracking, calling Escalate twice with the same arguments would
// write two audit rows and fan out two notifications — leaving the
// EscalationChecker free to spam audit history forever once a
// request timed out. Here we drive Escalate twice in a row and
// assert exactly one audit row + one notification + EscalationLevel
// stuck at 1, because the second call sees a stale expectedLevel and
// loses the CAS race against itself.
func TestNotifyingEscalator_IsIdempotent(t *testing.T) {
	db := escalatorTestDB(t)
	notifier := &stubRequesterNotifier{}
	fixed := time.Date(2026, 5, 10, 18, 30, 0, 0, time.UTC)
	esc := NewNotifyingEscalator(db, notifier)
	esc.SetClock(func() time.Time { return fixed })

	req := &models.AccessRequest{
		ID:              "01HREQESC00000000000DEDUP1",
		State:           models.RequestStateRequested,
		RequesterUserID: "01HUSER000000000000000000E",
	}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000DEDUP1"}
	insertEscalatorRequest(t, db, req)

	if err := esc.Escalate(context.Background(), req, wf, "manager", "admin"); err != nil {
		t.Fatalf("first Escalate: %v", err)
	}

	// Simulate a second poll re-discovering the same request and
	// invoking Escalate again with a stale snapshot of the request
	// (expectedLevel=0). The CAS must reject the bump.
	stale := *req
	stale.EscalationLevel = 0
	stale.LastEscalatedAt = nil
	if err := esc.Escalate(context.Background(), &stale, wf, "manager", "admin"); err != nil {
		t.Fatalf("second Escalate must be a silent no-op; got %v", err)
	}

	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("audit rows after duplicate Escalate = %d; want 1", len(rows))
	}
	if len(notifier.calls) != 1 {
		t.Errorf("notifier calls after duplicate Escalate = %d; want 1", len(notifier.calls))
	}
	var got models.AccessRequest
	if err := db.First(&got, "id = ?", req.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.EscalationLevel != 1 {
		t.Errorf("escalation_level = %d; want 1 (CAS must not double-bump)", got.EscalationLevel)
	}
}
