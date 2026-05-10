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

	// Notification failure must NOT propagate as an Escalate error.
	if err := esc.Escalate(context.Background(), req, wf, "manager", "security"); err != nil {
		t.Fatalf("Escalate must swallow notifier errors; got %v", err)
	}
	// Audit row still persisted.
	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("audit rows = %d; want 1", len(rows))
	}
}

func TestNotifyingEscalator_NoNotifierOK(t *testing.T) {
	db := escalatorTestDB(t)
	esc := NewNotifyingEscalator(db, nil)

	req := &models.AccessRequest{ID: "01HREQESC00000000000000003", State: models.RequestStateRequested, RequesterUserID: "u4"}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000000002"}
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
	req := &models.AccessRequest{ID: "01HREQESC00000000000000004", State: models.RequestStateRequested, RequesterUserID: "u5"}
	wf := &models.AccessWorkflow{ID: "01HWF00000000000000000003"}
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
