package workflow_engine

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

type recordingEscalator struct {
	calls []escalationCall
	fail  error
}

type escalationCall struct {
	requestID  string
	workflowID string
	from       string
	to         string
}

func (r *recordingEscalator) Escalate(_ context.Context, req *models.AccessRequest, wf *models.AccessWorkflow, from, to string) error {
	if r.fail != nil {
		return r.fail
	}
	r.calls = append(r.calls, escalationCall{
		requestID: req.ID, workflowID: wf.ID, from: from, to: to,
	})
	return nil
}

func mustInsertRequest(t *testing.T, db *gorm.DB, id, workflowID string, updatedAt time.Time) {
	t.Helper()
	req := &models.AccessRequest{
		ID:                 id,
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		RequesterUserID:    "01HUSER000000000000000000A",
		TargetUserID:       "01HUSER000000000000000000A",
		ConnectorID:        "01HCONN0000000000000000000",
		ResourceExternalID: "res-1",
		Role:               "viewer",
		State:              models.RequestStateRequested,
		WorkflowID:         &workflowID,
		UpdatedAt:          updatedAt,
	}
	if err := db.Create(req).Error; err != nil {
		t.Fatalf("create request: %v", err)
	}
	// Force UpdatedAt to the desired value (GORM hooks may overwrite).
	if err := db.Model(req).Update("updated_at", updatedAt).Error; err != nil {
		t.Fatalf("update updated_at: %v", err)
	}
}

func TestEscalationChecker_TimeoutEscalates(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000ESC001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepManagerApproval, TimeoutHours: 24, EscalationTarget: "security_review"},
	})
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	// Inserted 25h ago — timeout exceeded.
	mustInsertRequest(t, db, "01HREQ0000000000000000ESC1", wf.ID, now.Add(-25*time.Hour))

	esc := &recordingEscalator{}
	c := NewEscalationChecker(db, esc, func() time.Time { return now })
	n, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n != 1 || len(esc.calls) != 1 {
		t.Fatalf("calls = %d, escalator = %d", n, len(esc.calls))
	}
	if esc.calls[0].from != models.WorkflowStepManagerApproval || esc.calls[0].to != "security_review" {
		t.Errorf("calls = %+v", esc.calls[0])
	}
}

func TestEscalationChecker_NoTimeoutNoEscalate(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000ESC002", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepManagerApproval, TimeoutHours: 24, EscalationTarget: "security_review"},
	})
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	mustInsertRequest(t, db, "01HREQ0000000000000000ESC2", wf.ID, now.Add(-1*time.Hour))

	esc := &recordingEscalator{}
	c := NewEscalationChecker(db, esc, func() time.Time { return now })
	n, _ := c.Run(context.Background())
	if n != 0 {
		t.Errorf("calls = %d; want 0", n)
	}
}

func TestEscalationChecker_NoTargetNoEscalate(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000ESC003", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepManagerApproval, TimeoutHours: 24},
	})
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	mustInsertRequest(t, db, "01HREQ0000000000000000ESC3", wf.ID, now.Add(-25*time.Hour))

	esc := &recordingEscalator{}
	c := NewEscalationChecker(db, esc, func() time.Time { return now })
	n, _ := c.Run(context.Background())
	if n != 0 {
		t.Errorf("calls = %d; want 0 (no escalation_target)", n)
	}
}

func TestEscalationChecker_MultiLevelEscalates(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000ESC004", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepMultiLevel, Levels: []models.WorkflowStepLevel{
			{Role: "manager", TimeoutHours: 24},
			{Role: "security_review", TimeoutHours: 48},
		}},
	})
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	mustInsertRequest(t, db, "01HREQ0000000000000000ESC4", wf.ID, now.Add(-30*time.Hour))

	esc := &recordingEscalator{}
	c := NewEscalationChecker(db, esc, func() time.Time { return now })
	n, _ := c.Run(context.Background())
	if n != 1 || len(esc.calls) != 1 {
		t.Fatalf("calls = %d", n)
	}
	if esc.calls[0].from != "manager" || esc.calls[0].to != "security_review" {
		t.Errorf("calls = %+v", esc.calls[0])
	}
}

func TestEscalationChecker_IgnoresApprovedRequests(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000ESC005", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepManagerApproval, TimeoutHours: 1, EscalationTarget: "security_review"},
	})
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	wfID := wf.ID
	approved := &models.AccessRequest{
		ID:                 "01HREQ0000000000000000ESC5",
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		RequesterUserID:    "01HUSER000000000000000000A",
		TargetUserID:       "01HUSER000000000000000000A",
		ConnectorID:        "01HCONN0000000000000000000",
		ResourceExternalID: "res-1",
		Role:               "viewer",
		State:              models.RequestStateApproved,
		WorkflowID:         &wfID,
		UpdatedAt:          now.Add(-25 * time.Hour),
	}
	if err := db.Create(approved).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	esc := &recordingEscalator{}
	c := NewEscalationChecker(db, esc, func() time.Time { return now })
	n, _ := c.Run(context.Background())
	if n != 0 {
		t.Errorf("approved request escalated; n=%d", n)
	}
}
