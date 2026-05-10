package workflow_engine

import (
	"context"
	"strings"
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

// TestEscalationChecker_DedupesAcrossPolls regresses the "unbounded
// duplicate audit rows" bug Devin Review flagged on PR #20: with the
// real NotifyingEscalator wired in, two consecutive Run() passes
// against the same timed-out request must produce exactly one
// audit row (and one CAS bump on the request).
func TestEscalationChecker_DedupesAcrossPolls(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.AccessRequestStateHistory{}); err != nil {
		t.Fatalf("migrate state history: %v", err)
	}
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000DEDUP1", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepManagerApproval, TimeoutHours: 24, EscalationTarget: "security_review"},
	})
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	mustInsertRequest(t, db, "01HREQ000000000000000DEDUP", wf.ID, now.Add(-25*time.Hour))

	esc := NewNotifyingEscalator(db, nil)
	esc.SetClock(func() time.Time { return now })
	c := NewEscalationChecker(db, esc, func() time.Time { return now })

	// First poll: timed out → one escalation, one audit row.
	if n, err := c.Run(context.Background()); err != nil || n != 1 {
		t.Fatalf("first Run: n=%d err=%v", n, err)
	}

	// Second poll within the same minute. With the bug present
	// (UpdatedAt-only deadline, no Escalator-side dedup) this would
	// produce another escalation; with the fix in place the
	// EscalationChecker sees EscalationLevel=1 on a single-target
	// step and skips.
	if n, err := c.Run(context.Background()); err != nil || n != 0 {
		t.Fatalf("second Run should skip; got n=%d err=%v", n, err)
	}

	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", "01HREQ000000000000000DEDUP").Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("history rows = %d; want 1", len(rows))
	}
}

// TestEscalationChecker_MultiLevelAdvances exercises the full
// Levels[] walk: every poll advances escalation_level by one until
// we reach the last level, then no further escalations fire even
// though the (re-baselined) timeout keeps elapsing.
func TestEscalationChecker_MultiLevelAdvances(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.AccessRequestStateHistory{}); err != nil {
		t.Fatalf("migrate state history: %v", err)
	}
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000ML0001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepMultiLevel, Levels: []models.WorkflowStepLevel{
			{Role: "manager", TimeoutHours: 1},
			{Role: "security", TimeoutHours: 1},
			{Role: "admin", TimeoutHours: 1},
		}},
	})
	start := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	mustInsertRequest(t, db, "01HREQ0000000000000000ML01", wf.ID, start)

	now := start
	clock := func() time.Time { return now }
	esc := NewNotifyingEscalator(db, nil)
	esc.SetClock(clock)
	c := NewEscalationChecker(db, esc, clock)

	advance := func(d time.Duration, wantN int, wantLevel int) {
		t.Helper()
		now = now.Add(d)
		n, err := c.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if n != wantN {
			t.Errorf("escalations at %v = %d; want %d", now, n, wantN)
		}
		var got models.AccessRequest
		if err := db.First(&got, "id = ?", "01HREQ0000000000000000ML01").Error; err != nil {
			t.Fatalf("reload: %v", err)
		}
		if got.EscalationLevel != wantLevel {
			t.Errorf("level at %v = %d; want %d", now, got.EscalationLevel, wantLevel)
		}
	}

	// 1h after start: level 0 timed out → escalate manager → security.
	advance(1*time.Hour+time.Minute, 1, 1)
	// 1h after the first escalation: level 1 timed out → escalate security → admin.
	advance(1*time.Hour+time.Minute, 1, 2)
	// Another hour later: no level beyond admin, must stop.
	advance(1*time.Hour+time.Minute, 0, 2)

	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", "01HREQ0000000000000000ML01").Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("history rows = %d; want 2 (one per level handover)", len(rows))
	}
	// Reasons should reflect the actual handovers (manager→security, security→admin).
	wantSnippets := []string{"manager → security", "security → admin"}
	for i, row := range rows {
		if i >= len(wantSnippets) {
			break
		}
		if !strings.Contains(row.Reason, wantSnippets[i]) {
			t.Errorf("row[%d].Reason = %q; want substring %q", i, row.Reason, wantSnippets[i])
		}
	}
}
