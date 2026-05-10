package workflow_engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubApprover records every ApproveRequest call so the performer's
// happy / error paths can be asserted without spinning up the full
// AccessRequestService.
type stubApprover struct {
	calls []approveCall
	err   error
}

type approveCall struct {
	requestID, actor, reason string
}

func (s *stubApprover) ApproveRequest(_ context.Context, requestID, actor, reason string) error {
	if s.err != nil {
		return s.err
	}
	s.calls = append(s.calls, approveCall{requestID, actor, reason})
	return nil
}

// stubRequesterNotifier captures every NotifyRequester call.
type stubRequesterNotifier struct {
	calls []notifyCall
	err   error
}

type notifyCall struct {
	requestID, requester, message string
}

func (s *stubRequesterNotifier) NotifyRequester(_ context.Context, requestID, requesterUserID, message string) error {
	if s.err != nil {
		return s.err
	}
	s.calls = append(s.calls, notifyCall{requestID, requesterUserID, message})
	return nil
}

// performerTestDB extends newTestDB with the state-history table so
// MarkPending can write its audit row.
func performerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.AccessRequestStateHistory{}); err != nil {
		t.Fatalf("migrate state history: %v", err)
	}
	return db
}

func TestServiceStepPerformer_Approve_DelegatesToApprover(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	perf := NewServiceStepPerformer(db, approver, nil)
	req := &models.AccessRequest{
		ID:              "01HREQAPPROVE000000000001",
		WorkspaceID:     "01HWORKSPACE0000000000000A",
		RequesterUserID: "01HUSER000000000000000000A",
	}

	if err := perf.Approve(context.Background(), req, "auto-approved"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(approver.calls) != 1 {
		t.Fatalf("approver.calls = %d; want 1", len(approver.calls))
	}
	c := approver.calls[0]
	if c.requestID != req.ID || c.actor != SystemActorID || c.reason != "auto-approved" {
		t.Errorf("call = %+v", c)
	}
}

func TestServiceStepPerformer_Approve_NilRequestIsNoop(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	perf := NewServiceStepPerformer(db, approver, nil)
	if err := perf.Approve(context.Background(), nil, "ignored"); err != nil {
		t.Fatalf("Approve(nil): %v", err)
	}
	if len(approver.calls) != 0 {
		t.Errorf("nil request should not invoke approver; got %d calls", len(approver.calls))
	}
}

func TestServiceStepPerformer_Approve_PropagatesApproverError(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{err: errors.New("downstream unavailable")}
	perf := NewServiceStepPerformer(db, approver, nil)
	req := &models.AccessRequest{ID: "01HREQAPPROVE000000000002"}

	err := perf.Approve(context.Background(), req, "boom")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestServiceStepPerformer_MarkPending_WritesAudit(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	notifier := &stubRequesterNotifier{}
	fixed := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	perf := NewServiceStepPerformer(db, approver, notifier)
	perf.SetClock(func() time.Time { return fixed })

	req := &models.AccessRequest{
		ID:              "01HREQPENDING0000000000001",
		State:           models.RequestStateRequested,
		RequesterUserID: "01HUSER000000000000000000A",
	}

	if err := perf.MarkPending(context.Background(), req, models.WorkflowStepManagerApproval, "awaiting manager"); err != nil {
		t.Fatalf("MarkPending: %v", err)
	}
	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	row := rows[0]
	if row.FromState != models.RequestStateRequested || row.ToState != models.RequestStateRequested {
		t.Errorf("row states = %q→%q; want stay in requested", row.FromState, row.ToState)
	}
	if row.ActorUserID != SystemActorID {
		t.Errorf("actor = %q; want %q", row.ActorUserID, SystemActorID)
	}
	if row.Reason == "" {
		t.Error("reason is empty")
	}
	if !row.CreatedAt.Equal(fixed) {
		t.Errorf("created_at = %v; want %v", row.CreatedAt, fixed)
	}
	if len(notifier.calls) != 1 {
		t.Errorf("notifier.calls = %d; want 1", len(notifier.calls))
	}
}

func TestServiceStepPerformer_MarkPending_NoNotifierIsFine(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	perf := NewServiceStepPerformer(db, approver, nil)
	req := &models.AccessRequest{ID: "01HREQPENDING0000000000002", State: models.RequestStateRequested, RequesterUserID: "u1"}
	if err := perf.MarkPending(context.Background(), req, models.WorkflowStepSecurityReview, "awaiting sec"); err != nil {
		t.Fatalf("MarkPending: %v", err)
	}
}

func TestServiceStepPerformer_MarkPending_NotifierErrorSwallowed(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	notifier := &stubRequesterNotifier{err: errors.New("smtp down")}
	perf := NewServiceStepPerformer(db, approver, notifier)
	req := &models.AccessRequest{ID: "01HREQPENDING0000000000003", State: models.RequestStateRequested, RequesterUserID: "u2"}

	// MUST NOT return an error — notifications are best-effort and
	// the workflow walk must continue regardless of channel health.
	if err := perf.MarkPending(context.Background(), req, models.WorkflowStepManagerApproval, "ping"); err != nil {
		t.Fatalf("MarkPending must swallow notifier errors; got %v", err)
	}
	// Audit row still written.
	var rows []models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("audit rows = %d; want 1", len(rows))
	}
}

func TestServiceStepPerformer_MarkPending_NilRequestIsNoop(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	perf := NewServiceStepPerformer(db, approver, nil)
	if err := perf.MarkPending(context.Background(), nil, models.WorkflowStepManagerApproval, "x"); err != nil {
		t.Fatalf("MarkPending(nil): %v", err)
	}
}

func TestServiceStepPerformer_WithActorID_OverridesActor(t *testing.T) {
	db := performerTestDB(t)
	approver := &stubApprover{}
	perf := NewServiceStepPerformer(db, approver, nil).WithActorID("svc:ztna-api")
	req := &models.AccessRequest{ID: "01HREQ0000000000000ACTOR1", State: models.RequestStateRequested, RequesterUserID: "u3"}
	if err := perf.MarkPending(context.Background(), req, models.WorkflowStepManagerApproval, "x"); err != nil {
		t.Fatalf("MarkPending: %v", err)
	}
	var row models.AccessRequestStateHistory
	if err := db.Where("request_id = ?", req.ID).First(&row).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.ActorUserID != "svc:ztna-api" {
		t.Errorf("actor = %q; want svc:ztna-api", row.ActorUserID)
	}
	// Approve also uses the overridden actor.
	if err := perf.Approve(context.Background(), req, "ok"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approver.calls[0].actor != "svc:ztna-api" {
		t.Errorf("approver actor = %q", approver.calls[0].actor)
	}
}

func TestNewServiceStepPerformer_PanicsOnNilDeps(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil db")
		}
	}()
	NewServiceStepPerformer(nil, &stubApprover{}, nil)
}

func TestNewServiceStepPerformer_PanicsOnNilApprover(t *testing.T) {
	db := performerTestDB(t)
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil approver")
		}
	}()
	NewServiceStepPerformer(db, nil, nil)
}

func TestHumanizeStepType(t *testing.T) {
	cases := map[string]string{
		models.WorkflowStepManagerApproval: "manager approval",
		models.WorkflowStepSecurityReview:  "security review",
		models.WorkflowStepMultiLevel:      "multi-level approval",
		"telepathy":                        "telepathy",
	}
	for in, want := range cases {
		if got := humanizeStepType(in); got != want {
			t.Errorf("humanizeStepType(%q) = %q; want %q", in, got, want)
		}
	}
}
