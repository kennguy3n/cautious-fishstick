package workflow_engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// flakyPerformer fails the first N Approve calls then succeeds. Used
// to validate the executor's retry/DLQ behaviour.
type flakyPerformer struct {
	calls    int
	failFor  int // number of initial failures
	pendings int
}

func (p *flakyPerformer) Approve(_ context.Context, _ *models.AccessRequest, _ string) error {
	p.calls++
	if p.calls <= p.failFor {
		return fmt.Errorf("flaky downstream failure %d", p.calls)
	}
	return nil
}

func (p *flakyPerformer) MarkPending(_ context.Context, _ *models.AccessRequest, _, _ string) error {
	p.pendings++
	return nil
}

// retryTestDB extends newTestDB with the step-history table.
func retryTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.AccessWorkflowStepHistory{}); err != nil {
		t.Fatalf("migrate step history: %v", err)
	}
	return db
}

func makeAutoApproveWorkflow(t *testing.T, db *gorm.DB, id string) *models.AccessWorkflow {
	t.Helper()
	steps, _ := json.Marshal([]models.WorkflowStepDefinition{{Type: models.WorkflowStepAutoApprove}})
	wf := &models.AccessWorkflow{
		ID:          id,
		WorkspaceID: "01HWORKSPACE0000000000000A",
		Name:        "retry test",
		Steps:       datatypes.JSON(steps),
		IsActive:    true,
	}
	if err := db.Create(wf).Error; err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	return wf
}

func TestRunStepWithRetry_RetriesUntilSuccess(t *testing.T) {
	db := retryTestDB(t)
	perf := &flakyPerformer{failFor: 2}
	exec := NewWorkflowExecutor(db, perf)
	exec.SetRetryPolicy(RetryPolicy{MaxAttempts: 3, BaseBackoff: time.Microsecond, MaxBackoff: time.Microsecond})
	exec.SetSleeper(func(time.Duration) {})

	step := models.WorkflowStepDefinition{Type: models.WorkflowStepAutoApprove}
	decision, _, attempts, err := exec.runStepWithRetry(context.Background(), &models.AccessRequest{ID: "x"}, step)
	if err != nil {
		t.Fatalf("runStepWithRetry: %v", err)
	}
	if decision != StepApprove {
		t.Errorf("decision = %q; want approve", decision)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d; want 3", attempts)
	}
}

func TestRunStepWithRetry_ExhaustsAttempts(t *testing.T) {
	db := retryTestDB(t)
	perf := &flakyPerformer{failFor: 100}
	exec := NewWorkflowExecutor(db, perf)
	exec.SetRetryPolicy(RetryPolicy{MaxAttempts: 3, BaseBackoff: time.Microsecond})
	exec.SetSleeper(func(time.Duration) {})

	step := models.WorkflowStepDefinition{Type: models.WorkflowStepAutoApprove}
	_, _, attempts, err := exec.runStepWithRetry(context.Background(), &models.AccessRequest{ID: "x"}, step)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d; want 3", attempts)
	}
}

func TestRunStepWithRetry_UnknownStepNotRetried(t *testing.T) {
	db := retryTestDB(t)
	perf := &flakyPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	exec.SetRetryPolicy(RetryPolicy{MaxAttempts: 5, BaseBackoff: time.Microsecond})
	exec.SetSleeper(func(time.Duration) {})

	step := models.WorkflowStepDefinition{Type: "unknown_step_type"}
	_, _, attempts, err := exec.runStepWithRetry(context.Background(), &models.AccessRequest{ID: "x"}, step)
	if err == nil {
		t.Fatal("expected unknown step error")
	}
	if !errors.Is(err, ErrStepUnknown) {
		t.Errorf("err = %v; want ErrStepUnknown", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d; want 1 (unknown step is configuration error, not retry)", attempts)
	}
}

func TestExecute_StepHistoryRowsCreatedOnSuccess(t *testing.T) {
	db := retryTestDB(t)
	perf := &flakyPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	exec.SetSleeper(func(time.Duration) {})
	wf := makeAutoApproveWorkflow(t, db, "01HWFRETRY0000000000000001")
	areq := &models.AccessRequest{ID: "01HREQRETRY00000000000001", State: models.RequestStateRequested, RequesterUserID: "u1"}
	if err := db.Create(areq).Error; err != nil {
		t.Fatalf("create request: %v", err)
	}
	res, err := exec.Execute(context.Background(), &ExecuteRequest{RequestID: areq.ID, WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepApprove {
		t.Errorf("decision = %q; want approve", res.Decision)
	}
	var rows []models.AccessWorkflowStepHistory
	if err := db.Where("request_id = ?", areq.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load history: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	if rows[0].Status != models.WorkflowStepStatusCompleted {
		t.Errorf("status = %q; want completed", rows[0].Status)
	}
	if rows[0].Attempts != 1 {
		t.Errorf("attempts = %d; want 1", rows[0].Attempts)
	}
}

func TestExecute_FailedStepRecordedAndListable(t *testing.T) {
	db := retryTestDB(t)
	perf := &flakyPerformer{failFor: 100}
	exec := NewWorkflowExecutor(db, perf)
	exec.SetRetryPolicy(RetryPolicy{MaxAttempts: 2, BaseBackoff: time.Microsecond})
	exec.SetSleeper(func(time.Duration) {})
	wf := makeAutoApproveWorkflow(t, db, "01HWFRETRY0000000000000002")
	areq := &models.AccessRequest{ID: "01HREQRETRY00000000000002", State: models.RequestStateRequested, RequesterUserID: "u1"}
	if err := db.Create(areq).Error; err != nil {
		t.Fatalf("create request: %v", err)
	}
	_, err := exec.Execute(context.Background(), &ExecuteRequest{RequestID: areq.ID, WorkflowID: wf.ID})
	if err == nil {
		t.Fatal("expected error")
	}
	rows, err := exec.ListFailedSteps(context.Background(), areq.ID, 10)
	if err != nil {
		t.Fatalf("ListFailedSteps: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("failed rows = %d; want 1", len(rows))
	}
	if rows[0].Status != models.WorkflowStepStatusFailed {
		t.Errorf("status = %q; want failed", rows[0].Status)
	}
	if rows[0].Attempts != 2 {
		t.Errorf("attempts = %d; want 2", rows[0].Attempts)
	}

	all, err := exec.ListAllFailedSteps(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListAllFailedSteps: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("all failed rows = %d; want 1", len(all))
	}
}

func TestListFailedSteps_RejectsEmptyRequestID(t *testing.T) {
	db := retryTestDB(t)
	exec := NewWorkflowExecutor(db, &flakyPerformer{})
	if _, err := exec.ListFailedSteps(context.Background(), "", 10); err == nil {
		t.Fatal("expected error for empty request_id")
	}
}

func TestRetryPolicy_NextBackoff_CapsAtMaxBackoff(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 5, BaseBackoff: 10 * time.Millisecond, MaxBackoff: 30 * time.Millisecond}.normalised()
	if got := p.nextBackoff(1); got != 0 {
		t.Errorf("nextBackoff(1) = %v; want 0", got)
	}
	if got := p.nextBackoff(2); got != 10*time.Millisecond {
		t.Errorf("nextBackoff(2) = %v; want 10ms", got)
	}
	if got := p.nextBackoff(3); got != 20*time.Millisecond {
		t.Errorf("nextBackoff(3) = %v; want 20ms", got)
	}
	if got := p.nextBackoff(10); got != 30*time.Millisecond {
		t.Errorf("nextBackoff(10) = %v; want capped at 30ms", got)
	}
}

func TestDefaultRetryPolicy_HasSensibleDefaults(t *testing.T) {
	p := DefaultRetryPolicy()
	if p.MaxAttempts != 3 || p.BaseBackoff <= 0 || p.MaxBackoff <= 0 {
		t.Errorf("default policy = %+v", p)
	}
}
