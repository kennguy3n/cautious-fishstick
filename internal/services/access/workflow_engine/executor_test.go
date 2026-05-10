package workflow_engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessRequest{}, &models.AccessWorkflow{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

type recordingPerformer struct {
	approves    int
	pendings    []string
	failApprove error
	failPending error
}

func (r *recordingPerformer) Approve(_ context.Context, _ *models.AccessRequest, _ string) error {
	if r.failApprove != nil {
		return r.failApprove
	}
	r.approves++
	return nil
}
func (r *recordingPerformer) MarkPending(_ context.Context, _ *models.AccessRequest, stepType, _ string) error {
	if r.failPending != nil {
		return r.failPending
	}
	r.pendings = append(r.pendings, stepType)
	return nil
}

func mustStepsJSON(t *testing.T, steps []models.WorkflowStepDefinition) datatypes.JSON {
	t.Helper()
	b, err := json.Marshal(steps)
	if err != nil {
		t.Fatalf("marshal steps: %v", err)
	}
	return datatypes.JSON(b)
}

func insertWorkflow(t *testing.T, db *gorm.DB, id string, steps []models.WorkflowStepDefinition) *models.AccessWorkflow {
	t.Helper()
	wf := &models.AccessWorkflow{
		ID:          id,
		WorkspaceID: "01HWORKSPACE0000000000000A",
		Name:        "test",
		Steps:       mustStepsJSON(t, steps),
		IsActive:    true,
	}
	if err := db.Create(wf).Error; err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	return wf
}

func TestExecutor_AutoApprove(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove},
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepApprove {
		t.Errorf("decision = %q; want approve", res.Decision)
	}
	if perf.approves != 1 {
		t.Errorf("approves = %d; want 1", perf.approves)
	}
}

func TestExecutor_ManagerApprovalReturnsPending(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000002", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepManagerApproval},
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepPending {
		t.Errorf("decision = %q; want pending", res.Decision)
	}
	if len(perf.pendings) != 1 || perf.pendings[0] != models.WorkflowStepManagerApproval {
		t.Errorf("pendings = %v", perf.pendings)
	}
}

func TestExecutor_SecurityReviewReturnsPending(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000003", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepSecurityReview},
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepPending {
		t.Errorf("decision = %q; want pending", res.Decision)
	}
	if len(perf.pendings) != 1 || perf.pendings[0] != models.WorkflowStepSecurityReview {
		t.Errorf("pendings = %v", perf.pendings)
	}
}

func TestExecutor_MultiLevel_FirstLevelPends(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000004", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepMultiLevel, Levels: []models.WorkflowStepLevel{
			{Role: "manager", TimeoutHours: 24},
			{Role: "security_review", TimeoutHours: 48},
		}},
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepPending {
		t.Errorf("decision = %q; want pending", res.Decision)
	}
	if len(perf.pendings) != 1 || perf.pendings[0] != models.WorkflowStepMultiLevel {
		t.Errorf("pendings = %v", perf.pendings)
	}
}

func TestExecutor_MultiLevel_NoLevelsErrors(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000005", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepMultiLevel},
	})
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	if _, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecutor_AutoApproveAdvancesToNextStep(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000006", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove},
		{Type: models.WorkflowStepManagerApproval},
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepPending {
		t.Errorf("decision = %q; want pending after auto then manager", res.Decision)
	}
	if perf.approves != 1 {
		t.Errorf("approves = %d; want 1", perf.approves)
	}
	if len(perf.pendings) != 1 {
		t.Errorf("pendings = %v", perf.pendings)
	}
}

func TestExecutor_UnknownStepFails(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000007", []models.WorkflowStepDefinition{
		{Type: "telepathy"},
	})
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	_, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err == nil || !errors.Is(err, ErrStepUnknown) {
		t.Fatalf("err = %v; want ErrStepUnknown", err)
	}
}

func TestExecutor_WorkflowNotFound(t *testing.T) {
	db := newTestDB(t)
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	_, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: "01HMISSING00000000000000A"})
	if err == nil || !errors.Is(err, ErrWorkflowNotFound) {
		t.Fatalf("err = %v; want ErrWorkflowNotFound", err)
	}
}

func TestExecutor_ValidatesRequest(t *testing.T) {
	db := newTestDB(t)
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	_, err := exec.Execute(context.Background(), &ExecuteRequest{})
	if err == nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err = %v; want ErrInvalidRequest", err)
	}
	_, err = exec.Execute(context.Background(), nil)
	if err == nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err nil = %v; want ErrInvalidRequest", err)
	}
}

func TestExecutor_PerformerErrorPropagates(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW00000000000008", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove},
	})
	perf := &recordingPerformer{failApprove: errors.New("boom")}
	exec := NewWorkflowExecutor(db, perf)
	if _, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID}); err == nil {
		t.Fatal("expected error")
	}
}
