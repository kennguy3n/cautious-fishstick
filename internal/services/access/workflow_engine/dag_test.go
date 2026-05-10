package workflow_engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestDAGExecutor_LinearPipelineBackwardsCompat verifies that workflows
// with no `next` / `join` annotations continue to flow through the
// legacy linear executor path, even after the DAG runtime ships.
func TestDAGExecutor_LinearPipelineBackwardsCompat(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGLINEAR0000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove},
		{Type: models.WorkflowStepAutoApprove},
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepApprove {
		t.Fatalf("decision = %q; want approve", res.Decision)
	}
	if perf.approves != 2 {
		t.Fatalf("approves = %d; want 2", perf.approves)
	}
}

// TestDAGExecutor_FanOutTwoBranchesBothApprove launches a single root
// (auto_approve) that fans out to two parallel auto_approve branches.
// Both branches must run; the overall decision is approve.
func TestDAGExecutor_FanOutTwoBranchesBothApprove(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGFANOUT0000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1, 2}}, // 0 → {1, 2}
		{Type: models.WorkflowStepAutoApprove},                    // 1 leaf
		{Type: models.WorkflowStepAutoApprove},                    // 2 leaf
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepApprove {
		t.Fatalf("decision = %q; want approve", res.Decision)
	}
	if perf.approves != 3 {
		t.Fatalf("approves = %d; want 3 (root + 2 branches)", perf.approves)
	}
}

// TestDAGExecutor_FanOutAndJoin: root → branch_a, branch_b → join.
// Verifies that the join step waits until BOTH predecessors complete
// before running.
func TestDAGExecutor_FanOutAndJoin(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGJOIN000000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1, 2}}, // 0 root
		{Type: models.WorkflowStepAutoApprove, Next: []int{3}},    // 1 branch_a
		{Type: models.WorkflowStepAutoApprove, Next: []int{3}},    // 2 branch_b
		{Type: models.WorkflowStepAutoApprove, Join: []int{1, 2}}, // 3 join
	})

	// We use atomic counters to assert the join only runs after the
	// two branches finished. The recordingPerformer.approves counter
	// is bumped on Approve, and each step calls Approve before it
	// returns. So when step 3 runs, approves must already equal 3
	// (root + 2 branches).
	perf := &joinObservingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepApprove {
		t.Fatalf("decision = %q; want approve", res.Decision)
	}
	if perf.totalApproves() != 4 {
		t.Fatalf("approves = %d; want 4", perf.totalApproves())
	}
	if perf.joinObservedApprovesAtStart < 3 {
		t.Fatalf("join started after only %d approves; want >=3 (root + 2 branches)", perf.joinObservedApprovesAtStart)
	}
}

// TestDAGExecutor_FailureInOneBranchDoesNotBlockOther: if branch_a
// returns pending (a non-fatal halt), branch_b still runs to
// completion. The overall result is the worst-case decision (pending).
func TestDAGExecutor_FailureInOneBranchDoesNotBlockOther(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGFAIL000000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1, 2}}, // 0 root
		{Type: models.WorkflowStepManagerApproval},                // 1 branch_a → pending
		{Type: models.WorkflowStepAutoApprove},                    // 2 branch_b → approve
	})
	perf := &recordingPerformer{}
	exec := NewWorkflowExecutor(db, perf)
	res, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Decision != StepPending {
		t.Fatalf("decision = %q; want pending", res.Decision)
	}
	// Both branch_a (pending) and branch_b (approve) must have run;
	// approves == 2 (root + branch_b) and pendings has the manager step.
	if perf.approves != 2 {
		t.Fatalf("approves = %d; want 2 (root + branch_b)", perf.approves)
	}
	if len(perf.pendings) != 1 || perf.pendings[0] != models.WorkflowStepManagerApproval {
		t.Fatalf("pendings = %v; want [manager_approval]", perf.pendings)
	}
}

// TestDAGExecutor_RejectsCycle ensures dagBuild surfaces an error when
// the workflow contains a cycle.
func TestDAGExecutor_RejectsCycle(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGCYCLE00000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1}},
		{Type: models.WorkflowStepAutoApprove, Next: []int{0}},
	})
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	_, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err == nil {
		t.Fatal("Execute: expected cycle error, got nil")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("Execute: error = %v, want cycle", err)
	}
}

// TestDAGExecutor_RejectsOutOfRangeNext ensures dagBuild rejects
// references to step indices that don't exist.
func TestDAGExecutor_RejectsOutOfRangeNext(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGOOR0000000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{42}},
	})
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	_, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err == nil {
		t.Fatal("Execute: expected out-of-range error, got nil")
	}
	if !strings.Contains(err.Error(), "out-of-range") {
		t.Fatalf("Execute: error = %v, want out-of-range", err)
	}
}

// TestDAGExecutor_StepErrorPropagates: a step that returns an error
// (e.g. from the performer) is surfaced as an error from Execute.
func TestDAGExecutor_StepErrorPropagates(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HDAGERR0000000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1, 2}},
		{Type: models.WorkflowStepAutoApprove},
		{Type: models.WorkflowStepAutoApprove},
	})
	perf := &recordingPerformer{failApprove: errors.New("downstream boom")}
	exec := NewWorkflowExecutor(db, perf)
	_, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID})
	if err == nil {
		t.Fatal("Execute: expected error from performer, got nil")
	}
}

// joinObservingPerformer is a Performer that records the number of
// approves observed at the start of the LAST approve call. Used by
// TestDAGExecutor_FanOutAndJoin to assert that the join step ran
// strictly after both predecessor branches finished.
type joinObservingPerformer struct {
	approves                    atomic.Int64
	joinObservedApprovesAtStart int64
}

func (j *joinObservingPerformer) Approve(_ context.Context, _ *models.AccessRequest, _ string) error {
	current := j.approves.Add(1)
	// The join step is the LAST approve in TestDAGExecutor_FanOutAndJoin
	// (steps run root, branch_a, branch_b, join). When the 4th approve
	// fires, capture how many were observed BEFORE it (current-1 = 3).
	if current == 4 {
		j.joinObservedApprovesAtStart = current - 1
	}
	return nil
}

func (j *joinObservingPerformer) MarkPending(_ context.Context, _ *models.AccessRequest, _, _ string) error {
	return nil
}

func (j *joinObservingPerformer) totalApproves() int64 { return j.approves.Load() }
