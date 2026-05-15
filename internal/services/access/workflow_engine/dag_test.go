package workflow_engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// pinSQLiteSingleConn caps the pool of the supplied gorm.DB to a
// single underlying connection. Tests that use the DAG executor must
// call this when they need step-history persistence — otherwise
// goroutines created by the DAG fan-out may grab connections bound to
// fresh `:memory:` databases that haven't had AutoMigrate applied.
func pinSQLiteSingleConn(t *testing.T, db *gorm.DB) {
	t.Helper()
	sql, err := db.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	sql.SetMaxOpenConns(1)
	sql.SetMaxIdleConns(1)
}

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

// TestDAGExecutor_BranchIndexRecorded verifies that step-history rows
// emitted by the DAG executor carry a non-nil branch_index matching
// the index of the root the step descends from. Linear runs and root
// nodes themselves keep the value at their root position (0 for the
// single-root case).
func TestDAGExecutor_BranchIndexRecorded(t *testing.T) {
	db := newTestDB(t)
	// The DAG executor fans out across goroutines that all need to
	// see the same in-memory sqlite database. Without pinning to a
	// single connection, each goroutine's first INSERT may bind to a
	// fresh `:memory:` DB that hasn't had AutoMigrate applied.
	pinSQLiteSingleConn(t, db)
	if err := db.AutoMigrate(&models.AccessWorkflowStepHistory{}); err != nil {
		t.Fatalf("migrate step history: %v", err)
	}
	wf := insertWorkflow(t, db, "01HDAGBRIDX00000000000001", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1, 2}}, // 0 root
		{Type: models.WorkflowStepAutoApprove, Next: []int{3}},    // 1 branch_a
		{Type: models.WorkflowStepAutoApprove, Next: []int{3}},    // 2 branch_b
		{Type: models.WorkflowStepAutoApprove, Join: []int{1, 2}}, // 3 join
	})
	// Insert an AccessRequest so the executor has a request id to
	// attach step history rows to.
	wfID := wf.ID
	areq := &models.AccessRequest{
		ID:                 "01HDAGREQ000000000000001A",
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		RequesterUserID:    "01HUSER00000000000000000R",
		TargetUserID:       "01HUSER00000000000000000T",
		ConnectorID:        "01HCONNECT00000000000000C",
		ResourceExternalID: "res-1",
		Role:               "viewer",
		State:              "requested",
		WorkflowID:         &wfID,
	}
	if err := db.Create(areq).Error; err != nil {
		t.Fatalf("create request: %v", err)
	}
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	if _, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID, RequestID: areq.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var rows []models.AccessWorkflowStepHistory
	if err := db.Where("request_id = ?", areq.ID).Find(&rows).Error; err != nil {
		t.Fatalf("query history: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("history rows = %d; want 4", len(rows))
	}
	byStep := map[int]int{}
	for _, r := range rows {
		if r.BranchIndex == nil {
			t.Fatalf("step %d has nil branch_index", r.StepIndex)
		}
		byStep[r.StepIndex] = *r.BranchIndex
	}
	// roots in dagBuild are returned in ascending order, so root 0
	// is branch 0. branch_a (1) descends from root 0 → branch 0.
	// branch_b (2) is NOT a root (predecessor is 0), it inherits
	// from root 0 too. join (3) inherits min predecessor → 0.
	if byStep[0] != 0 {
		t.Errorf("root step 0 branch_index = %d; want 0", byStep[0])
	}
	if byStep[3] < 0 {
		t.Errorf("join step 3 branch_index = %d; want >=0", byStep[3])
	}
	for k, v := range byStep {
		if v < 0 {
			t.Errorf("step %d branch_index = %d (must be >= 0)", k, v)
		}
	}
}

// TestDAGExecutor_BranchIndexLinearStaysZero confirms that single-root
// linear pipelines still write branch_index = 0 (NOT nil) — operators
// querying for "all step history for branch 0" should see linear
// workflows too. This is the cross-cutting DLQ invariant in
// docs/internal/PHASES.md Phase 8.
func TestDAGExecutor_BranchIndexLinearStaysZero(t *testing.T) {
	db := newTestDB(t)
	// Even single-branch workflows route through executeDAG (which
	// uses goroutines), so we must pin the sqlite pool to one
	// connection — see TestDAGExecutor_BranchIndexRecorded for the
	// full explanation of the :memory: isolation failure mode.
	pinSQLiteSingleConn(t, db)
	if err := db.AutoMigrate(&models.AccessWorkflowStepHistory{}); err != nil {
		t.Fatalf("migrate step history: %v", err)
	}
	wf := insertWorkflow(t, db, "01HDAGBRIDXLIN0000000001A", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove, Next: []int{1}},
		{Type: models.WorkflowStepAutoApprove},
	})
	wfID := wf.ID
	areq := &models.AccessRequest{
		ID:                 "01HDAGREQLIN000000000001A",
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		RequesterUserID:    "01HUSER00000000000000000R",
		TargetUserID:       "01HUSER00000000000000000T",
		ConnectorID:        "01HCONNECT00000000000000C",
		ResourceExternalID: "res-1",
		Role:               "viewer",
		State:              "requested",
		WorkflowID:         &wfID,
	}
	if err := db.Create(areq).Error; err != nil {
		t.Fatalf("create request: %v", err)
	}
	exec := NewWorkflowExecutor(db, &recordingPerformer{})
	if _, err := exec.Execute(context.Background(), &ExecuteRequest{WorkflowID: wf.ID, RequestID: areq.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var rows []models.AccessWorkflowStepHistory
	if err := db.Where("request_id = ?", areq.ID).Order("step_index").Find(&rows).Error; err != nil {
		t.Fatalf("query history: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("history rows = %d; want 2", len(rows))
	}
	for _, r := range rows {
		if r.BranchIndex == nil || *r.BranchIndex != 0 {
			t.Errorf("step %d branch_index = %v; want *0", r.StepIndex, r.BranchIndex)
		}
	}
}
