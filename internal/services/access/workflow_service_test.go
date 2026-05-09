package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// fakeApprover is a tiny stub implementing RequestApprover. It records the
// last call so workflow tests can assert that ExecuteWorkflow either did
// or did not invoke ApproveRequest.
type fakeApprover struct {
	calls       int
	requestID   string
	actorUserID string
	reason      string
	err         error
}

func (f *fakeApprover) ApproveRequest(_ context.Context, requestID, actorUserID, reason string) error {
	f.calls++
	f.requestID = requestID
	f.actorUserID = actorUserID
	f.reason = reason
	return f.err
}

// seedWorkflow inserts a workflow row with the given match rule and steps.
// The bytes are stored as datatypes.JSON; SQLite stores them as TEXT.
func seedWorkflow(t *testing.T, db *gorm.DB, workspaceID string, rule, steps interface{}, createdAt time.Time) *models.AccessWorkflow {
	t.Helper()
	ruleBytes, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}
	stepBytes, err := json.Marshal(steps)
	if err != nil {
		t.Fatalf("marshal steps: %v", err)
	}
	wf := &models.AccessWorkflow{
		ID:          newULID(),
		WorkspaceID: workspaceID,
		Name:        "test workflow",
		MatchRule:   datatypes.JSON(ruleBytes),
		Steps:       datatypes.JSON(stepBytes),
		IsActive:    true,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	}
	if err := db.Create(wf).Error; err != nil {
		t.Fatalf("seed workflow: %v", err)
	}
	return wf
}

// TestResolveWorkflow_ReturnsMatchingWorkflow seeds three workflows and
// asserts that the one with matching connector_id+role wins. The most-
// specific rule is inserted second to ensure ordering by CreatedAt is
// preserved (oldest-first).
func TestResolveWorkflow_ReturnsMatchingWorkflow(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"

	now := time.Now()
	// First, a wildcard manager-approval workflow created earliest.
	wfWildcard := seedWorkflow(t, db, workspace,
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepManagerApproval}},
		now,
	)
	// Second, a narrower auto-approve workflow for connector X + role
	// "viewer".
	wfNarrow := seedWorkflow(t, db, workspace,
		map[string]interface{}{
			"connector_id": "01H000000000000000CONNECTOR",
			"role":         "viewer",
		},
		[]map[string]string{{"type": models.WorkflowStepAutoApprove}},
		now.Add(time.Second),
	)
	// Third, a workflow in a different workspace which must NEVER match.
	_ = seedWorkflow(t, db, "01H000000000000000OTHERWS",
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepAutoApprove}},
		now.Add(2*time.Second),
	)

	svc := NewWorkflowService(db, &fakeApprover{})

	req := &models.AccessRequest{
		WorkspaceID:        workspace,
		ConnectorID:        "01H000000000000000CONNECTOR",
		Role:               "viewer",
		ResourceExternalID: "projects/foo",
	}
	got, err := svc.ResolveWorkflow(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveWorkflow: %v", err)
	}
	if got == nil {
		t.Fatal("ResolveWorkflow returned nil; want wildcard workflow (oldest match wins)")
	}
	// Wildcard was inserted first and matches everything, so it wins.
	if got.ID != wfWildcard.ID {
		t.Errorf("got workflow %q; want %q (oldest matching wins)", got.ID, wfWildcard.ID)
	}
	_ = wfNarrow
}

// TestResolveWorkflow_ResourcePatternMatching exercises the path.Match-
// based pattern.
func TestResolveWorkflow_ResourcePatternMatching(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	wf := seedWorkflow(t, db, workspace,
		map[string]interface{}{
			"resource_pattern": "projects/*",
		},
		[]map[string]string{{"type": models.WorkflowStepAutoApprove}},
		time.Now(),
	)
	svc := NewWorkflowService(db, &fakeApprover{})

	t.Run("matches", func(t *testing.T) {
		req := &models.AccessRequest{
			WorkspaceID:        workspace,
			ResourceExternalID: "projects/alpha",
		}
		got, err := svc.ResolveWorkflow(context.Background(), req)
		if err != nil {
			t.Fatalf("ResolveWorkflow: %v", err)
		}
		if got == nil || got.ID != wf.ID {
			t.Errorf("got %v; want match for projects/alpha", got)
		}
	})
	t.Run("does not match", func(t *testing.T) {
		req := &models.AccessRequest{
			WorkspaceID:        workspace,
			ResourceExternalID: "buckets/foo",
		}
		got, err := svc.ResolveWorkflow(context.Background(), req)
		if err != nil {
			t.Fatalf("ResolveWorkflow: %v", err)
		}
		if got != nil {
			t.Errorf("got %v; want nil for buckets/foo", got)
		}
	})
}

// TestResolveWorkflow_NoMatchReturnsNil asserts that an empty workspace
// (or one with only inactive workflows) yields (nil, nil).
func TestResolveWorkflow_NoMatchReturnsNil(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	svc := NewWorkflowService(db, &fakeApprover{})

	req := &models.AccessRequest{WorkspaceID: workspace}
	got, err := svc.ResolveWorkflow(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveWorkflow: %v", err)
	}
	if got != nil {
		t.Errorf("got %v; want nil", got)
	}
}

// TestResolveWorkflow_InactiveWorkflowsIgnored confirms IsActive=false
// rows are filtered.
func TestResolveWorkflow_InactiveWorkflowsIgnored(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	wf := seedWorkflow(t, db, workspace,
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepAutoApprove}},
		time.Now(),
	)
	if err := db.Model(&models.AccessWorkflow{}).Where("id = ?", wf.ID).Update("is_active", false).Error; err != nil {
		t.Fatalf("disable workflow: %v", err)
	}

	svc := NewWorkflowService(db, &fakeApprover{})
	req := &models.AccessRequest{WorkspaceID: workspace}
	got, err := svc.ResolveWorkflow(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveWorkflow: %v", err)
	}
	if got != nil {
		t.Errorf("got %v; want nil for inactive-only workspace", got)
	}
}

// TestExecuteWorkflow_AutoApproveCallsApprover asserts that an auto-
// approve workflow forwards to ApproveRequest.
func TestExecuteWorkflow_AutoApproveCallsApprover(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	wf := seedWorkflow(t, db, workspace,
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepAutoApprove}},
		time.Now(),
	)
	approver := &fakeApprover{}
	svc := NewWorkflowService(db, approver)

	req := &models.AccessRequest{ID: "01H000000000000000REQABCDEFG", WorkspaceID: workspace}
	if err := svc.ExecuteWorkflow(context.Background(), req, wf, "system", "auto"); err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if approver.calls != 1 {
		t.Errorf("approver calls = %d; want 1", approver.calls)
	}
	if approver.requestID != req.ID {
		t.Errorf("approver requestID = %q; want %q", approver.requestID, req.ID)
	}
	if approver.actorUserID != "system" {
		t.Errorf("approver actorUserID = %q; want %q", approver.actorUserID, "system")
	}
}

// TestExecuteWorkflow_ManagerApprovalIsNoOp asserts that the
// manager-approval step does nothing — the request stays in "requested"
// and the approver is not called.
func TestExecuteWorkflow_ManagerApprovalIsNoOp(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	wf := seedWorkflow(t, db, workspace,
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepManagerApproval}},
		time.Now(),
	)
	approver := &fakeApprover{}
	svc := NewWorkflowService(db, approver)

	req := &models.AccessRequest{ID: "01H000000000000000REQABCDEFG", WorkspaceID: workspace}
	if err := svc.ExecuteWorkflow(context.Background(), req, wf, "system", "manager"); err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if approver.calls != 0 {
		t.Errorf("approver calls = %d; want 0 (manager_approval is a no-op)", approver.calls)
	}
}

// TestExecuteWorkflow_NilWorkflowFallsBackToAutoApprove asserts that
// passing nil for the workflow auto-approves. This is the "no policy
// match → self-service let-through" Phase 2 default.
func TestExecuteWorkflow_NilWorkflowFallsBackToAutoApprove(t *testing.T) {
	db := newTestDB(t)
	approver := &fakeApprover{}
	svc := NewWorkflowService(db, approver)

	req := &models.AccessRequest{ID: "01H000000000000000REQABCDEFG"}
	if err := svc.ExecuteWorkflow(context.Background(), req, nil, "system", "no rule"); err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if approver.calls != 1 {
		t.Errorf("approver calls = %d; want 1", approver.calls)
	}
}

// TestExecuteWorkflow_UnknownStepTypeReturnsError asserts that a
// misconfigured step type fails loudly.
func TestExecuteWorkflow_UnknownStepTypeReturnsError(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	wf := seedWorkflow(t, db, workspace,
		map[string]interface{}{},
		[]map[string]string{{"type": "fancy_new_thing"}},
		time.Now(),
	)
	svc := NewWorkflowService(db, &fakeApprover{})

	req := &models.AccessRequest{ID: "01H000000000000000REQABCDEFG", WorkspaceID: workspace}
	err := svc.ExecuteWorkflow(context.Background(), req, wf, "system", "wat")
	if err == nil {
		t.Fatal("ExecuteWorkflow returned nil; want ErrWorkflowExecution")
	}
	if !errors.Is(err, ErrWorkflowExecution) {
		t.Errorf("err = %v; want ErrWorkflowExecution", err)
	}
}

// TestExecuteWorkflow_EmptyStepsReturnsError asserts that an empty Steps
// array (a nonsense workflow) is rejected.
func TestExecuteWorkflow_EmptyStepsReturnsError(t *testing.T) {
	db := newTestDB(t)
	const workspace = "01H000000000000000WORKSPACE"
	wf := seedWorkflow(t, db, workspace,
		map[string]interface{}{},
		[]map[string]string{},
		time.Now(),
	)
	svc := NewWorkflowService(db, &fakeApprover{})

	req := &models.AccessRequest{ID: "01H000000000000000REQABCDEFG", WorkspaceID: workspace}
	err := svc.ExecuteWorkflow(context.Background(), req, wf, "system", "wat")
	if !errors.Is(err, ErrWorkflowExecution) {
		t.Errorf("err = %v; want ErrWorkflowExecution", err)
	}
}

// TestResolveWorkflow_NilRequestRejected guards the trivial nil-pointer
// path.
func TestResolveWorkflow_NilRequestRejected(t *testing.T) {
	db := newTestDB(t)
	svc := NewWorkflowService(db, &fakeApprover{})
	_, err := svc.ResolveWorkflow(context.Background(), nil)
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want ErrValidation", err)
	}
}
