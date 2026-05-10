package access

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestResolveWorkflowWithRisk_DBHit prefers a matching DB workflow over
// the synthetic risk router result.
func TestResolveWorkflowWithRisk_DBHit(t *testing.T) {
	db := newTestDB(t)
	const ws = "01HRISK00000000000000000W1"
	wf := seedWorkflow(t, db, ws,
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepManagerApproval}},
		time.Now().Add(-time.Minute),
	)

	svc := NewWorkflowService(db, &fakeApprover{})
	res, err := svc.ResolveWorkflowWithRisk(context.Background(), &models.AccessRequest{
		WorkspaceID: ws,
		RiskScore:   models.RequestRiskHigh,
	})
	if err != nil {
		t.Fatalf("ResolveWorkflowWithRisk: %v", err)
	}
	if res.Workflow == nil || res.Workflow.ID != wf.ID {
		t.Fatalf("workflow = %+v", res.Workflow)
	}
	if res.SyntheticType != "" {
		t.Errorf("synthetic = %q; want empty when DB hit", res.SyntheticType)
	}
}

// TestResolveWorkflowWithRisk_NoDBLowRisk synthesizes auto_approve.
func TestResolveWorkflowWithRisk_NoDBLowRisk(t *testing.T) {
	db := newTestDB(t)
	svc := NewWorkflowService(db, &fakeApprover{})
	res, err := svc.ResolveWorkflowWithRisk(context.Background(), &models.AccessRequest{
		WorkspaceID: "01HRISK00000000000000000W2",
		RiskScore:   models.RequestRiskLow,
	})
	if err != nil {
		t.Fatalf("ResolveWorkflowWithRisk: %v", err)
	}
	if res.Workflow != nil {
		t.Fatalf("Workflow = %+v; want nil", res.Workflow)
	}
	if res.SyntheticType != models.WorkflowStepAutoApprove {
		t.Errorf("SyntheticType = %q; want auto_approve", res.SyntheticType)
	}
}

// TestResolveWorkflowWithRisk_NoDBMediumRisk synthesizes manager_approval.
func TestResolveWorkflowWithRisk_NoDBMediumRisk(t *testing.T) {
	db := newTestDB(t)
	svc := NewWorkflowService(db, &fakeApprover{})
	res, _ := svc.ResolveWorkflowWithRisk(context.Background(), &models.AccessRequest{
		WorkspaceID: "01HRISK00000000000000000W3",
		RiskScore:   models.RequestRiskMedium,
	})
	if res.SyntheticType != models.WorkflowStepManagerApproval {
		t.Errorf("SyntheticType = %q; want manager_approval", res.SyntheticType)
	}
}

// TestResolveWorkflowWithRisk_NoDBHighRisk synthesizes security_review.
func TestResolveWorkflowWithRisk_NoDBHighRisk(t *testing.T) {
	db := newTestDB(t)
	svc := NewWorkflowService(db, &fakeApprover{})
	res, _ := svc.ResolveWorkflowWithRisk(context.Background(), &models.AccessRequest{
		WorkspaceID: "01HRISK00000000000000000W4",
		RiskScore:   models.RequestRiskHigh,
	})
	if res.SyntheticType != models.WorkflowStepSecurityReview {
		t.Errorf("SyntheticType = %q; want security_review", res.SyntheticType)
	}
}

// TestResolveWorkflowWithRisk_SensitiveTagOverridesLow forces
// security_review even for a low-risk request when RiskFactors contains
// "sensitive_resource".
func TestResolveWorkflowWithRisk_SensitiveTagOverridesLow(t *testing.T) {
	db := newTestDB(t)
	svc := NewWorkflowService(db, &fakeApprover{})

	factors := []string{"sensitive_resource"}
	b, _ := json.Marshal(factors)
	res, err := svc.ResolveWorkflowWithRisk(context.Background(), &models.AccessRequest{
		WorkspaceID: "01HRISK00000000000000000W5",
		RiskScore:   models.RequestRiskLow,
		RiskFactors: datatypes.JSON(b),
	})
	if err != nil {
		t.Fatalf("ResolveWorkflowWithRisk: %v", err)
	}
	if res.SyntheticType != models.WorkflowStepSecurityReview {
		t.Errorf("SyntheticType = %q; want security_review (sensitive override)", res.SyntheticType)
	}
}

// TestResolveWorkflowWithRisk_UnknownRiskFailSafe synthesizes
// manager_approval when RiskScore is empty / unknown.
func TestResolveWorkflowWithRisk_UnknownRiskFailSafe(t *testing.T) {
	db := newTestDB(t)
	svc := NewWorkflowService(db, &fakeApprover{})
	res, _ := svc.ResolveWorkflowWithRisk(context.Background(), &models.AccessRequest{
		WorkspaceID: "01HRISK00000000000000000W6",
	})
	if res.SyntheticType != models.WorkflowStepManagerApproval {
		t.Errorf("SyntheticType = %q; want manager_approval (fail-safe)", res.SyntheticType)
	}
}

// TestExecuteWorkflow_SecurityReviewLeavesPending exercises the new
// step type added in Phase 8.
func TestExecuteWorkflow_SecurityReviewLeavesPending(t *testing.T) {
	db := newTestDB(t)
	const ws = "01HRISK00000000000000000W7"
	wf := seedWorkflow(t, db, ws,
		map[string]interface{}{},
		[]map[string]string{{"type": models.WorkflowStepSecurityReview}},
		time.Now(),
	)
	approver := &fakeApprover{}
	svc := NewWorkflowService(db, approver)
	req := &models.AccessRequest{ID: "01HREQ0000000000000000RSK1", WorkspaceID: ws}
	if err := svc.ExecuteWorkflow(context.Background(), req, wf, "system", "test"); err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if approver.calls != 0 {
		t.Errorf("ApproveRequest called %d times; want 0 for security_review", approver.calls)
	}
}

// TestExecuteWorkflow_MultiLevelLeavesPending exercises the multi_level
// step type added in Phase 8.
func TestExecuteWorkflow_MultiLevelLeavesPending(t *testing.T) {
	db := newTestDB(t)
	const ws = "01HRISK00000000000000000W8"
	wf := seedWorkflow(t, db, ws,
		map[string]interface{}{},
		[]map[string]interface{}{{
			"type": models.WorkflowStepMultiLevel,
			"levels": []map[string]interface{}{
				{"role": "manager", "timeout_hours": 24},
				{"role": "security_review", "timeout_hours": 48},
			},
		}},
		time.Now(),
	)
	approver := &fakeApprover{}
	svc := NewWorkflowService(db, approver)
	req := &models.AccessRequest{ID: "01HREQ0000000000000000RSK2", WorkspaceID: ws}
	if err := svc.ExecuteWorkflow(context.Background(), req, wf, "system", "test"); err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if approver.calls != 0 {
		t.Errorf("ApproveRequest called %d times; want 0 for multi_level", approver.calls)
	}
}
