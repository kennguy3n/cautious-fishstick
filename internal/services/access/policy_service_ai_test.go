package access

import (
	"context"
	"testing"
)

func TestSimulate_PopulatesRiskFromAssessor(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	stub := &stubRiskAssessor{score: "high", factors: []string{"broad_scope"}, ok: true}
	svc.SetRiskAssessor(stub)

	created, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	report, err := svc.Simulate(context.Background(), created.WorkspaceID, created.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("AssessRequestRisk calls = %d; want 1", stub.calls)
	}
	if report.RiskScore != "high" {
		t.Fatalf("RiskScore = %q; want high", report.RiskScore)
	}
	if len(report.RiskFactors) != 1 || report.RiskFactors[0] != "broad_scope" {
		t.Fatalf("RiskFactors = %v; want [broad_scope]", report.RiskFactors)
	}
}

func TestSimulate_NoAssessorLeavesRiskEmpty(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	created, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	report, err := svc.Simulate(context.Background(), created.WorkspaceID, created.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if report.RiskScore != "" {
		t.Fatalf("RiskScore = %q; want empty", report.RiskScore)
	}
}

func TestSimulate_AssessorFallbackLeavesRiskEmpty(t *testing.T) {
	// Per Simulate's documented contract: on AI failure (ok=false) we
	// do NOT synthesise a fallback risk_score on the impact report
	// — the access-request workflow is the only path that defaults
	// to "medium".
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	stub := &stubRiskAssessor{score: "medium", factors: []string{"ai_unavailable"}, ok: false}
	svc.SetRiskAssessor(stub)

	created, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	report, err := svc.Simulate(context.Background(), created.WorkspaceID, created.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if report.RiskScore != "" {
		t.Fatalf("RiskScore = %q; want empty (AI failure)", report.RiskScore)
	}
}
