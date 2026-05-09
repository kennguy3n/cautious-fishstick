package access

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubRiskAssessor is a tiny test double that returns canned
// (score, factors, ok) tuples and records call count + payload so
// tests can assert the service calls AssessRequestRisk exactly once
// per CreateRequest.
type stubRiskAssessor struct {
	calls       int
	payload     interface{}
	score       string
	factors     []string
	ok          bool
}

func (s *stubRiskAssessor) AssessRequestRisk(_ context.Context, payload interface{}) (string, []string, bool) {
	s.calls++
	s.payload = payload
	return s.score, s.factors, s.ok
}

func TestCreateRequest_PopulatesRiskFromAssessor(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	stub := &stubRiskAssessor{score: models.RequestRiskHigh, factors: []string{"sensitive_resource"}, ok: true}
	svc.SetRiskAssessor(stub)

	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("AssessRequestRisk calls = %d; want 1", stub.calls)
	}
	if req.RiskScore != models.RequestRiskHigh {
		t.Fatalf("returned RiskScore = %q; want %q", req.RiskScore, models.RequestRiskHigh)
	}

	// Read back the row to confirm UPDATE landed.
	var stored models.AccessRequest
	if err := db.Where("id = ?", req.ID).First(&stored).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if stored.RiskScore != models.RequestRiskHigh {
		t.Fatalf("stored RiskScore = %q; want %q", stored.RiskScore, models.RequestRiskHigh)
	}
	var factors []string
	if err := json.Unmarshal(stored.RiskFactors, &factors); err != nil {
		t.Fatalf("decode RiskFactors: %v", err)
	}
	if len(factors) != 1 || factors[0] != "sensitive_resource" {
		t.Fatalf("RiskFactors = %v; want [sensitive_resource]", factors)
	}
}

func TestCreateRequest_NoAssessorLeavesRiskEmpty(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if req.RiskScore != "" {
		t.Fatalf("RiskScore = %q; want empty (no assessor wired)", req.RiskScore)
	}
}

func TestCreateRequest_AssessorFallbackPersistsMedium(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	// ok=false simulates the AssessRiskWithFallback path: AI was
	// unreachable, fallback fired with score="medium".
	stub := &stubRiskAssessor{score: models.RequestRiskMedium, factors: []string{"ai_unavailable"}, ok: false}
	svc.SetRiskAssessor(stub)

	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if req.RiskScore != models.RequestRiskMedium {
		t.Fatalf("RiskScore = %q; want %q", req.RiskScore, models.RequestRiskMedium)
	}
}

func TestCreateRequest_AssessorEmptyScoreSkipsUpdate(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	// score="" is the rare "AI returned but agent had no opinion"
	// path. We treat it as "no score" so the row stays empty.
	stub := &stubRiskAssessor{score: "", ok: true}
	svc.SetRiskAssessor(stub)

	req, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if req.RiskScore != "" {
		t.Fatalf("RiskScore = %q; want empty", req.RiskScore)
	}
}

func TestSuggestedWorkflowStep(t *testing.T) {
	cases := []struct {
		score string
		want  string
	}{
		{models.RequestRiskLow, models.WorkflowStepAutoApprove},
		{models.RequestRiskMedium, models.WorkflowStepManagerApproval},
		{models.RequestRiskHigh, models.WorkflowStepManagerApproval},
		{"", models.WorkflowStepManagerApproval},
		{"unknown", models.WorkflowStepManagerApproval},
	}
	for _, c := range cases {
		if got := SuggestedWorkflowStep(c.score); got != c.want {
			t.Errorf("SuggestedWorkflowStep(%q) = %q; want %q", c.score, got, c.want)
		}
	}
}
