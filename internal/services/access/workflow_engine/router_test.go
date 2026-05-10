package workflow_engine

import (
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func TestRiskRouter_Route(t *testing.T) {
	r := NewRiskRouter()
	cases := []struct {
		name string
		risk RiskBucket
		tags []string
		want WorkflowType
	}{
		{"low → self_service", RiskLow, nil, WorkflowSelfService},
		{"medium → manager", RiskMedium, nil, WorkflowManagerApproval},
		{"high → security", RiskHigh, nil, WorkflowSecurityReview},
		{"sensitive tag overrides low", RiskLow, []string{"sensitive_resource"}, WorkflowSecurityReview},
		{"sensitive tag overrides medium", RiskMedium, []string{"sensitive_resource"}, WorkflowSecurityReview},
		{"case-insensitive sensitive tag", RiskMedium, []string{"  Sensitive_Resource  "}, WorkflowSecurityReview},
		{"unknown risk → manager (fail safe)", "", nil, WorkflowManagerApproval},
		{"weird risk string → manager (fail safe)", "very_high", nil, WorkflowManagerApproval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Route(tc.risk, tc.tags); got != tc.want {
				t.Errorf("Route(%q, %v) = %q; want %q", tc.risk, tc.tags, got, tc.want)
			}
		})
	}
}

func TestRiskRouter_RouteRequest(t *testing.T) {
	r := NewRiskRouter()

	if got := r.RouteRequest(nil, nil); got != WorkflowManagerApproval {
		t.Errorf("nil request = %q; want manager", got)
	}

	req := &models.AccessRequest{RiskScore: "high"}
	if got := r.RouteRequest(req, nil); got != WorkflowSecurityReview {
		t.Errorf("high = %q; want security_review", got)
	}

	req2 := &models.AccessRequest{RiskScore: "low"}
	if got := r.RouteRequest(req2, []string{"sensitive_resource"}); got != WorkflowSecurityReview {
		t.Errorf("low+sensitive = %q; want security_review", got)
	}
}

func TestStepTypeFor(t *testing.T) {
	cases := map[WorkflowType]string{
		WorkflowSelfService:     models.WorkflowStepAutoApprove,
		WorkflowManagerApproval: models.WorkflowStepManagerApproval,
		WorkflowSecurityReview:  models.WorkflowStepSecurityReview,
		WorkflowType("bogus"):   models.WorkflowStepManagerApproval,
	}
	for in, want := range cases {
		if got := StepTypeFor(in); got != want {
			t.Errorf("StepTypeFor(%q) = %q; want %q", in, got, want)
		}
	}
}
