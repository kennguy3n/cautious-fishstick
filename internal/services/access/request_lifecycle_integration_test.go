package access

import (
	"context"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// deterministicRiskAssessor is a real (not mock) RiskAssessor with
// fixed rules: justifications containing "emergency" score "high",
// roles containing "admin" score "medium", everything else "low".
//
// This exercises the real wiring in AccessRequestService.CreateRequest
// without going through the Phase 4 AIClient — the goal of this test
// is to prove the request lifecycle composes correctly with a real
// risk-assessor, not to test the AI agent.
type deterministicRiskAssessor struct{}

func (deterministicRiskAssessor) AssessRequestRisk(_ context.Context, payload interface{}) (string, []string, bool) {
	p, ok := payload.(riskAssessmentPayload)
	if !ok {
		return "low", nil, true
	}
	if strings.Contains(strings.ToLower(p.Justification), "emergency") {
		return "high", []string{"keyword:emergency"}, true
	}
	if strings.Contains(strings.ToLower(p.Role), "admin") {
		return "medium", []string{"role:admin"}, true
	}
	return "low", nil, true
}

// TestRequestLifecycle_WithDeterministicRiskAssessor wires every
// real service together (AccessRequestService, AccessProvisioningService,
// deterministicRiskAssessor) and runs three scenarios in one test
// against a single real DB:
//
//  1. Justification "emergency" → risk_score=high persisted; lifecycle
//     proceeds normally to provisioned.
//  2. Role "admin" → risk_score=medium persisted; lifecycle proceeds.
//  3. Plain viewer role → risk_score=low persisted; lifecycle proceeds.
//
// The MockAccessConnector is the ONLY mock; the risk assessor is a
// real implementation with deterministic rules.
func TestRequestLifecycle_WithDeterministicRiskAssessor(t *testing.T) {
	const provider = "mock_request_lifecycle_risk"
	db := newE2ETestDB(t)
	conn := seedE2EConnector(t, db, "01HCONN0E2E0RISKASSESSOR01", provider)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	reqSvc := NewAccessRequestService(db)
	reqSvc.SetRiskAssessor(deterministicRiskAssessor{})
	provSvc := NewAccessProvisioningService(db)

	cases := []struct {
		name           string
		input          CreateAccessRequestInput
		wantRiskScore  string
		wantRiskFactor string
	}{
		{
			name: "emergency justification scores high",
			input: CreateAccessRequestInput{
				WorkspaceID:        "01H000000000000000WORKSPACE",
				RequesterUserID:    "01H00000000000000REQEMERG01",
				TargetUserID:       "01H00000000000000TGTEMERG01",
				ConnectorID:        conn.ID,
				ResourceExternalID: "projects/foo",
				Role:               "viewer",
				Justification:      "emergency: prod incident",
			},
			wantRiskScore:  "high",
			wantRiskFactor: "keyword:emergency",
		},
		{
			name: "admin role scores medium",
			input: CreateAccessRequestInput{
				WorkspaceID:        "01H000000000000000WORKSPACE",
				RequesterUserID:    "01H00000000000000REQADMIN01",
				TargetUserID:       "01H00000000000000TGTADMIN01",
				ConnectorID:        conn.ID,
				ResourceExternalID: "projects/bar",
				Role:               "admin",
				Justification:      "quarterly admin review",
			},
			wantRiskScore:  "medium",
			wantRiskFactor: "role:admin",
		},
		{
			name: "plain viewer scores low",
			input: CreateAccessRequestInput{
				WorkspaceID:        "01H000000000000000WORKSPACE",
				RequesterUserID:    "01H00000000000000REQVIEW01",
				TargetUserID:       "01H00000000000000TGTVIEW01",
				ConnectorID:        conn.ID,
				ResourceExternalID: "projects/baz",
				Role:               "viewer",
				Justification:      "weekly review",
			},
			wantRiskScore: "low",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			created, err := reqSvc.CreateRequest(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("CreateRequest: %v", err)
			}
			if created.RiskScore != tc.wantRiskScore {
				t.Fatalf("RiskScore = %q; want %q", created.RiskScore, tc.wantRiskScore)
			}
			if tc.wantRiskFactor != "" {
				if !strings.Contains(string(created.RiskFactors), tc.wantRiskFactor) {
					t.Fatalf("RiskFactors = %s; want to contain %q", string(created.RiskFactors), tc.wantRiskFactor)
				}
			}
			// Run the lifecycle through to provisioned to prove
			// risk scoring doesn't block the happy path.
			if err := reqSvc.ApproveRequest(context.Background(), created.ID, "01HACTOR000000000000000001", "manager OK"); err != nil {
				t.Fatalf("ApproveRequest: %v", err)
			}
			var approved models.AccessRequest
			if err := db.Where("id = ?", created.ID).First(&approved).Error; err != nil {
				t.Fatalf("reload approved: %v", err)
			}
			if err := provSvc.Provision(context.Background(), &approved, nil, nil); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			var final models.AccessRequest
			if err := db.Where("id = ?", created.ID).First(&final).Error; err != nil {
				t.Fatalf("reload final: %v", err)
			}
			if final.State != models.RequestStateProvisioned {
				t.Fatalf("final state = %q; want provisioned", final.State)
			}
		})
	}
}
