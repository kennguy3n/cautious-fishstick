package aiclient

import (
	"context"
	"errors"
	"log"
)

// DefaultRiskScore is the value populated on the access_request /
// ImpactReport when the AI agent is unreachable. Per
// docs/PROPOSAL.md §5.3 (failure modes), AI is decision-support not
// critical path: a temporarily-down agent must NOT block an access
// request, so the access_request workflow defaults to "medium" and
// routes through manager_approval.
const DefaultRiskScore = "medium"

// AssessRiskWithFallback wraps InvokeSkill("access_risk_assessment",
// payload) with the documented fallback behaviour:
//
//   - On success: returns the SkillResponse from the agent.
//   - On any error: logs a warning (without the API key, without the
//     payload), returns a stub response with RiskScore=DefaultRiskScore
//     and a single risk_factor "ai_unavailable", and ok=false so the
//     caller can see the fallback fired.
//
// This helper is the canonical way to call the AI agent from the
// access_request workflow. Callers that need the raw error (e.g.
// PolicyService.Simulate, where AI failure is acceptable but
// shouldn't synthesise a risk score) call InvokeSkill directly.
//
// AssessRiskWithFallback never panics, never blocks longer than the
// underlying http.Client's timeout, and never logs sensitive
// payloads.
func AssessRiskWithFallback(
	ctx context.Context,
	client *AIClient,
	payload interface{},
) (resp *SkillResponse, ok bool) {
	if client == nil {
		log.Printf("aiclient: assess risk: client is nil; using fallback risk_score=%s", DefaultRiskScore)
		return fallbackResponse(), false
	}

	out, err := client.InvokeSkill(ctx, "access_risk_assessment", payload)
	if err != nil {
		// Differentiate "intentionally unconfigured" from "transient
		// failure" in the log line so operators don't get paged for
		// the dev / test environments where AI is intentionally off.
		if errors.Is(err, ErrAIUnconfigured) {
			log.Printf("aiclient: assess risk: AI unconfigured; using fallback risk_score=%s", DefaultRiskScore)
		} else {
			log.Printf("aiclient: assess risk: AI unavailable (%v); using fallback risk_score=%s", err, DefaultRiskScore)
		}
		return fallbackResponse(), false
	}
	if out == nil || out.RiskScore == "" {
		log.Printf("aiclient: assess risk: AI returned empty response; using fallback risk_score=%s", DefaultRiskScore)
		return fallbackResponse(), false
	}
	return out, true
}

// fallbackResponse returns the canonical "AI is down" stub response.
// Centralised so the message stays consistent across the workflow
// and the policy simulator.
func fallbackResponse() *SkillResponse {
	return &SkillResponse{
		RiskScore:   DefaultRiskScore,
		RiskFactors: []string{"ai_unavailable"},
		Reason:      "AI agent unavailable; defaulted to medium risk",
	}
}

// RiskAssessmentAdapter wraps *AIClient as an adapter that can be
// passed to access.AccessRequestService.SetRiskAssessor without the
// service depending on the aiclient package directly. The adapter
// composes AssessRiskWithFallback so the request workflow gets the
// PROPOSAL §5.3 fallback for free.
//
// Inner may be nil (in which case AssessRequestRisk returns the
// fallback). This makes it cheap to wire in the adapter
// unconditionally even when the AI agent is intentionally
// unconfigured.
type RiskAssessmentAdapter struct {
	Inner *AIClient
}

// AssessRequestRisk satisfies access.RiskAssessor by forwarding to
// AssessRiskWithFallback and unpacking the response into the
// (riskScore, riskFactors, ok) tuple the service expects.
func (a *RiskAssessmentAdapter) AssessRequestRisk(
	ctx context.Context,
	payload interface{},
) (string, []string, bool) {
	if a == nil {
		out := fallbackResponse()
		return out.RiskScore, out.RiskFactors, false
	}
	resp, ok := AssessRiskWithFallback(ctx, a.Inner, payload)
	return resp.RiskScore, resp.RiskFactors, ok
}
