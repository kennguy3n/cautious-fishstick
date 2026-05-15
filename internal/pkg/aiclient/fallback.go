package aiclient

import (
	"context"
	"errors"
	"log"
)

// DefaultRiskScore is the value populated on the access_request /
// ImpactReport when the AI agent is unreachable. Per
// docs/overview.md §5.3 (failure modes), AI is decision-support not
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

// ReviewAutomationPayload is the canonical request shape for the
// access_review_automation skill. The Go service layer marshals one
// of these per pending decision into a /a2a/invoke call and the
// Python agent returns SkillResponse.Decision / SkillResponse.Reason.
//
// UsageData is intentionally typed as map[string]interface{} so the
// service layer can pass through whatever recent-usage observations
// it has (last-seen timestamp, days_since_last_use, sign-in counts,
// ...) without locking the schema in Go. Mirrors the shape the Python
// access_review_automation skill consumes.
type ReviewAutomationPayload struct {
	GrantID   string                 `json:"grant_id"`
	UserID    string                 `json:"user_id,omitempty"`
	Role      string                 `json:"role,omitempty"`
	Resource  string                 `json:"resource_external_id,omitempty"`
	UsageData map[string]interface{} `json:"usage_data,omitempty"`
}

// allowedReviewDecisions is the set of decision strings the Python
// access_review_automation skill is allowed to return. Anything else
// is treated as "AI returned an unexpected verdict" and the caller
// leaves the row pending. Keep this in sync with
// cmd/access-ai-agent/skills/access_review_automation.py
// ALLOWED_DECISIONS.
var allowedReviewDecisions = map[string]struct{}{
	"certify":  {},
	"revoke":   {},
	"escalate": {},
}

// AutomateReviewWithFallback wraps AIClient.InvokeSkill(
// "access_review_automation", payload) with the PROPOSAL §5.3
// fallback semantics:
//
//   - On success with a recognised decision: returns (decision,
//     reason, true).
//   - On any error or nil client: logs a warning, returns ("", "",
//     false) so the caller leaves the decision pending.
//   - On a 2xx response with an unrecognised decision: logs a
//     warning, returns ("", "", false) so the caller leaves the
//     decision pending rather than auto-certifying on a bogus
//     verdict.
//
// AI is decision-support, not critical path — a momentarily-down
// agent must NOT block the access-review campaign's auto-
// certification pass.
func AutomateReviewWithFallback(
	ctx context.Context,
	client *AIClient,
	payload ReviewAutomationPayload,
) (decision string, reason string, ok bool) {
	if client == nil {
		log.Printf("aiclient: automate review: client is nil; leaving grant %s pending", payload.GrantID)
		return "", "", false
	}
	resp, err := client.InvokeSkill(ctx, "access_review_automation", payload)
	if err != nil {
		if errors.Is(err, ErrAIUnconfigured) {
			log.Printf("aiclient: automate review: AI unconfigured; leaving grant %s pending", payload.GrantID)
		} else {
			log.Printf("aiclient: automate review: AI unavailable (%v); leaving grant %s pending", err, payload.GrantID)
		}
		return "", "", false
	}
	if resp == nil || resp.Decision == "" {
		log.Printf("aiclient: automate review: AI returned empty decision; leaving grant %s pending", payload.GrantID)
		return "", "", false
	}
	if _, allowed := allowedReviewDecisions[resp.Decision]; !allowed {
		log.Printf("aiclient: automate review: AI returned unexpected decision %q; leaving grant %s pending", resp.Decision, payload.GrantID)
		return "", "", false
	}
	return resp.Decision, resp.Reason, true
}

// DetectAnomaliesWithFallback wraps AIClient.DetectAnomalies with
// the same PROPOSAL §5.3 fallback semantics as
// AssessRiskWithFallback:
//
//   - On success: returns the AnomalyEvent slice (possibly empty).
//   - On any error or nil client: logs a warning, returns an empty
//     slice and ok=false so the caller sees the fallback fired.
//
// AI is decision-support, not critical path — a momentarily-down
// agent must NOT block the AnomalyDetectionService's periodic
// scan.
func DetectAnomaliesWithFallback(
	ctx context.Context,
	client *AIClient,
	grantID string,
	usageData map[string]interface{},
) (anomalies []AnomalyEvent, ok bool) {
	if client == nil {
		log.Printf("aiclient: detect anomalies: client is nil; using empty fallback for grant %s", grantID)
		return nil, false
	}
	out, err := client.DetectAnomalies(ctx, grantID, usageData)
	if err != nil {
		if errors.Is(err, ErrAIUnconfigured) {
			log.Printf("aiclient: detect anomalies: AI unconfigured; using empty fallback for grant %s", grantID)
		} else {
			log.Printf("aiclient: detect anomalies: AI unavailable (%v); using empty fallback for grant %s", err, grantID)
		}
		return nil, false
	}
	return out, true
}
