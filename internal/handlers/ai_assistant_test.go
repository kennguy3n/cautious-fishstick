package handlers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

func TestAIHandler_Assistant_DisabledReturns503(t *testing.T) {
	r := Router(Dependencies{}) // no AI service
	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]string{"query": "hello"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Code, w.Body.String())
	}
}

func TestAIHandler_Assistant_MissingQueryReturns400(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})
	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]string{
		"workspace_id": "ws-1",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestAIHandler_Assistant_RoutesToRiskAssessmentSkill(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{
		RiskScore:   "high",
		RiskFactors: []string{"sensitive_resource"},
	}}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query":        "is this grant risky?",
		"workspace_id": "ws-1",
		"grant_id":     "01H...",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if stub.skill != "risk_assessment" {
		t.Fatalf("invoked skill = %q; want risk_assessment", stub.skill)
	}
	var got assistantResponse
	decodeJSON(t, w, &got)
	if got.Intent != "risk_assessment" || got.Skill != "risk_assessment" {
		t.Fatalf("intent/skill = (%q, %q); want both risk_assessment", got.Intent, got.Skill)
	}
	if got.Result == nil || got.Result.RiskScore != "high" {
		t.Fatalf("result = %+v; want RiskScore=high", got.Result)
	}
}

func TestAIHandler_Assistant_RoutesToAnomalyDetectionSkill(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query": "is alice's grant behaving anomalously?",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if stub.skill != "access_anomaly_detection" {
		t.Fatalf("invoked skill = %q; want access_anomaly_detection", stub.skill)
	}
}

func TestAIHandler_Assistant_RoutesToConnectorSetupSkill(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query": "how do I connect Okta?",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if stub.skill != "connector_setup" {
		t.Fatalf("invoked skill = %q; want connector_setup", stub.skill)
	}
}

func TestAIHandler_Assistant_FallsThroughToPolicyRecommendation(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query": "what would a sensible policy here look like?",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if stub.skill != "policy_recommendation" {
		t.Fatalf("invoked skill = %q; want policy_recommendation (default)", stub.skill)
	}
}

func TestAIHandler_Assistant_SkillOverrideBypassesClassifier(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query": "is this risky?", // would normally classify as risk_assessment
		"skill": "policy_recommendation",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if stub.skill != "policy_recommendation" {
		t.Fatalf("invoked skill = %q; want policy_recommendation (override)", stub.skill)
	}
	var got assistantResponse
	decodeJSON(t, w, &got)
	if got.Intent != "override" {
		t.Fatalf("intent = %q; want override", got.Intent)
	}
}

// TestAIHandler_Assistant_RoutesPunctuatedConnectQueryToConnectorSetup
// pins the classifyIntent fix for the trailing-punctuation edge case
// — "how do I connect?" used to fall through to policy_recommendation
// because the "connect " keyword guard required a trailing space.
func TestAIHandler_Assistant_RoutesPunctuatedConnectQueryToConnectorSetup(t *testing.T) {
	for _, q := range []string{
		"how do I connect?",
		"how do I connect!",
		"connect.",
		"how do I CONNECT?", // also exercises lower-casing
	} {
		t.Run(q, func(t *testing.T) {
			stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
			r := Router(Dependencies{AIService: stub})
			w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
				"query": q,
			})
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
			}
			if stub.skill != "connector_setup" {
				t.Fatalf("invoked skill = %q; want connector_setup for %q", stub.skill, q)
			}
		})
	}
}

// TestAIHandler_Assistant_UnknownSkillOverrideReturns400 pins the
// skill allowlist guard: a typo in the override surfaces as a clear
// validation error rather than getting forwarded to the agent and
// returning an opaque 502.
func TestAIHandler_Assistant_UnknownSkillOverrideReturns400(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query": "anything",
		"skill": "risk_assesment", // typo: missing the second 's'
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400 for unknown skill", w.Code, w.Body.String())
	}
	if stub.skill != "" {
		t.Fatalf("invoker.skill = %q; want empty (handler must short-circuit before invoking)", stub.skill)
	}
}

func TestAIHandler_Assistant_UpstreamErrorReturns502(t *testing.T) {
	stub := &stubAIInvoker{err: errors.New("agent unreachable")}
	r := Router(Dependencies{AIService: stub})

	w := doJSON(t, r, http.MethodPost, "/access/assistant", map[string]interface{}{
		"query": "explain this policy",
	})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s; want 502", w.Code, w.Body.String())
	}
}
