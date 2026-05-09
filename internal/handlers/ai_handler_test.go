package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// stubAIInvoker is a tiny test double that records calls and returns
// a canned response or error.
type stubAIInvoker struct {
	skill   string
	payload interface{}
	resp    *aiclient.SkillResponse
	err     error
}

func (s *stubAIInvoker) InvokeSkill(_ context.Context, skill string, payload interface{}) (*aiclient.SkillResponse, error) {
	s.skill = skill
	s.payload = payload
	return s.resp, s.err
}

func TestAIHandler_Explain_Returns503WhenAIDisabled(t *testing.T) {
	r := Router(Dependencies{}) // no AI service
	w := doJSON(t, r, http.MethodPost, "/access/explain", map[string]string{"policy_id": "p1"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Code, w.Body.String())
	}
}

func TestAIHandler_Explain_HappyPath(t *testing.T) {
	stub := &stubAIInvoker{
		resp: &aiclient.SkillResponse{
			Explanation: "this rule grants engineers SSH on prod-db",
			RiskFactors: []string{"sensitive_resource"},
		},
	}
	r := Router(Dependencies{AIService: stub})
	w := doJSON(t, r, http.MethodPost, "/access/explain", map[string]string{"policy_id": "01H..."})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got struct {
		Explanation string   `json:"explanation"`
		RiskFactors []string `json:"risk_factors"`
	}
	decodeJSON(t, w, &got)
	if got.Explanation != "this rule grants engineers SSH on prod-db" {
		t.Fatalf("explanation = %q; unexpected", got.Explanation)
	}
	if stub.skill != "policy_recommendation" {
		t.Fatalf("invoked skill = %q; want policy_recommendation", stub.skill)
	}
}

func TestAIHandler_Explain_MissingIdsReturns400(t *testing.T) {
	stub := &stubAIInvoker{resp: &aiclient.SkillResponse{}}
	r := Router(Dependencies{AIService: stub})
	w := doJSON(t, r, http.MethodPost, "/access/explain", map[string]string{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestAIHandler_Explain_UpstreamErrorReturns502(t *testing.T) {
	stub := &stubAIInvoker{err: errors.New("boom")}
	r := Router(Dependencies{AIService: stub})
	w := doJSON(t, r, http.MethodPost, "/access/explain", map[string]string{"policy_id": "p1"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s; want 502", w.Code, w.Body.String())
	}
}

func TestAIHandler_Suggest_HappyPath(t *testing.T) {
	stub := &stubAIInvoker{
		resp: &aiclient.SkillResponse{
			Explanation: "consider connector-X for engineers",
		},
	}
	r := Router(Dependencies{AIService: stub})
	w := doJSON(t, r, http.MethodPost, "/access/suggest", map[string]interface{}{
		"user_id":      "01H...",
		"workspace_id": "ws-1",
		"context":      map[string]string{"team": "engineering"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if stub.skill != "policy_recommendation" {
		t.Fatalf("invoked skill = %q; want policy_recommendation", stub.skill)
	}
}

func TestAIHandler_Suggest_DisabledReturns503(t *testing.T) {
	r := Router(Dependencies{})
	w := doJSON(t, r, http.MethodPost, "/access/suggest", map[string]string{})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", w.Code)
	}
}
