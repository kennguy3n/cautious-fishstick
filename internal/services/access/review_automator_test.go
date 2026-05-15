package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// TestReviewAutomatorAdapter_AutomateReview_AutoCertify drives the
// adapter end-to-end against a real httptest AI agent that responds
// with the canonical "certify" verdict. The adapter must surface
// (decision, reason, ok=true) so AccessReviewService transitions
// the pending decision to certified per docs/PHASES.md Phase 5
// auto-cert behaviour.
func TestReviewAutomatorAdapter_AutomateReview_AutoCertify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/a2a/invoke" {
			t.Errorf("path = %q; want /a2a/invoke", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(aiclient.SkillResponse{
			Decision: "certify",
			Reason:   "low-risk admin grant; recent logins within policy",
		})
	}))
	t.Cleanup(srv.Close)

	a := &ReviewAutomatorAdapter{Inner: aiclient.NewAIClient(srv.URL, "k")}
	decision, reason, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if !ok {
		t.Fatal("ok = false; want true on AI success")
	}
	if decision != "certify" {
		t.Errorf("decision = %q; want certify", decision)
	}
	if reason == "" {
		t.Error("reason is empty; want passthrough from AI agent")
	}
}

// TestReviewAutomatorAdapter_AutomateReview_EscalateHighRisk
// verifies the adapter recognises the canonical "escalate" verdict.
// AccessReviewService treats this as a leave-pending signal (the
// operator must look at it) — the adapter just surfaces the verdict.
func TestReviewAutomatorAdapter_AutomateReview_EscalateHighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(aiclient.SkillResponse{
			Decision: "escalate",
			Reason:   "anomalous geo + multiple connectors",
		})
	}))
	t.Cleanup(srv.Close)

	a := &ReviewAutomatorAdapter{Inner: aiclient.NewAIClient(srv.URL, "k")}
	decision, _, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if !ok {
		t.Fatal("ok = false; want true on AI success")
	}
	if decision != "escalate" {
		t.Errorf("decision = %q; want escalate", decision)
	}
}

// TestReviewAutomatorAdapter_AutomateReview_UnknownDecisionFallback
// asserts that an unexpected decision string (e.g. AI hallucinates
// "delete") trips the fallback. AccessReviewService must NOT trust
// arbitrary decisions per docs/architecture.md §9.
func TestReviewAutomatorAdapter_AutomateReview_UnknownDecisionFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(aiclient.SkillResponse{
			Decision: "delete-the-tenant",
		})
	}))
	t.Cleanup(srv.Close)

	a := &ReviewAutomatorAdapter{Inner: aiclient.NewAIClient(srv.URL, "k")}
	decision, reason, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if ok {
		t.Fatal("ok = true; want false on unrecognised verdict")
	}
	if decision != "" || reason != "" {
		t.Errorf("decision=%q reason=%q; want empty on fallback", decision, reason)
	}
}

// TestReviewAutomatorAdapter_AutomateReview_AIUnavailable drives the
// adapter against an httptest server that returns HTTP 500 and
// verifies the (decision, reason, ok) tuple degrades to the
// docs/architecture.md §9 "leave pending" fallback rather than surfacing
// the error to the caller.
func TestReviewAutomatorAdapter_AutomateReview_AIUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	a := &ReviewAutomatorAdapter{Inner: aiclient.NewAIClient(srv.URL, "k")}
	decision, reason, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if ok {
		t.Fatal("ok = true; want false on AI 500")
	}
	if decision != "" || reason != "" {
		t.Errorf("decision=%q reason=%q; want empty on AI 500", decision, reason)
	}
}

// TestReviewAutomatorAdapter_AutomateReview_EmptyDecisionFallback
// asserts that a 2xx response with an empty Decision field is
// treated as the same fallback — the AI explicitly said "no
// verdict", so the decision stays pending.
func TestReviewAutomatorAdapter_AutomateReview_EmptyDecisionFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(aiclient.SkillResponse{Decision: "", Reason: "unsure"})
	}))
	t.Cleanup(srv.Close)

	a := &ReviewAutomatorAdapter{Inner: aiclient.NewAIClient(srv.URL, "k")}
	_, _, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if ok {
		t.Fatal("ok = true; want false on empty decision")
	}
}

// TestReviewAutomatorAdapter_NilInner_DoubleCheck mirrors the
// adapter-level nil-safety guard already covered in
// review_service_autocert_test.go but lives in this file so the
// dedicated automator test file is self-sufficient.
func TestReviewAutomatorAdapter_NilInner_DoubleCheck(t *testing.T) {
	a := &ReviewAutomatorAdapter{Inner: nil}
	_, _, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if ok {
		t.Fatal("ok = true; want false when Inner is nil")
	}
}
