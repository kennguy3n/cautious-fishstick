package aiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInvokeSkill_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/a2a/invoke" {
			t.Errorf("path = %q; want /a2a/invoke", r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "secret-key" {
			t.Errorf("X-API-Key = %q; want secret-key", got)
		}
		var body invokePayload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.SkillName != "access_risk_assessment" {
			t.Errorf("skill_name = %q", body.SkillName)
		}
		_ = json.NewEncoder(w).Encode(SkillResponse{
			RiskScore:   "low",
			RiskFactors: []string{"none"},
		})
	}))
	defer server.Close()

	c := NewAIClient(server.URL, "secret-key")
	resp, err := c.InvokeSkill(context.Background(), "access_risk_assessment", map[string]string{"foo": "bar"})
	if err != nil {
		t.Fatalf("InvokeSkill: %v", err)
	}
	if resp.RiskScore != "low" {
		t.Fatalf("RiskScore = %q; want low", resp.RiskScore)
	}
	if len(resp.RiskFactors) != 1 || resp.RiskFactors[0] != "none" {
		t.Fatalf("RiskFactors = %v", resp.RiskFactors)
	}
}

func TestInvokeSkill_NonOKStatusReturnsErrAIRequestFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer server.Close()

	c := NewAIClient(server.URL, "")
	_, err := c.InvokeSkill(context.Background(), "x", nil)
	if !errors.Is(err, ErrAIRequestFailed) {
		t.Fatalf("err = %v; want ErrAIRequestFailed", err)
	}
}

func TestInvokeSkill_EmptyBaseURLReturnsErrAIUnconfigured(t *testing.T) {
	c := NewAIClient("", "")
	_, err := c.InvokeSkill(context.Background(), "x", nil)
	if !errors.Is(err, ErrAIUnconfigured) {
		t.Fatalf("err = %v; want ErrAIUnconfigured", err)
	}
}

func TestInvokeSkill_EmptySkillReturnsError(t *testing.T) {
	c := NewAIClient("http://example.com", "")
	_, err := c.InvokeSkill(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error for empty skill_name")
	}
}

func TestInvokeSkill_TimeoutReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewAIClient(server.URL, "")
	c.SetHTTPClient(&http.Client{Timeout: 10 * time.Millisecond})
	_, err := c.InvokeSkill(context.Background(), "x", nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestInvokeSkill_MalformedResponseReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not-json")
	}))
	defer server.Close()
	c := NewAIClient(server.URL, "")
	_, err := c.InvokeSkill(context.Background(), "x", nil)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAssessRiskWithFallback_AIReturnsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{RiskScore: "high", RiskFactors: []string{"x"}})
	}))
	defer server.Close()

	c := NewAIClient(server.URL, "")
	resp, ok := AssessRiskWithFallback(context.Background(), c, map[string]string{"x": "y"})
	if !ok {
		t.Fatal("ok = false; want true on happy path")
	}
	if resp.RiskScore != "high" {
		t.Fatalf("RiskScore = %q; want high", resp.RiskScore)
	}
}

func TestAssessRiskWithFallback_NilClientReturnsFallback(t *testing.T) {
	resp, ok := AssessRiskWithFallback(context.Background(), nil, nil)
	if ok {
		t.Fatal("ok = true; want false on nil client")
	}
	if resp.RiskScore != DefaultRiskScore {
		t.Fatalf("RiskScore = %q; want %q", resp.RiskScore, DefaultRiskScore)
	}
	if len(resp.RiskFactors) != 1 || resp.RiskFactors[0] != "ai_unavailable" {
		t.Fatalf("RiskFactors = %v; want [ai_unavailable]", resp.RiskFactors)
	}
}

func TestAssessRiskWithFallback_UnconfiguredReturnsFallback(t *testing.T) {
	c := NewAIClient("", "")
	resp, ok := AssessRiskWithFallback(context.Background(), c, nil)
	if ok {
		t.Fatal("ok = true; want false")
	}
	if resp.RiskScore != DefaultRiskScore {
		t.Fatalf("RiskScore = %q; want %q", resp.RiskScore, DefaultRiskScore)
	}
}

func TestAssessRiskWithFallback_ServerErrorReturnsFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewAIClient(server.URL, "")
	resp, ok := AssessRiskWithFallback(context.Background(), c, nil)
	if ok {
		t.Fatal("ok = true; want false on server error")
	}
	if resp.RiskScore != DefaultRiskScore {
		t.Fatalf("RiskScore = %q; want %q", resp.RiskScore, DefaultRiskScore)
	}
}

func TestAssessRiskWithFallback_EmptyResponseReturnsFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	defer server.Close()
	c := NewAIClient(server.URL, "")
	resp, ok := AssessRiskWithFallback(context.Background(), c, nil)
	if ok {
		t.Fatal("ok = true; want false on empty response")
	}
	if resp.RiskScore != DefaultRiskScore {
		t.Fatalf("RiskScore = %q; want %q", resp.RiskScore, DefaultRiskScore)
	}
}

func TestTruncateBody_ShortBodyReturnedAsIs(t *testing.T) {
	if got := truncateBody([]byte("ok")); got != "ok" {
		t.Fatalf("truncateBody = %q; want ok", got)
	}
}

func TestTruncateBody_LongBodyTruncated(t *testing.T) {
	long := strings.Repeat("x", 1000)
	got := truncateBody([]byte(long))
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected truncation suffix; got %q", got[len(got)-10:])
	}
}
