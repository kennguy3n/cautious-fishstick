package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAPIPolicyEvaluator_EvaluateCommand_HappyPath proves the
// evaluator POSTs the right shape and decodes the response.
func TestAPIPolicyEvaluator_EvaluateCommand_HappyPath(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotBody   evaluateRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"deny","reason":"matched policy pcp-1","matched_policy_id":"pcp-1"}`)
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "k-1", nil)
	action, reason, err := eval.EvaluateCommand(context.Background(), "ws-1", "ses-1", "rm -rf /")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != "deny" {
		t.Fatalf("action = %q; want deny", action)
	}
	if reason != "matched policy pcp-1" {
		t.Fatalf("reason = %q; want %q", reason, "matched policy pcp-1")
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/pam/policy/evaluate" {
		t.Fatalf("path = %q; want /pam/policy/evaluate", gotPath)
	}
	if gotAuth != "Bearer k-1" {
		t.Fatalf("authorization = %q; want %q", gotAuth, "Bearer k-1")
	}
	if gotBody.WorkspaceID != "ws-1" || gotBody.SessionID != "ses-1" || gotBody.Input != "rm -rf /" {
		t.Fatalf("body = %+v; want ws-1/ses-1/rm -rf /", gotBody)
	}
}

func TestAPIPolicyEvaluator_NilReceiverAllowsEverything(t *testing.T) {
	var eval *APIPolicyEvaluator
	action, reason, err := eval.EvaluateCommand(context.Background(), "ws-1", "ses-1", "anything")
	if err != nil {
		t.Fatalf("nil receiver returned err: %v", err)
	}
	if action != "allow" {
		t.Fatalf("nil receiver action = %q; want allow", action)
	}
	if reason != "" {
		t.Fatalf("nil receiver reason = %q; want empty", reason)
	}
}

func TestAPIPolicyEvaluator_EmptyInputShortCircuits(t *testing.T) {
	// If the evaluator hits the network for an empty input it
	// would generate spurious load on the control plane for every
	// stray carriage return. The server is intentionally
	// failing-loud so a regression here trips the test.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("HTTP server should not be hit on empty input")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "k-1", nil)
	action, _, err := eval.EvaluateCommand(context.Background(), "ws-1", "ses-1", "")
	if err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
	if action != "allow" {
		t.Fatalf("empty input action = %q; want allow", action)
	}
}

func TestAPIPolicyEvaluator_EmptyWorkspaceRejected(t *testing.T) {
	eval := NewAPIPolicyEvaluator("http://unused", "k", nil)
	_, _, err := eval.EvaluateCommand(context.Background(), "", "ses-1", "ls")
	if err == nil || !strings.Contains(err.Error(), "workspace_id") {
		t.Fatalf("err = %v; want 'workspace_id' error", err)
	}
}

func TestAPIPolicyEvaluator_EmptySessionRejected(t *testing.T) {
	eval := NewAPIPolicyEvaluator("http://unused", "k", nil)
	_, _, err := eval.EvaluateCommand(context.Background(), "ws", "", "ls")
	if err == nil || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("err = %v; want 'session_id' error", err)
	}
}

func TestAPIPolicyEvaluator_Non200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "k", nil)
	_, _, err := eval.EvaluateCommand(context.Background(), "ws", "ses", "ls")
	if err == nil {
		t.Fatalf("expected error on 500 response")
	}
	if !strings.Contains(err.Error(), "status=500") {
		t.Fatalf("err = %v; want status=500", err)
	}
}

func TestAPIPolicyEvaluator_MalformedJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"action":`)
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "k", nil)
	_, _, err := eval.EvaluateCommand(context.Background(), "ws", "ses", "ls")
	if err == nil || !strings.Contains(err.Error(), "decode evaluate body") {
		t.Fatalf("err = %v; want decode error", err)
	}
}

func TestAPIPolicyEvaluator_EmptyActionErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"action":""}`)
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "k", nil)
	_, _, err := eval.EvaluateCommand(context.Background(), "ws", "ses", "ls")
	if err == nil || !strings.Contains(err.Error(), "empty action") {
		t.Fatalf("err = %v; want 'empty action' error", err)
	}
}

func TestAPIPolicyEvaluator_OmitsAuthorizationWhenAPIKeyEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization should be omitted when api key is empty; got %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "", nil)
	if _, _, err := eval.EvaluateCommand(context.Background(), "ws", "ses", "ls"); err != nil {
		t.Fatalf("EvaluateCommand: %v", err)
	}
}

func TestAPIPolicyEvaluator_RespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	}))
	defer srv.Close()

	eval := NewAPIPolicyEvaluator(srv.URL, "k", &http.Client{Timeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := eval.EvaluateCommand(ctx, "ws", "ses", "ls")
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func TestAPIPolicyEvaluator_NilClientGetsDefault(t *testing.T) {
	eval := NewAPIPolicyEvaluator("http://x", "k", nil)
	if eval.client == nil {
		t.Fatalf("expected default client when nil supplied")
	}
	if eval.client.Timeout != 5*time.Second {
		t.Fatalf("default timeout = %s; want 5s", eval.client.Timeout)
	}
}
