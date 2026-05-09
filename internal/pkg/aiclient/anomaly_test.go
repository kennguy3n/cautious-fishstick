package aiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAIClient_DetectAnomalies_HappyPath asserts a 200 response
// with a structured Anomalies array round-trips through the client
// unchanged.
func TestAIClient_DetectAnomalies_HappyPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/a2a/invoke" {
			t.Errorf("path = %q; want /a2a/invoke", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var inv invokePayload
		if err := json.Unmarshal(body, &inv); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if inv.SkillName != "access_anomaly_detection" {
			t.Errorf("skill = %q; want access_anomaly_detection", inv.SkillName)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"anomalies": [
				{"kind":"geo_unusual","severity":"medium","confidence":0.78,"reason":"sign-in from new country"},
				{"kind":"frequency_spike","severity":"high","confidence":0.91,"reason":"10x baseline access rate"}
			]
		}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAIClient(srv.URL, "test-key")
	c.SetHTTPClient(srv.Client())

	got, err := c.DetectAnomalies(context.Background(), "01H00000000000000GRANT00001", map[string]interface{}{
		"days_since_last_use": 0,
	})
	if err != nil {
		t.Fatalf("DetectAnomalies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("anomalies = %d; want 2", len(got))
	}
	if got[0].Kind != "geo_unusual" {
		t.Errorf("anomalies[0].Kind = %q; want geo_unusual", got[0].Kind)
	}
	if got[1].Severity != "high" {
		t.Errorf("anomalies[1].Severity = %q; want high", got[1].Severity)
	}
}

// TestAIClient_DetectAnomalies_Empty asserts a 200 response with
// no anomalies returns an empty slice (not an error).
func TestAIClient_DetectAnomalies_Empty(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAIClient(srv.URL, "k")
	c.SetHTTPClient(srv.Client())
	got, err := c.DetectAnomalies(context.Background(), "g1", nil)
	if err != nil {
		t.Fatalf("DetectAnomalies: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("anomalies = %v; want empty", got)
	}
}

// TestAIClient_DetectAnomalies_TransportError asserts that a
// non-200 response surfaces ErrAIRequestFailed.
func TestAIClient_DetectAnomalies_TransportError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAIClient(srv.URL, "k")
	c.SetHTTPClient(srv.Client())
	_, err := c.DetectAnomalies(context.Background(), "g1", nil)
	if !errors.Is(err, ErrAIRequestFailed) {
		t.Errorf("err = %v; want errors.Is(err, ErrAIRequestFailed)", err)
	}
}

// TestDetectAnomaliesWithFallback_NilClient asserts a nil client
// surfaces the empty fallback without panicking.
func TestDetectAnomaliesWithFallback_NilClient(t *testing.T) {
	t.Parallel()
	buf := captureLogs(t)
	got, ok := DetectAnomaliesWithFallback(context.Background(), nil, "g1", nil)
	if ok {
		t.Errorf("ok = true; want false")
	}
	if len(got) != 0 {
		t.Errorf("anomalies = %v; want empty", got)
	}
	if !strings.Contains(buf.String(), "client is nil") {
		t.Errorf("log missing nil-client warning: %q", buf.String())
	}
}

// TestDetectAnomaliesWithFallback_AIUnreachable asserts an
// unreachable AI agent surfaces the empty fallback and ok=false.
func TestDetectAnomaliesWithFallback_AIUnreachable(t *testing.T) {
	t.Parallel()
	c := NewAIClient("http://127.0.0.1:1", "k") // port 1 is reserved → connect refused
	got, ok := DetectAnomaliesWithFallback(context.Background(), c, "g1", nil)
	if ok {
		t.Errorf("ok = true; want false on unreachable AI")
	}
	if len(got) != 0 {
		t.Errorf("anomalies = %v; want empty", got)
	}
}

// TestDetectAnomaliesWithFallback_HappyPath asserts the wrapper
// returns the agent's anomalies unchanged on success.
func TestDetectAnomaliesWithFallback_HappyPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"anomalies":[{"kind":"stale_grant"}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAIClient(srv.URL, "k")
	c.SetHTTPClient(srv.Client())
	got, ok := DetectAnomaliesWithFallback(context.Background(), c, "g1", nil)
	if !ok {
		t.Errorf("ok = false; want true on AI success")
	}
	if len(got) != 1 || got[0].Kind != "stale_grant" {
		t.Errorf("anomalies = %v; want [{stale_grant}]", got)
	}
}

// captureLogs swaps log.Default()'s writer for an in-memory buffer
// so the fallback warnings can be asserted against. Restored on
// cleanup.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}
