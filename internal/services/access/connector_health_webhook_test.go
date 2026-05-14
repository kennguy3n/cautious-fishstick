package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureWebhookServer records every received envelope so tests can
// inspect EventType and trigger counts.
type captureWebhookServer struct {
	mu        sync.Mutex
	envelopes []ConnectorHealthEvent
	server    *httptest.Server
	failCount int // 0 → always 200; >0 → return 500 for the first N hits
}

func newCaptureWebhookServer(failCount int) *captureWebhookServer {
	c := &captureWebhookServer{failCount: failCount}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "wrong content-type", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var ev ConnectorHealthEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.envelopes = append(c.envelopes, ev)
		shouldFail := c.failCount > 0
		if shouldFail {
			c.failCount--
		}
		c.mu.Unlock()
		if shouldFail {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return c
}

func (c *captureWebhookServer) URL() string { return c.server.URL }
func (c *captureWebhookServer) Close()      { c.server.Close() }
func (c *captureWebhookServer) Received() []ConnectorHealthEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ConnectorHealthEvent, len(c.envelopes))
	copy(out, c.envelopes)
	return out
}

// TestConnectorHealthWebhook_StaleAuditDispatches verifies the
// "stale_audit" trigger fires exactly one POST with the expected
// fields populated.
func TestConnectorHealthWebhook_StaleAuditDispatches(t *testing.T) {
	srv := newCaptureWebhookServer(0)
	t.Cleanup(srv.Close)

	d := NewConnectorHealthWebhookDispatcher(ConnectorHealthWebhookConfig{
		WebhookURL: srv.URL(),
		HTTPClient: srv.server.Client(),
	})
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	lastAudit := now.Add(-48 * time.Hour)
	n, err := d.EvaluateAndDispatch(context.Background(),
		"01HCONN", "01HWS", "okta", "directory", "active",
		nil, true, &lastAudit, now,
	)
	if err != nil {
		t.Fatalf("EvaluateAndDispatch: %v", err)
	}
	if n != 1 {
		t.Errorf("dispatched = %d; want 1", n)
	}
	got := srv.Received()
	if len(got) != 1 {
		t.Fatalf("envelopes = %d; want 1", len(got))
	}
	if got[0].EventType != "stale_audit" {
		t.Errorf("event_type = %q; want stale_audit", got[0].EventType)
	}
	if got[0].ConnectorID != "01HCONN" || got[0].WorkspaceID != "01HWS" {
		t.Errorf("ids: %+v", got[0])
	}
}

// TestConnectorHealthWebhook_CredentialExpiredDispatches verifies
// the "credential_expired" trigger fires when CredentialExpiredTime
// is in the past.
func TestConnectorHealthWebhook_CredentialExpiredDispatches(t *testing.T) {
	srv := newCaptureWebhookServer(0)
	t.Cleanup(srv.Close)

	d := NewConnectorHealthWebhookDispatcher(ConnectorHealthWebhookConfig{
		WebhookURL: srv.URL(),
		HTTPClient: srv.server.Client(),
	})
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-3 * time.Hour)
	n, err := d.EvaluateAndDispatch(context.Background(),
		"01HCONN", "01HWS", "okta", "directory", "active",
		&expired, false, nil, now,
	)
	if err != nil {
		t.Fatalf("EvaluateAndDispatch: %v", err)
	}
	if n != 1 {
		t.Errorf("dispatched = %d; want 1", n)
	}
	got := srv.Received()
	if len(got) != 1 {
		t.Fatalf("envelopes = %d; want 1", len(got))
	}
	if got[0].EventType != "credential_expired" {
		t.Errorf("event_type = %q; want credential_expired", got[0].EventType)
	}
}

// TestConnectorHealthWebhook_BothTriggersFireTwoEvents verifies
// that when both conditions are met two separate POSTs are made so
// downstream receivers can dedupe per event_type.
func TestConnectorHealthWebhook_BothTriggersFireTwoEvents(t *testing.T) {
	srv := newCaptureWebhookServer(0)
	t.Cleanup(srv.Close)

	d := NewConnectorHealthWebhookDispatcher(ConnectorHealthWebhookConfig{
		WebhookURL: srv.URL(),
		HTTPClient: srv.server.Client(),
	})
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-1 * time.Hour)
	lastAudit := now.Add(-30 * time.Hour)
	n, err := d.EvaluateAndDispatch(context.Background(),
		"01HCONN", "01HWS", "okta", "directory", "active",
		&expired, true, &lastAudit, now,
	)
	if err != nil {
		t.Fatalf("EvaluateAndDispatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("dispatched = %d; want 2", n)
	}
	got := srv.Received()
	types := make([]string, len(got))
	for i, ev := range got {
		types[i] = ev.EventType
	}
	if !containsAll(types, []string{"stale_audit", "credential_expired"}) {
		t.Errorf("event types = %v; want both stale_audit & credential_expired", types)
	}
}

// TestConnectorHealthWebhook_FutureCredentialNoFire verifies the
// failure path: credentials that haven't expired yet (in the future)
// do NOT trigger a credential_expired event.
func TestConnectorHealthWebhook_FutureCredentialNoFire(t *testing.T) {
	srv := newCaptureWebhookServer(0)
	t.Cleanup(srv.Close)

	d := NewConnectorHealthWebhookDispatcher(ConnectorHealthWebhookConfig{
		WebhookURL: srv.URL(),
		HTTPClient: srv.server.Client(),
	})
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	future := now.Add(7 * 24 * time.Hour)
	n, err := d.EvaluateAndDispatch(context.Background(),
		"01HCONN", "01HWS", "okta", "directory", "active",
		&future, false, nil, now,
	)
	if err != nil {
		t.Fatalf("EvaluateAndDispatch: %v", err)
	}
	if n != 0 {
		t.Errorf("dispatched = %d; want 0", n)
	}
	if got := srv.Received(); len(got) != 0 {
		t.Errorf("envelopes received = %d; want 0", len(got))
	}
}

// TestConnectorHealthWebhook_EmptyURLNoop is the explicit no-op
// path: an unconfigured webhook URL must not error and must not
// require an HTTP client.
func TestConnectorHealthWebhook_EmptyURLNoop(t *testing.T) {
	d := NewConnectorHealthWebhookDispatcher(ConnectorHealthWebhookConfig{WebhookURL: ""})
	if d.Configured() {
		t.Error("Configured() = true; want false for empty URL")
	}
	now := time.Now()
	expired := now.Add(-1 * time.Hour)
	n, err := d.EvaluateAndDispatch(context.Background(),
		"01HCONN", "01HWS", "okta", "directory", "active",
		&expired, true, nil, now,
	)
	if err != nil {
		t.Fatalf("EvaluateAndDispatch: %v", err)
	}
	if n != 0 {
		t.Errorf("dispatched = %d; want 0 (no-op)", n)
	}
}

// TestConnectorHealthWebhook_5xxReturnsError is the failure path:
// a 500 from the webhook receiver must surface as an error to the
// caller (so the caller can log / retry / metric on it).
func TestConnectorHealthWebhook_5xxReturnsError(t *testing.T) {
	srv := newCaptureWebhookServer(10) // every call fails
	t.Cleanup(srv.Close)

	d := NewConnectorHealthWebhookDispatcher(ConnectorHealthWebhookConfig{
		WebhookURL: srv.URL(),
		HTTPClient: srv.server.Client(),
	})
	now := time.Now()
	_, err := d.EvaluateAndDispatch(context.Background(),
		"01HCONN", "01HWS", "okta", "directory", "active",
		nil, true, nil, now,
	)
	if err == nil {
		t.Fatal("expected error on 500 webhook response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q missing status code", err.Error())
	}
}

func containsAll(haystack, needles []string) bool {
	for _, n := range needles {
		found := false
		for _, h := range haystack {
			if h == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
