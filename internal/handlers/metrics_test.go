package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestMetricsRegistry_RenderEmpty(t *testing.T) {
	r := NewMetricsRegistry()
	out := r.Render()
	if out != "" {
		t.Fatalf("expected empty render, got %q", out)
	}
}

func TestMetricsRegistry_HTTPRequestCounter(t *testing.T) {
	r := NewMetricsRegistry()
	r.ObserveHTTPRequest("GET", "/access/requests/:id", 200, 12*time.Millisecond)
	r.ObserveHTTPRequest("GET", "/access/requests/:id", 200, 90*time.Millisecond)
	r.ObserveHTTPRequest("GET", "/access/requests/:id", 500, 5*time.Millisecond)

	out := r.Render()

	if !strings.Contains(out, "# TYPE ztna_api_http_requests_total counter\n") {
		t.Fatalf("missing TYPE line for http_requests_total:\n%s", out)
	}
	if !strings.Contains(out, `ztna_api_http_requests_total{method="GET",path="/access/requests/:id",status="200"} 2`) {
		t.Fatalf("expected counter to record 2 successful requests:\n%s", out)
	}
	if !strings.Contains(out, `ztna_api_http_requests_total{method="GET",path="/access/requests/:id",status="500"} 1`) {
		t.Fatalf("expected counter to record 1 failure:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE ztna_api_http_request_duration_seconds histogram\n") {
		t.Fatalf("missing histogram TYPE line:\n%s", out)
	}
	if !strings.Contains(out, `ztna_api_http_request_duration_seconds_count{method="GET",path="/access/requests/:id"} 3`) {
		t.Fatalf("expected histogram count = 3:\n%s", out)
	}
}

func TestMetricsRegistry_NilSafe(t *testing.T) {
	// Nil receivers must not panic — handlers and middleware rely on
	// this to stay safe when deps.Metrics is unset.
	var r *MetricsRegistry
	r.ObserveHTTPRequest("GET", "/x", 200, time.Second)
	r.ObserveConnectorSync("okta", "identities", "success", time.Second)
	r.ObserveAIAgentCall("risk", "success", time.Second)
	r.SetQueueDepth("audit", 5)
}

func TestMetricsRegistry_ConnectorAIQueue(t *testing.T) {
	r := NewMetricsRegistry()
	r.ObserveConnectorSync("okta", "identities", "success", 250*time.Millisecond)
	r.ObserveAIAgentCall("assess_risk", "success", 80*time.Millisecond)
	r.SetQueueDepth("audit", 7)
	r.SetQueueDepth("sync", 0)

	out := r.Render()

	checks := []string{
		`# TYPE ztna_api_connector_sync_duration_seconds histogram`,
		`ztna_api_connector_sync_duration_seconds_count{provider="okta",kind="identities",status="success"} 1`,
		`# TYPE ztna_api_ai_agent_call_duration_seconds histogram`,
		`ztna_api_ai_agent_call_duration_seconds_count{skill="assess_risk",status="success"} 1`,
		`# TYPE ztna_api_worker_queue_depth gauge`,
		`ztna_api_worker_queue_depth{queue="audit"} 7`,
		`ztna_api_worker_queue_depth{queue="sync"} 0`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("missing %q in metrics output:\n%s", c, out)
		}
	}
}

// validPromLine is a loose grammar check for Prometheus exposition
// format: each non-empty, non-comment line must start with a metric
// name (alpha/underscore/colon then alphanumeric/underscore/colon),
// optionally followed by a labelset in braces, a space, then a value.
var validPromLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+[^\s]+(\s+[0-9]+)?$`)

func TestMetricsHandler_ValidPrometheusFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := NewMetricsRegistry()
	r.ObserveHTTPRequest("POST", "/access/requests", 201, 50*time.Millisecond)
	r.ObserveAIAgentCall("assess_risk", "error", 1200*time.Millisecond)

	engine := gin.New()
	engine.GET("/metrics", MetricsHandler(r))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain Content-Type, got %q", ct)
	}

	for i, line := range strings.Split(strings.TrimSpace(w.Body.String()), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !validPromLine.MatchString(line) {
			t.Fatalf("line %d not valid Prometheus exposition format: %q", i+1, line)
		}
	}
}

func TestMetricsHandler_NilRegistry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/metrics", MetricsHandler(nil))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even with nil registry, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ztna_api_up 1") {
		t.Fatalf("expected ztna_api_up fallback metric, got:\n%s", w.Body.String())
	}
}

func TestMetricsMiddleware_PopulatesRegistryFromRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := NewMetricsRegistry()
	engine := gin.New()
	engine.Use(MetricsMiddleware(r))
	engine.GET("/access/requests/:id", func(c *gin.Context) { c.JSON(200, gin.H{"id": c.Param("id")}) })

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/access/requests/abc", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
	}

	out := r.Render()
	if !strings.Contains(out, `ztna_api_http_requests_total{method="GET",path="/access/requests/:id",status="200"} 3`) {
		t.Fatalf("middleware did not aggregate by matched route:\n%s", out)
	}
}

func TestMetricsMiddleware_UnmatchedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := NewMetricsRegistry()
	engine := gin.New()
	engine.Use(MetricsMiddleware(r))

	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	out := r.Render()
	if !strings.Contains(out, `path="unmatched"`) {
		t.Fatalf("unmatched route should bucket under path=\"unmatched\":\n%s", out)
	}
}
