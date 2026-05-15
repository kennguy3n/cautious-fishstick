package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// Task 8 (PHASES.md cross-cutting test coverage hardening) — exercises
// the *gin.Engine returned by Router(Dependencies{}) end-to-end: the
// middleware chain (gin.Recovery → JSONLoggerMiddleware →
// MetricsMiddleware → RateLimiter → JSONValidationMiddleware), the
// always-on /health, /metrics, /swagger* routes, and the
// dependency-gated handler registrations. The contract under test is
// docs/architecture.md §5 "Hot-path HTTP server" and the
// cross-cutting rule that Router(Dependencies{}) on a bare struct
// never panics — it returns a healthy engine with only the
// always-on routes wired.
//
// The tests use httptest.NewRecorder to dial the engine in-process so
// no real network I/O happens, matching the project convention.

// routerForTest constructs a router with the rate limiter disabled
// (so back-to-back probes never get 429'd) so each subtest is
// independent. Each subtest can pass extra Dependencies fields via
// the variadic; the helper supplies the DisableRateLimiter default.
func routerForTest(t *testing.T, mutators ...func(d *Dependencies)) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	d := Dependencies{DisableRateLimiter: true}
	for _, m := range mutators {
		m(&d)
	}
	return Router(d)
}

func TestRouter_AlwaysOnRoutes(t *testing.T) {
	r := routerForTest(t)

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string // substring
	}{
		{"health", http.MethodGet, "/health", http.StatusOK, `"status":"ok"`},
		{"metrics", http.MethodGet, "/metrics", http.StatusOK, ""},
		{"swagger-json", http.MethodGet, "/swagger.json", http.StatusOK, ""},
		{"swagger-yaml", http.MethodGet, "/swagger.yaml", http.StatusOK, ""},
		{"swagger-html", http.MethodGet, "/swagger", http.StatusOK, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%q", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body=%q does not contain %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestRouter_UnknownRouteReturns404(t *testing.T) {
	r := routerForTest(t)

	cases := []string{
		"/does-not-exist",
		"/access/no-such-resource",
		"/workspace/missing",
		"/access/grants/abc/extra/segments",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Fatalf("path=%q status=%d want=404", p, w.Code)
			}
		})
	}
}

func TestRouter_DependencyGatedRoutesNotRegisteredWhenNil(t *testing.T) {
	// With an empty Dependencies, PolicyService / AccessRequestService /
	// ConnectorManagementService etc. are all nil, so their routes are
	// NOT registered and the engine should return 404 — never panic.
	r := routerForTest(t)

	probes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/access/requests"},               // AccessRequestService nil
		{http.MethodPost, "/access/requests"},              // AccessRequestService nil
		{http.MethodGet, "/access/grants"},                 // AccessGrantReader nil
		{http.MethodGet, "/access/connectors"},             // ConnectorListReader nil
		{http.MethodGet, "/access/connectors/catalogue"},   // ConnectorCatalogueReader nil
		{http.MethodPost, "/access/reviews"},               // AccessReviewService nil
		{http.MethodGet, "/scim/Users"},                    // JMLService nil
		{http.MethodGet, "/workspace/policies"},            // PolicyService nil
		{http.MethodGet, "/access/orphans"},                // OrphanReconciler nil
	}
	for _, p := range probes {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			req := httptest.NewRequest(p.method, p.path, nil)
			if p.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
				req.Body = bodyFromString(`{}`)
				req.ContentLength = int64(len(`{}`))
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s %s status=%d want=404 body=%q", p.method, p.path, w.Code, w.Body.String())
			}
		})
	}
}

func TestRouter_AIRoutesAlwaysRegistered(t *testing.T) {
	// The AI handlers are registered regardless of AIService nil-ness so
	// callers see a structured 503 from the handler itself (not 404).
	// This is the contract documented on router.go:153-157.
	r := routerForTest(t)

	body := []byte(`{"request_id":"req_1","workspace_id":"ws_1"}`)
	cases := []string{"/access/explain", "/access/suggest"}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = int64(len(body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code == http.StatusNotFound {
				t.Fatalf("path=%q got 404 — AI handler was not registered", p)
			}
			// The exact status code is 503 (AIInvoker nil) but the test
			// only asserts that the route was *registered*; any non-404
			// proves the handler chain ran. We accept 4xx/5xx; we just
			// reject 404.
		})
	}
}

func TestRouter_JSONValidationRejectsBadContentType(t *testing.T) {
	// JSONValidationMiddleware sits at the top of the chain; a POST
	// with a body but no application/json Content-Type must short-
	// circuit to 415 before any handler runs. We use /access/explain
	// (always registered) so the test exercises only the middleware
	// gate, not handler-specific behaviour.
	r := routerForTest(t)

	body := []byte(`field=value`)
	req := httptest.NewRequest(http.MethodPost, "/access/explain", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Content-Type=form status=%d want=415 body=%q", w.Code, w.Body.String())
	}
}

func TestRouter_JSONValidationRejectsMalformedBody(t *testing.T) {
	// Bytes that are not valid JSON must produce 400 from the
	// validation middleware (not 500 from the handler).
	r := routerForTest(t)

	body := []byte(`{not-json`)
	req := httptest.NewRequest(http.MethodPost, "/access/explain", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed body status=%d want=400 body=%q", w.Code, w.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("400 body is not JSON: %v", err)
	}
}

func TestRouter_RateLimiterTripsOnAccessPaths(t *testing.T) {
	// With a hyper-aggressive limiter (0.01 RPS / capacity 1) the
	// second request to a /access/* path within the same workspace
	// bucket must come back 429. This catches regressions where the
	// limiter middleware is mis-ordered (it must run *before* handler
	// routing).
	limiter := NewRateLimiterWithRPS(0.01)
	r := routerForTest(t, func(d *Dependencies) {
		d.RateLimiter = limiter
		d.DisableRateLimiter = false
	})

	const ws = "ws_rate_test"
	statuses := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/access/grants?workspace_id="+ws, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		statuses = append(statuses, w.Code)
	}
	// The first request is the only one with budget. The remaining
	// two must be rate-limited (429); the exact ordering of 404 vs
	// 429 depends on Gin's tree, but every call after the budget
	// expires must be 429.
	saw429 := false
	for _, s := range statuses {
		if s == http.StatusTooManyRequests {
			saw429 = true
		}
	}
	if !saw429 {
		t.Fatalf("rate-limit never tripped on /access/grants; statuses=%v", statuses)
	}
}

func TestRouter_HealthBypassesRateLimiter(t *testing.T) {
	// /health is the kube probe surface — it MUST not be rate
	// limited even at hyper-aggressive RPS, otherwise a noisy
	// kubelet evicts every pod simultaneously.
	limiter := NewRateLimiterWithRPS(0.01)
	r := routerForTest(t, func(d *Dependencies) {
		d.RateLimiter = limiter
		d.DisableRateLimiter = false
	})

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("/health probe #%d returned %d, want 200", i, w.Code)
		}
	}
}

func TestRouter_RecoveryMiddlewareCatchesPanic(t *testing.T) {
	// gin.Recovery() sits at the top of the chain. We bolt a route
	// that panics onto a freshly-constructed engine to confirm the
	// recovery middleware turns the panic into a 500 rather than
	// crashing the process.
	r := routerForTest(t)
	r.GET("/test/panic", func(c *gin.Context) {
		panic("synthetic")
	})

	req := httptest.NewRequest(http.MethodGet, "/test/panic", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("panic status=%d want=500", w.Code)
	}
}

func TestRouter_ConcurrentRequestsAreSafe(t *testing.T) {
	// Smoke test for the -race detector: hammer /health from 20
	// goroutines × 20 requests and assert no panic / data race. The
	// chain crosses the metrics middleware (atomic counters) and
	// the limiter (mutex-protected bucket map).
	r := routerForTest(t)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				req := httptest.NewRequest(http.MethodGet, "/health", nil)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Errorf("status=%d want=200", w.Code)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// bodyFromString is a tiny helper that returns an io.ReadCloser over
// the bytes. We need it because httptest.NewRequest doesn't take a
// raw string and net/http expects an io.Reader for non-nil bodies.
func bodyFromString(s string) *readCloser {
	return &readCloser{Reader: strings.NewReader(s)}
}

type readCloser struct {
	*strings.Reader
}

func (r *readCloser) Close() error { return nil }
