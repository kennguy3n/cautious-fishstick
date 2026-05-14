package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimiter_AllowsRequestsUnderLimit(t *testing.T) {
	rl := NewRateLimiterWithRPS(10)
	for i := 0; i < 5; i++ {
		ok, _ := rl.Allow("ws:abc")
		if !ok {
			t.Fatalf("request %d: expected allow, got deny", i+1)
		}
	}
}

func TestRateLimiter_DeniesWhenBucketEmpty(t *testing.T) {
	rl := NewRateLimiterWithRPS(2) // capacity = 2 * 2 = 4
	// Burn the bucket.
	for i := 0; i < 4; i++ {
		ok, _ := rl.Allow("ws:abc")
		if !ok {
			t.Fatalf("burst request %d: expected allow", i+1)
		}
	}
	// Next call has no tokens left and no time has elapsed.
	ok, retryAfter := rl.Allow("ws:abc")
	if ok {
		t.Fatalf("expected deny after exhausting bucket")
	}
	if retryAfter < 1 {
		t.Fatalf("expected retry-after >=1s, got %d", retryAfter)
	}
}

func TestRateLimiter_RefillsAfterElapsedTime(t *testing.T) {
	rl := NewRateLimiterWithRPS(10) // capacity = 20
	// Drive time deterministically.
	now := time.Unix(1_700_000_000, 0)
	rl.nowFunc = func() time.Time { return now }

	for i := 0; i < 20; i++ {
		ok, _ := rl.Allow("ws:abc")
		if !ok {
			t.Fatalf("burst request %d: expected allow", i+1)
		}
	}
	ok, _ := rl.Allow("ws:abc")
	if ok {
		t.Fatalf("expected deny after burst exhaust")
	}
	// Advance one second — should refill 10 tokens.
	now = now.Add(time.Second)
	for i := 0; i < 10; i++ {
		ok, _ := rl.Allow("ws:abc")
		if !ok {
			t.Fatalf("post-refill request %d: expected allow", i+1)
		}
	}
	ok, _ = rl.Allow("ws:abc")
	if ok {
		t.Fatalf("expected deny after second exhaust")
	}
}

func TestRateLimiter_IndependentBucketsPerIdentifier(t *testing.T) {
	rl := NewRateLimiterWithRPS(1) // capacity = 2
	for i := 0; i < 2; i++ {
		if ok, _ := rl.Allow("ws:a"); !ok {
			t.Fatalf("ws:a burst %d: expected allow", i+1)
		}
	}
	if ok, _ := rl.Allow("ws:a"); ok {
		t.Fatalf("ws:a should be exhausted")
	}
	// ws:b has its own bucket, untouched.
	if ok, _ := rl.Allow("ws:b"); !ok {
		t.Fatalf("ws:b should be unaffected by ws:a exhaustion")
	}
}

func TestRateLimiterMiddleware_Returns429WhenExceeded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := NewRateLimiterWithRPS(1) // capacity = 2

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/access/anything", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// First two calls succeed; the third must 429.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/access/anything?workspace_id=ws-1", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("burst request %d: expected 200, got %d", i+1, w.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/access/anything?workspace_id=ws-1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429, got empty")
	}
	if _, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil {
		t.Fatalf("Retry-After must be numeric seconds, got %q", w.Header().Get("Retry-After"))
	}
}

func TestRateLimiterMiddleware_HealthEndpointBypasses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := NewRateLimiterWithRPS(0.0001) // capacity ≈ 0.0002, effectively no tokens

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("/health probe %d should never be throttled, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimitRPSFromEnv_DefaultsWhenUnset(t *testing.T) {
	t.Setenv("ZTNA_API_RATE_LIMIT_RPS", "")
	if got := rateLimitRPSFromEnv(); got != float64(defaultRateLimitRPS) {
		t.Fatalf("expected default %d, got %v", defaultRateLimitRPS, got)
	}
}

func TestRateLimitRPSFromEnv_ParsesPositiveValues(t *testing.T) {
	t.Setenv("ZTNA_API_RATE_LIMIT_RPS", "42.5")
	if got := rateLimitRPSFromEnv(); got != 42.5 {
		t.Fatalf("expected 42.5, got %v", got)
	}
}

func TestRateLimitRPSFromEnv_FallsBackOnBadValues(t *testing.T) {
	for _, raw := range []string{"-1", "0", "not-a-number"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("ZTNA_API_RATE_LIMIT_RPS", raw)
			if got := rateLimitRPSFromEnv(); got != float64(defaultRateLimitRPS) {
				t.Fatalf("input %q: expected default fallback, got %v", raw, got)
			}
		})
	}
}

func TestRateLimiter_NilSafeMiddleware(t *testing.T) {
	// A nil receiver should produce a passthrough handler so callers
	// can write `r.Use((&RateLimiter{...}).Middleware())` without a
	// branch on whether the limiter was constructed.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var rl *RateLimiter
	r.Use(rl.Middleware())
	r.GET("/access/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/access/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("nil limiter should be a passthrough, got %d", w.Code)
	}
}

func TestRateLimiter_HeaderFallbackIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := NewRateLimiterWithRPS(1) // capacity 2

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/access/foo", func(c *gin.Context) { c.Status(http.StatusOK) })

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/access/foo", nil)
		req.Header.Set("X-Workspace-ID", "ws-via-header")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("burst %d: expected 200, got %d", i+1, w.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/access/foo", nil)
	req.Header.Set("X-Workspace-ID", "ws-via-header")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for header-only workspace, got %d", w.Code)
	}
}

func TestRateLimiter_IdleEvictionShrinksMap(t *testing.T) {
	rl := NewRateLimiterWithRPS(10)
	now := time.Unix(1_700_000_000, 0)
	rl.nowFunc = func() time.Time { return now }

	// Hit ws-a, then advance far past idleEvictionAfter, then hit
	// ws-b. The act of inserting ws-b triggers the sweep and ws-a
	// should be gone.
	rl.Allow("ws-a")
	now = now.Add(idleEvictionAfter + time.Second)
	rl.Allow("ws-b")

	if _, ok := rl.buckets.Load("ws-a"); ok {
		t.Fatalf("ws-a should have been evicted after idle window")
	}
	if _, ok := rl.buckets.Load("ws-b"); !ok {
		t.Fatalf("ws-b should still be present")
	}
}

func TestMain_RateLimitEnvDoesNotLeak(t *testing.T) {
	// Sanity: clearing the env var must not leave a sticky value
	// from a previous test (covers a regression we hit when
	// rateLimitRPSFromEnv used a package-level cached parse).
	os.Unsetenv("ZTNA_API_RATE_LIMIT_RPS")
	if got := rateLimitRPSFromEnv(); got != float64(defaultRateLimitRPS) {
		t.Fatalf("expected default after unset, got %v", got)
	}
}
