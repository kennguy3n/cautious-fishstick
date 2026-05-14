// Package handlers — per-workspace token-bucket rate-limiting
// middleware.
//
// The Phase 8 hardening pass (docs/PROPOSAL.md §10.2 "API hardening")
// asks for a configurable rate limit on every /access/* and
// /workspace/* route. The implementation here is a classic token
// bucket per identifier (workspace_id when available, falling back
// to ClientIP for unauthenticated probes or for routes that don't
// expose a workspace context yet) running entirely in-process. The
// limiter is intentionally allocation-light and lock-cheap so it
// stays on the request hot path:
//
//   - One sync.Map keyed by identifier holds *workspaceBucket entries.
//   - Each bucket carries its own sync.Mutex so different workspaces
//     don't contend with each other.
//   - Refill is lazy: every Allow() call recomputes the bucket's
//     tokens from time.Since(lastRefill) instead of running a
//     background goroutine. This removes the goroutine-leak risk
//     unit tests are sensitive to and lets the GC reclaim a bucket
//     as soon as its identifier stops being seen (we periodically
//     evict idle buckets in Allow itself to keep the map bounded).
//
// When a request is denied the middleware returns 429 with a
// structured JSON envelope shaped like the other access-platform
// errors (Error / Message keys) plus a Retry-After header in
// seconds so well-behaved clients back off.
package handlers

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// defaultRateLimitRPS is the per-workspace fill rate when
// ZTNA_API_RATE_LIMIT_RPS is unset or unparseable. 100 req/s is the
// PROPOSAL §10.2 default and matches the SN360 ingestion-service
// budget for an admin UI burst.
const defaultRateLimitRPS = 100

// defaultRateLimitBurstFactor scales the configured RPS into the
// bucket's maximum capacity. A factor of 2× is the conventional
// "small burst for legitimate clients" envelope that keeps the bucket
// from rejecting a healthy admin UI page load (which often fans out
// 5–20 concurrent API calls in the first 250 ms) while still
// throttling abusive callers.
const defaultRateLimitBurstFactor = 2

// idleEvictionAfter is the inactivity window after which we drop a
// bucket entry. The map is unbounded otherwise and an attacker
// rotating through workspace IDs could pin every entry in memory.
// 10 minutes is well past the realistic burst window and keeps the
// allocator quiet under steady-state traffic.
const idleEvictionAfter = 10 * time.Minute

// rateLimitedPathPrefixes lists the route prefixes the middleware
// scopes itself to. Anything outside this list (e.g. /health,
// /metrics, /swagger) is exempt: probes from kube-controller-manager
// and a Prometheus scrape job would otherwise share the same bucket
// as a real client and either get throttled themselves or quickly
// burn through the bucket capacity, masking real abuse.
//
// /scim/* is intentionally omitted: SCIM endpoints are called by
// upstream IdP connectors (Okta, Auth0, Azure AD) which already have
// their own rate budgets and a separate validation pipeline in
// scim_handler.go. Adding the same throttle here would create a
// dual-throttle that masks IdP misbehaviour without protecting any
// resource we couldn't already protect through the IdP's own quotas.
// Operators worried about a compromised IdP connector token should
// scope that risk by rotating the SCIM bearer in the IdP, not by
// extending the rate limiter into /scim/*.
var rateLimitedPathPrefixes = []string{
	"/access/",
	"/workspace/",
}

// workspaceBucket is a single token bucket. tokens is a float so
// fractional refills survive sub-second precision; the bucket
// silently clamps to [0, capacity] on each refill.
type workspaceBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	rps        float64
	lastRefill time.Time
	lastSeen   time.Time
}

// allow drains one token. Returns true when the request is admitted
// and false when the bucket is empty. The retryAfter return value is
// the wait, in seconds (rounded up), the client should observe before
// retrying — only meaningful when allow returns false.
func (b *workspaceBucket) allow(now time.Time) (bool, int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.lastRefill.IsZero() {
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.rps
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
		}
	}
	b.lastRefill = now
	b.lastSeen = now

	if b.tokens >= 1.0 {
		b.tokens--
		return true, 0
	}
	// Compute how long until the bucket holds a full token again,
	// rounded up to the next whole second so the value is always
	// >=1 (HTTP semantics — Retry-After: 0 is meaningless).
	missing := 1.0 - b.tokens
	wait := missing / b.rps
	secs := int(wait + 0.999999)
	if secs < 1 {
		secs = 1
	}
	return false, secs
}

// RateLimiter holds the per-workspace bucket map and configuration.
// Construct via NewRateLimiter so the default RPS and capacity are
// applied consistently. The zero value is not usable.
type RateLimiter struct {
	rps      float64
	capacity float64

	buckets sync.Map // map[string]*workspaceBucket

	// nowFunc is overridable so tests can drive time deterministically.
	nowFunc func() time.Time
}

// NewRateLimiter returns a limiter configured from environment.
// When ZTNA_API_RATE_LIMIT_RPS is set to a non-positive value or
// fails to parse the limiter falls back to defaultRateLimitRPS. The
// burst capacity is set to rps * defaultRateLimitBurstFactor.
func NewRateLimiter() *RateLimiter {
	return NewRateLimiterWithRPS(rateLimitRPSFromEnv())
}

// NewRateLimiterWithRPS is the test-friendly constructor that skips
// the env read.
func NewRateLimiterWithRPS(rps float64) *RateLimiter {
	if rps <= 0 {
		rps = float64(defaultRateLimitRPS)
	}
	return &RateLimiter{
		rps:      rps,
		capacity: rps * float64(defaultRateLimitBurstFactor),
		nowFunc:  time.Now,
	}
}

// rateLimitRPSFromEnv reads ZTNA_API_RATE_LIMIT_RPS and falls back
// to defaultRateLimitRPS on any parse failure or non-positive value.
func rateLimitRPSFromEnv() float64 {
	raw := os.Getenv("ZTNA_API_RATE_LIMIT_RPS")
	if raw == "" {
		return float64(defaultRateLimitRPS)
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return float64(defaultRateLimitRPS)
	}
	return v
}

// Allow drains one token for the given identifier. Used directly by
// tests; production callers go through the gin handler returned by
// Middleware().
func (l *RateLimiter) Allow(identifier string) (bool, int) {
	now := l.nowFunc()
	b := l.bucketFor(identifier, now)
	return b.allow(now)
}

// bucketFor returns the bucket for identifier, lazily creating one
// and evicting idle entries from the map. The eviction sweep is a
// trivial O(N) walk; under steady-state traffic N stays in the
// dozens (one bucket per active workspace) so the cost is
// negligible. Under attack N is bounded by the request rate × the
// eviction window, which is what we want — the map can't grow
// without bound regardless of how many distinct identifiers an
// adversary cycles through, because each entry is dropped within
// idleEvictionAfter of its last hit.
func (l *RateLimiter) bucketFor(identifier string, now time.Time) *workspaceBucket {
	if v, ok := l.buckets.Load(identifier); ok {
		return v.(*workspaceBucket)
	}
	nb := &workspaceBucket{
		tokens:     l.capacity, // start full so the first request always passes
		capacity:   l.capacity,
		rps:        l.rps,
		lastRefill: now,
		lastSeen:   now,
	}
	actual, _ := l.buckets.LoadOrStore(identifier, nb)
	// Opportunistic eviction sweep — only triggered on the cold path
	// where we just inserted a new bucket, so steady-state lookups
	// stay sync.Map-free of housekeeping work.
	if actual == nb {
		l.sweepIdle(now)
	}
	return actual.(*workspaceBucket)
}

// sweepIdle drops every bucket whose lastSeen is older than now -
// idleEvictionAfter. We snapshot the bucket under its own mutex so
// we don't race with a concurrent Allow.
func (l *RateLimiter) sweepIdle(now time.Time) {
	cutoff := now.Add(-idleEvictionAfter)
	l.buckets.Range(func(k, v any) bool {
		b := v.(*workspaceBucket)
		b.mu.Lock()
		seen := b.lastSeen
		b.mu.Unlock()
		if seen.Before(cutoff) {
			l.buckets.Delete(k)
		}
		return true
	})
}

// Middleware returns the gin.HandlerFunc that enforces the rate
// limit. Calls outside the /access/* and /workspace/* prefix are
// passed through untouched.
func (l *RateLimiter) Middleware() gin.HandlerFunc {
	if l == nil {
		// Defensive — a nil limiter is a no-op so callers can pass
		// the result of a constructor unchecked.
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		if !shouldRateLimit(c.Request.URL.Path) {
			c.Next()
			return
		}
		id := identifierFor(c)
		ok, retryAfter := l.Allow(id)
		if !ok {
			c.Writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "too many requests; retry later",
				"retry_after_seconds": retryAfter,
			})
			return
		}
		c.Next()
	}
}

// shouldRateLimit reports whether path is in the rate-limited
// prefix set. Paths outside the set bypass the limiter so kube
// probes (/health) and Prometheus scrapes (/metrics) don't share
// buckets with real callers.
func shouldRateLimit(path string) bool {
	for _, p := range rateLimitedPathPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// identifierFor returns the per-bucket identifier. The middleware
// looks at the workspace_id query parameter first (the cross-cutting
// convention every handler uses today, see access_request_handler.go,
// connector_catalogue_handler.go, ...). If absent we fall back to
// ClientIP so unauthenticated abuse still gets throttled — the
// limiter never lets an unidentified caller run unbounded.
//
// IMPORTANT: many POST endpoints (POST /access/requests,
// POST /access/connectors/batch-status, POST /access/reviews) carry
// `workspace_id` in the JSON body rather than as a query parameter
// or header. The middleware does NOT consume the request body to
// inspect that field — reading the body here would force every
// downstream handler to re-read it from an io.NopCloser tee, which
// is a meaningful overhead on every request. As a result, those POST
// flows bucket on ClientIP today. Behind a shared proxy this means
// multiple tenants can share one bucket. Clients that need per-
// workspace isolation on POST flows should send the workspace_id as
// a query parameter OR the X-Workspace-ID header in addition to the
// body; the handlers tolerate both shapes.
func identifierFor(c *gin.Context) string {
	if ws := c.Query("workspace_id"); ws != "" {
		return "ws:" + ws
	}
	if ws := c.GetHeader("X-Workspace-ID"); ws != "" {
		return "ws:" + ws
	}
	return "ip:" + c.ClientIP()
}
