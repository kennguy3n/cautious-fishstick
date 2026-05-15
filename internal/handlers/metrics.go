// Package handlers — Prometheus /metrics endpoint and in-process
// metrics registry.
//
// The registry is intentionally tiny: it exposes the four families
// docs/architecture.md §2 calls out (HTTP request count/latency,
// connector sync duration, AI agent call latency, worker queue
// depth) and emits them in the Prometheus text exposition format
// (see https://prometheus.io/docs/instrumenting/exposition_formats/).
//
// We deliberately do not pull in github.com/prometheus/client_golang
// — the surface we need is small and a third-party dep adds a
// non-trivial transitive footprint to a service that already runs
// without one. Tests pin the wire format so a future swap to the
// reference library stays drop-in.
package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// defaultBuckets is the Prometheus default histogram bucket layout
// (seconds), copied from the reference implementation so dashboards
// authored against the canonical buckets work without adjustment.
var defaultBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// MetricsRegistry is a thread-safe, in-process collector for the
// four metric families ztna-api exports. Construct one via
// NewMetricsRegistry; the zero value is not usable.
type MetricsRegistry struct {
	mu sync.RWMutex

	// HTTP server-side metrics keyed by labelset (method,path,status
	// for counters; method,path for histograms).
	httpCount   map[string]uint64
	httpLatency map[string]*histogram

	// Connector sync duration histogram keyed by provider,kind,status.
	connectorSync map[string]*histogram

	// AI agent call latency histogram keyed by skill,status.
	aiAgentLatency map[string]*histogram

	// Worker queue depth gauges keyed by queue name.
	queueDepth map[string]float64
}

// NewMetricsRegistry constructs an empty registry.
func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		httpCount:      map[string]uint64{},
		httpLatency:    map[string]*histogram{},
		connectorSync:  map[string]*histogram{},
		aiAgentLatency: map[string]*histogram{},
		queueDepth:     map[string]float64{},
	}
}

// histogram is a fixed-bucket cumulative counter. Buckets are stored
// as a parallel array of upper-bounds + cumulative counts.
type histogram struct {
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

func newHistogram(buckets []float64) *histogram {
	bs := make([]float64, len(buckets))
	copy(bs, buckets)
	return &histogram{
		buckets: bs,
		counts:  make([]uint64, len(bs)),
	}
}

func (h *histogram) observe(v float64) {
	h.sum += v
	h.count++
	for i, ub := range h.buckets {
		if v <= ub {
			h.counts[i]++
		}
	}
}

// labelKey serializes label name/value pairs into a stable map key.
// The order of (name, value) pairs is preserved because callers pass
// labels in a fixed order per metric family.
//
// The serialization uses `|` as the pair separator and `=` as the
// name/value separator. Both characters are escaped in the value to
// keep the encoding round-trippable through splitLabels — without
// the escape, a value containing `|` (e.g. an arbitrary connector
// provider string) would silently collide with another labelset
// and corrupt the Prometheus output.
func labelKey(pairs ...string) string {
	if len(pairs)%2 != 0 {
		panic("labelKey: odd number of arguments")
	}
	var b strings.Builder
	for i := 0; i < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(pairs[i])
		b.WriteByte('=')
		b.WriteString(escapeLabelKeyValue(pairs[i+1]))
	}
	return b.String()
}

// labelKeyEscaper escapes `\`, `|`, and `=` in label values so the
// `|`-separated, `=`-pair-delimited encoding produced by labelKey
// stays unambiguous regardless of the value contents.
var labelKeyEscaper = strings.NewReplacer(
	`\`, `\\`,
	`|`, `\|`,
	`=`, `\=`,
)

func escapeLabelKeyValue(v string) string {
	return labelKeyEscaper.Replace(v)
}

// unescapeLabelKeyValue reverses escapeLabelKeyValue. Used by
// splitLabels to recover the original label value from a labelKey
// segment.
func unescapeLabelKeyValue(v string) string {
	if !strings.ContainsRune(v, '\\') {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			b.WriteByte(v[i+1])
			i++
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// ObserveHTTPRequest records a single Gin request. Path should be
// the route template ("/access/requests/:id"), not the raw URL, so
// cardinality stays bounded.
func (r *MetricsRegistry) ObserveHTTPRequest(method, path string, status int, duration time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ck := labelKey("method", method, "path", path, "status", fmt.Sprintf("%d", status))
	r.httpCount[ck]++
	hk := labelKey("method", method, "path", path)
	h, ok := r.httpLatency[hk]
	if !ok {
		h = newHistogram(defaultBuckets)
		r.httpLatency[hk] = h
	}
	h.observe(duration.Seconds())
}

// ObserveConnectorSync records the duration of a connector sync run.
// Kind is the sync kind ("identities", "teams", ...); status is
// "success" or "error".
func (r *MetricsRegistry) ObserveConnectorSync(provider, kind, status string, duration time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := labelKey("provider", provider, "kind", kind, "status", status)
	h, ok := r.connectorSync[k]
	if !ok {
		h = newHistogram(defaultBuckets)
		r.connectorSync[k] = h
	}
	h.observe(duration.Seconds())
}

// ObserveAIAgentCall records the duration of an AI agent invocation.
// Status is "success" or "error".
func (r *MetricsRegistry) ObserveAIAgentCall(skill, status string, duration time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := labelKey("skill", skill, "status", status)
	h, ok := r.aiAgentLatency[k]
	if !ok {
		h = newHistogram(defaultBuckets)
		r.aiAgentLatency[k] = h
	}
	h.observe(duration.Seconds())
}

// SetQueueDepth records the current depth of a named worker queue.
// Pass the absolute depth, not a delta.
func (r *MetricsRegistry) SetQueueDepth(queue string, depth int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queueDepth[queue] = float64(depth)
}

// Render emits the registry contents in Prometheus text exposition
// format (Content-Type: text/plain; version=0.0.4). Output is
// deterministic across calls: label sets are sorted lexically by
// their composite key so dashboards diff cleanly across reloads.
func (r *MetricsRegistry) Render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var b strings.Builder

	// ztna_api_http_requests_total
	if len(r.httpCount) > 0 {
		b.WriteString("# HELP ztna_api_http_requests_total Total HTTP requests served by the access API.\n")
		b.WriteString("# TYPE ztna_api_http_requests_total counter\n")
		for _, k := range sortedKeys(r.httpCount) {
			labels := renderLabels(k)
			fmt.Fprintf(&b, "ztna_api_http_requests_total%s %d\n", labels, r.httpCount[k])
		}
	}

	// ztna_api_http_request_duration_seconds
	if len(r.httpLatency) > 0 {
		b.WriteString("# HELP ztna_api_http_request_duration_seconds HTTP request duration in seconds.\n")
		b.WriteString("# TYPE ztna_api_http_request_duration_seconds histogram\n")
		for _, k := range sortedHistKeys(r.httpLatency) {
			writeHistogram(&b, "ztna_api_http_request_duration_seconds", k, r.httpLatency[k])
		}
	}

	// ztna_api_connector_sync_duration_seconds
	if len(r.connectorSync) > 0 {
		b.WriteString("# HELP ztna_api_connector_sync_duration_seconds Access connector sync duration in seconds.\n")
		b.WriteString("# TYPE ztna_api_connector_sync_duration_seconds histogram\n")
		for _, k := range sortedHistKeys(r.connectorSync) {
			writeHistogram(&b, "ztna_api_connector_sync_duration_seconds", k, r.connectorSync[k])
		}
	}

	// ztna_api_ai_agent_call_duration_seconds
	if len(r.aiAgentLatency) > 0 {
		b.WriteString("# HELP ztna_api_ai_agent_call_duration_seconds AI agent call duration in seconds.\n")
		b.WriteString("# TYPE ztna_api_ai_agent_call_duration_seconds histogram\n")
		for _, k := range sortedHistKeys(r.aiAgentLatency) {
			writeHistogram(&b, "ztna_api_ai_agent_call_duration_seconds", k, r.aiAgentLatency[k])
		}
	}

	// ztna_api_worker_queue_depth
	if len(r.queueDepth) > 0 {
		b.WriteString("# HELP ztna_api_worker_queue_depth Current depth of a named worker queue.\n")
		b.WriteString("# TYPE ztna_api_worker_queue_depth gauge\n")
		for _, k := range sortedFloatKeys(r.queueDepth) {
			labels := renderLabels(labelKey("queue", k))
			fmt.Fprintf(&b, "ztna_api_worker_queue_depth%s %g\n", labels, r.queueDepth[k])
		}
	}

	return b.String()
}

func writeHistogram(b *strings.Builder, name, k string, h *histogram) {
	labels := splitLabels(k)
	for i, ub := range h.buckets {
		fmt.Fprintf(b, "%s_bucket%s %d\n", name, renderLabelsWithExtra(labels, "le", formatBucket(ub)), h.counts[i])
	}
	fmt.Fprintf(b, "%s_bucket%s %d\n", name, renderLabelsWithExtra(labels, "le", "+Inf"), h.count)
	fmt.Fprintf(b, "%s_sum%s %g\n", name, renderLabels(k), h.sum)
	fmt.Fprintf(b, "%s_count%s %d\n", name, renderLabels(k), h.count)
}

// formatBucket renders a bucket upper bound the way the Prometheus
// client_golang reference does — short decimal, no trailing zeros.
func formatBucket(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	return s
}

// renderLabels turns a "k1=v1|k2=v2" composite key into
// `{k1="v1",k2="v2"}`. Returns "" when k is empty.
func renderLabels(k string) string {
	if k == "" {
		return ""
	}
	pairs := splitLabels(k)
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pairs[i])
		b.WriteString("=\"")
		b.WriteString(escapeLabelValue(pairs[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func renderLabelsWithExtra(base []string, extraName, extraValue string) string {
	pairs := make([]string, 0, len(base)+2)
	pairs = append(pairs, base...)
	pairs = append(pairs, extraName, extraValue)
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pairs[i])
		b.WriteString("=\"")
		b.WriteString(escapeLabelValue(pairs[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func splitLabels(k string) []string {
	if k == "" {
		return nil
	}
	parts := splitLabelKey(k)
	pairs := make([]string, 0, len(parts)*2)
	for _, p := range parts {
		eq := indexUnescaped(p, '=')
		if eq < 0 {
			continue
		}
		pairs = append(pairs, p[:eq], unescapeLabelKeyValue(p[eq+1:]))
	}
	return pairs
}

// splitLabelKey splits a labelKey string on un-escaped `|` so an
// escaped `\|` inside a value does not start a new pair.
func splitLabelKey(k string) []string {
	var out []string
	start := 0
	for i := 0; i < len(k); i++ {
		if k[i] == '\\' && i+1 < len(k) {
			i++
			continue
		}
		if k[i] == '|' {
			out = append(out, k[start:i])
			start = i + 1
		}
	}
	out = append(out, k[start:])
	return out
}

// indexUnescaped returns the index of the first un-escaped byte b
// in s, or -1 if not found.
func indexUnescaped(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if s[i] == b {
			return i
		}
	}
	return -1
}

// labelValueEscaper escapes characters that the Prometheus text
// exposition format requires escaping inside a double-quoted label
// value (backslash, double-quote, newline). Hoisted to package level
// because escapeLabelValue is called once per label per bucket per
// histogram per scrape — re-allocating the Replacer on every call
// would dominate the /metrics CPU profile on a busy cluster.
var labelValueEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	"\n", `\n`,
)

func escapeLabelValue(v string) string {
	return labelValueEscaper.Replace(v)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedHistKeys(m map[string]*histogram) []string {
	return sortedKeys(m)
}

func sortedFloatKeys(m map[string]float64) []string {
	return sortedKeys(m)
}

// MetricsHandler returns a Gin handler that renders the registry on
// every GET /metrics request. Returns a small static body when the
// registry is nil so dev binaries without metrics wired still serve
// the route.
func MetricsHandler(registry *MetricsRegistry) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if registry == nil {
			c.String(http.StatusOK, "# HELP ztna_api_up Tag indicating the metrics endpoint is reachable.\n# TYPE ztna_api_up gauge\nztna_api_up 1\n")
			return
		}
		c.String(http.StatusOK, registry.Render())
	}
}

// metricsSelfInstrumentationSkip lists the paths the middleware
// must not record into the registry. /metrics is the Prometheus
// scrape itself (15-30s intervals) and /health is the kube-probe
// stream — both would dominate the request count and skew the
// p50/p95 latency histograms with their own overhead. Matching is
// exact on c.FullPath so a route accidentally registered under
// /metrics/* is still observed.
var metricsSelfInstrumentationSkip = map[string]struct{}{
	"/metrics": {},
	"/health":  {},
}

// MetricsMiddleware returns a Gin middleware that observes every
// request's method + matched route + status into the registry. The
// matched route (c.FullPath) is preferred over the raw URL so
// /access/requests/abc and /access/requests/def collapse into the
// same time series.
func MetricsMiddleware(registry *MetricsRegistry) gin.HandlerFunc {
	return func(c *gin.Context) {
		if registry == nil {
			c.Next()
			return
		}
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" {
			path = "unmatched"
		}
		if _, skip := metricsSelfInstrumentationSkip[path]; skip {
			return
		}
		registry.ObserveHTTPRequest(c.Request.Method, path, c.Writer.Status(), time.Since(start))
	}
}
