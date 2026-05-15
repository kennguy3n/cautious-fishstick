package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newRequestIDTestEngine builds a minimal Gin engine that only mounts
// the middleware under test plus a probe handler that echoes the
// in-context request ID into the response body. Other middleware are
// deliberately omitted so tests can assert RequestIDMiddleware's
// behaviour in isolation.
func newRequestIDTestEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/probe", func(c *gin.Context) {
		c.String(http.StatusOK, GetRequestID(c))
	})
	return r
}

// TestRequestIDMiddleware_GeneratesUUID_WhenHeaderAbsent asserts the
// middleware mints a UUID when no inbound header is supplied and
// echoes the same value into the response header.
func TestRequestIDMiddleware_GeneratesUUID_WhenHeaderAbsent(t *testing.T) {
	r := newRequestIDTestEngine(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	got := w.Header().Get(requestIDHeader)
	body := strings.TrimSpace(w.Body.String())
	if got == "" {
		t.Fatalf("X-Request-ID header missing")
	}
	if body != got {
		t.Errorf("body request ID %q != header %q", body, got)
	}
	// UUIDv4 is 36 chars (32 hex + 4 dashes); we don't pin the format
	// but accept anything in the acceptable charset.
	if !isAcceptableInboundRequestID(got) {
		t.Errorf("generated ID %q failed isAcceptableInboundRequestID", got)
	}
}

// TestRequestIDMiddleware_HonoursInboundHeader asserts a well-formed
// inbound X-Request-ID is preserved on context and on the response.
func TestRequestIDMiddleware_HonoursInboundHeader(t *testing.T) {
	r := newRequestIDTestEngine(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(requestIDHeader, "edge-proxy-abc-123")
	r.ServeHTTP(w, req)

	if got := w.Header().Get(requestIDHeader); got != "edge-proxy-abc-123" {
		t.Errorf("header X-Request-ID = %q; want %q", got, "edge-proxy-abc-123")
	}
	if body := strings.TrimSpace(w.Body.String()); body != "edge-proxy-abc-123" {
		t.Errorf("body request ID = %q; want %q", body, "edge-proxy-abc-123")
	}
}

// TestRequestIDMiddleware_RejectsHostileHeader asserts the middleware
// drops a header containing non-allowlisted bytes and mints a fresh ID.
func TestRequestIDMiddleware_RejectsHostileHeader(t *testing.T) {
	r := newRequestIDTestEngine(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	// Embedded newline + control bytes: classic log-injection probe.
	req.Header.Set(requestIDHeader, "bad-id\nlog-poisoning-attempt")
	r.ServeHTTP(w, req)

	got := w.Header().Get(requestIDHeader)
	if got == "" {
		t.Fatalf("X-Request-ID empty after hostile header")
	}
	if strings.Contains(got, "\n") || strings.Contains(got, "log-poisoning") {
		t.Errorf("middleware echoed unsafe inbound header: %q", got)
	}
}

// TestRequestIDMiddleware_RejectsOverlongHeader asserts the middleware
// drops inbound IDs longer than maxInboundRequestIDLen and mints a
// fresh one (preventing log-line inflation).
func TestRequestIDMiddleware_RejectsOverlongHeader(t *testing.T) {
	r := newRequestIDTestEngine(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(requestIDHeader, strings.Repeat("a", maxInboundRequestIDLen+1))
	r.ServeHTTP(w, req)

	got := w.Header().Get(requestIDHeader)
	if len(got) > maxInboundRequestIDLen {
		t.Errorf("middleware echoed overlong inbound header: len=%d", len(got))
	}
}

// TestGetRequestID_NilContext is the defensive guard against a
// future caller passing nil — historically a panic source on Gin
// helpers.
func TestGetRequestID_NilContext(t *testing.T) {
	if got := GetRequestID(nil); got != "" {
		t.Errorf("GetRequestID(nil) = %q; want \"\"", got)
	}
}

// TestIsAcceptableInboundRequestID_TableDriven covers the validator
// itself so the policy is asserted once instead of being indirectly
// exercised by the middleware tests.
func TestIsAcceptableInboundRequestID_TableDriven(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"00000000-0000-0000-0000-000000000000", true},
		{"req_abcDEF123", true},
		{"req-abc-123", true},
		{"req with space", false},
		{"req\nnewline", false},
		{"req/slash", false},
		{strings.Repeat("a", maxInboundRequestIDLen), true},
		{strings.Repeat("a", maxInboundRequestIDLen+1), false},
	}
	for _, tc := range cases {
		got := isAcceptableInboundRequestID(tc.in)
		if got != tc.want {
			t.Errorf("isAcceptableInboundRequestID(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}
