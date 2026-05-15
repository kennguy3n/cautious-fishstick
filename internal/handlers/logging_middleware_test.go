package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// captureLogger swaps the package logger for a *bytes.Buffer-backed
// JSON logger and returns a cleanup func that restores the original.
func captureLogger(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := Logger()
	SetLogger(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf, func() { SetLogger(prev) }
}

func TestJSONLoggerMiddleware_OutputIsJSON(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	engine.GET("/ok", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if buf.Len() == 0 {
		t.Fatalf("expected at least one log line, got 0 bytes")
	}

	// Every emitted line MUST be parseable as JSON — that is the whole
	// point of the middleware.
	for i, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Fatalf("log line %d is not JSON: %v\n%q", i+1, err, line)
		}
		if parsed["msg"] != "http_request" {
			t.Fatalf("expected msg=http_request, got %v", parsed["msg"])
		}
		if parsed["method"] != http.MethodGet {
			t.Fatalf("expected method=GET, got %v", parsed["method"])
		}
		if parsed["path"] != "/ok" {
			t.Fatalf("expected path=/ok, got %v", parsed["path"])
		}
		if parsed["status"].(float64) != 200 {
			t.Fatalf("expected status=200, got %v", parsed["status"])
		}
	}
}

func TestJSONLoggerMiddleware_FailurePath5xxLogsAtError(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	engine.GET("/boom", func(c *gin.Context) {
		_ = c.Error(errors.New("boom"))
		c.JSON(500, gin.H{"error": "boom"})
	})

	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed); err != nil {
		t.Fatalf("not JSON: %v\n%q", err, buf.String())
	}
	if parsed["level"] != "ERROR" {
		t.Fatalf("expected level=ERROR for 5xx, got %v", parsed["level"])
	}
	if errs, ok := parsed["errors"].(string); !ok || !strings.Contains(errs, "boom") {
		t.Fatalf("expected errors field to surface boom, got %v", parsed["errors"])
	}
}

func TestJSONLoggerMiddleware_4xxLogsAtWarn(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	engine.GET("/nope", func(c *gin.Context) { c.JSON(404, gin.H{"error": "nope"}) })

	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if parsed["level"] != "WARN" {
		t.Fatalf("expected level=WARN for 4xx, got %v", parsed["level"])
	}
}

func TestSetLogger_NilSilencesOutput(t *testing.T) {
	prev := Logger()
	defer SetLogger(prev)

	SetLogger(nil)
	// Reaching here without panicking is half the test; also make
	// sure a subsequent Info call doesn't blow up.
	Logger().Info("ignored", slog.String("k", "v"))
}

// TestJSONLoggerMiddleware_DoesNotLogRequestBody asserts that even
// when a handler receives a request body containing what looks like
// a secret, the structured log line emitted by the middleware never
// echoes the body or any of its keys. This locks in the contract
// that the middleware logs ONLY the route shape + timing + status
// — never inbound payload data.
func TestJSONLoggerMiddleware_DoesNotLogRequestBody(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	engine.POST("/echo", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	body := `{"client_secret":"supersecret-shhh","password":"hunter2","api_token":"tok_abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	logged := buf.String()
	for _, leak := range []string{"supersecret-shhh", "hunter2", "tok_abc123", "client_secret", "password", "api_token"} {
		if strings.Contains(logged, leak) {
			t.Errorf("log line leaked %q from request body:\n%s", leak, logged)
		}
	}
}

// TestJSONLoggerMiddleware_DoesNotLogSensitiveHeaders asserts the
// middleware never echoes Authorization / Cookie / X-Api-Key
// headers. These would be the most damaging accidental log leaks
// per docs/PHASES.md cross-cutting criterion "No secret/token/PII
// logged".
func TestJSONLoggerMiddleware_DoesNotLogSensitiveHeaders(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	engine.GET("/ok", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("Authorization", "Bearer secret-bearer-token-xyz")
	req.Header.Set("Cookie", "session=secret-session-cookie")
	req.Header.Set("X-Api-Key", "secret-api-key-abc")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	logged := buf.String()
	for _, leak := range []string{"secret-bearer-token-xyz", "secret-session-cookie", "secret-api-key-abc"} {
		if strings.Contains(logged, leak) {
			t.Errorf("log line leaked sensitive header value %q:\n%s", leak, logged)
		}
	}
}

// TestJSONLoggerMiddleware_DurationIsMeasured asserts the
// "duration" field on the log line is at least the handler's
// observed sleep — i.e. the middleware actually times the handler
// rather than emitting a hard-coded zero. The lower bound is
// intentionally loose (90% of the sleep) to absorb scheduler
// variance on CI.
func TestJSONLoggerMiddleware_DurationIsMeasured(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	const sleep = 10 * time.Millisecond
	engine.GET("/slow", func(c *gin.Context) {
		time.Sleep(sleep)
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	durNS, ok := parsed["duration"].(float64)
	if !ok {
		t.Fatalf("duration field type = %T; want float64 (slog duration → ns int)", parsed["duration"])
	}
	if durNS < float64(sleep)*0.9 {
		t.Errorf("duration = %.0f ns; want >= %.0f ns (handler slept %v)", durNS, float64(sleep)*0.9, sleep)
	}
}

// TestJSONLoggerMiddleware_UnmatchedRouteBucketsAsUnmatched asserts
// scanner traffic hitting random URLs lands under path="unmatched"
// so the log aggregator's path cardinality is bounded. The raw URL
// is still recorded under raw_path for forensic spelunking.
func TestJSONLoggerMiddleware_UnmatchedRouteBucketsAsUnmatched(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(JSONLoggerMiddleware())
	// no routes — every request is unmatched

	req := httptest.NewRequest(http.MethodGet, "/random/scanner/path", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if parsed["path"] != "unmatched" {
		t.Errorf("path = %v; want %q (cardinality cap)", parsed["path"], "unmatched")
	}
	if parsed["raw_path"] != "/random/scanner/path" {
		t.Errorf("raw_path = %v; want %q (forensics)", parsed["raw_path"], "/random/scanner/path")
	}
}
