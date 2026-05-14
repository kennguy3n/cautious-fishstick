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
