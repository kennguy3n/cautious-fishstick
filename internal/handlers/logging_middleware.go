// Package handlers — structured JSON logging middleware.
//
// Gin's default Logger emits a single-line human format that is
// neither greppable nor structured. The middleware below uses the
// standard library's log/slog (Go 1.21+) JSON handler so every
// request line is parseable by the standard SOC/SIEM tooling
// (Datadog, ELK, Loki) without a custom parser.
//
// The handler reads from a package-level *slog.Logger so cmd binaries
// can override the destination (stdout in dev, a file or syslog
// dialer in prod) without changing the Gin router signature. See
// SetLogger / Logger below.
package handlers

import (
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	loggerMu sync.RWMutex
	logger   *slog.Logger
)

// init seeds a sensible default logger so handlers don't have to
// nil-check. cmd/ztna-api/main.go overrides this via SetLogger.
func init() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Logger returns the current package logger. Returned pointer is safe
// to retain — concurrent SetLogger swaps the underlying value.
func Logger() *slog.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return logger
}

// SetLogger replaces the package logger. Pass nil to reset to a
// silent logger (useful in tests). Safe for concurrent use.
func SetLogger(l *slog.Logger) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	if l == nil {
		l = slog.New(slog.NewJSONHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	logger = l
}

// discardWriter is io.Writer that drops everything. Used by
// SetLogger(nil) to silence the logger in unit tests without
// reaching into the slog internals.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// JSONLoggerMiddleware logs every HTTP request as a single JSON line
// with method, path (matched route), status, duration, client IP and
// the count of bytes written. Errors stashed on the context via
// c.Errors are flattened into a single comma-separated "errors"
// field so the log line stays one record per request.
func JSONLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		dur := time.Since(start)

		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		attrs := []any{
			slog.String("method", c.Request.Method),
			slog.String("path", path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("duration", dur),
			slog.String("client_ip", c.ClientIP()),
			slog.Int("bytes", c.Writer.Size()),
		}

		if len(c.Errors) > 0 {
			attrs = append(attrs, slog.String("errors", c.Errors.String()))
		}

		// Bucket the log level so 5xx surfaces in error dashboards
		// without flooding the log volume with INFO records.
		status := c.Writer.Status()
		switch {
		case status >= 500:
			Logger().Error("http_request", attrs...)
		case status >= 400:
			Logger().Warn("http_request", attrs...)
		default:
			Logger().Info("http_request", attrs...)
		}
	}
}
