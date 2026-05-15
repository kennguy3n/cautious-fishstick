// Package handlers — request-ID middleware.
//
// Every inbound HTTP request gets a stable identifier so log lines,
// trace entries, and structured error envelopes can be stitched
// together across the platform. The middleware honours an inbound
// `X-Request-ID` header when the client supplies one (so an edge
// proxy / mobile SDK can thread its own correlation ID through to
// the API), and otherwise mints a fresh UUIDv4.
//
// The ID is exposed in three places:
//
//   - On the gin.Context under requestIDContextKey, retrievable by
//     handlers via GetRequestID(c).
//   - On the response as the `X-Request-ID` header so clients can
//     echo the ID back when filing a support ticket.
//   - On the JSONLoggerMiddleware's `http_request` log line as the
//     `request_id` field, so log search by ID works out of the box.
//
// Inbound header values are sanitised: anything outside the
// conventional UUID / hex / dash / underscore character set is
// rejected and replaced with a freshly minted UUID. Length is capped
// at 128 characters so a hostile client cannot inflate log line size.
package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// requestIDHeader is the standard header name the middleware honours
// on inbound requests and emits on responses.
const requestIDHeader = "X-Request-ID"

// requestIDContextKey is the Gin context key the middleware writes
// to and GetRequestID reads from. Handlers should prefer
// GetRequestID over c.GetString so this string lives in exactly one
// place.
const requestIDContextKey = "request_id"

// maxInboundRequestIDLen caps the length of an inbound header value
// before it is rejected. 128 is wide enough for a UUID + prefix
// while small enough that an attacker can't inflate log lines at
// our expense.
const maxInboundRequestIDLen = 128

// RequestIDMiddleware returns a Gin handler that ensures every
// request has a stable identifier on context and on the response.
//
// Behaviour:
//   - If the request carries an `X-Request-ID` header AND the value
//     passes isAcceptableInboundRequestID, that value is used.
//   - Otherwise a fresh UUIDv4 is generated.
//   - The chosen ID is stored on the gin.Context under
//     requestIDContextKey and echoed on the response.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.GetHeader(requestIDHeader))
		if !isAcceptableInboundRequestID(id) {
			id = uuid.NewString()
		}
		c.Set(requestIDContextKey, id)
		c.Writer.Header().Set(requestIDHeader, id)
		c.Next()
	}
}

// GetRequestID returns the request ID stashed on the context by
// RequestIDMiddleware, or the empty string if no middleware ran.
// Safe to call with a nil context.
func GetRequestID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if v, ok := c.Get(requestIDContextKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// isAcceptableInboundRequestID reports whether the caller-supplied
// header value is safe to use as-is. We accept ASCII alphanumerics,
// dashes, and underscores, mirroring the conventional UUID / nanoid
// character set. Anything else (including the empty string) returns
// false and the middleware mints a fresh UUID.
func isAcceptableInboundRequestID(v string) bool {
	if v == "" || len(v) > maxInboundRequestIDLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		switch {
		case b >= 'a' && b <= 'z':
		case b >= 'A' && b <= 'Z':
		case b >= '0' && b <= '9':
		case b == '-', b == '_':
		default:
			return false
		}
	}
	return true
}
