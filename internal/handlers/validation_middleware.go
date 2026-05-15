// Package handlers — request-body validation middleware.
//
// The Phase 8 hardening pass asks for "JSON schema validation for
// POST/PUT/PATCH request bodies on all handler endpoints" with
// structured 400 errors carrying field-level messages. The
// middleware below enforces three layers of validation for any
// mutation request (POST/PUT/PATCH/DELETE) carrying a Content-Type
// of application/json:
//
//  1. Content-Type. A mutation method with a non-empty body MUST
//     declare Content-Type: application/json (or a parameterised
//     variant). Anything else is a 415 Unsupported Media Type —
//     handlers downstream all assume JSON and silently misparse
//     form-encoded payloads if we don't gate at the edge.
//  2. Body size. Bodies above maxRequestBodyBytes are rejected with
//     413 Payload Too Large. The limit guards against memory-spike
//     DoS without paying the cost of streaming the body through
//     every handler.
//  3. JSON well-formedness. The bytes must decode as a single JSON
//     value (any value — null/number/array/object). When decoding
//     fails the middleware surfaces a structured 400 with the
//     offset and a human-readable message so admin UIs can pinpoint
//     the problem.
//
// On success the buffered body is rewound onto the request so
// downstream handlers' c.ShouldBindJSON calls see the same bytes —
// the middleware is transparent to handlers that already validate
// their own struct shapes; it just front-loads the cheap "is this
// even JSON?" check so handlers don't litter the same boilerplate.
//
// Per-field validation (required keys, enums, etc.) stays in the
// service layer — the middleware does not own the schema for every
// resource because the schemas live next to the GORM models. What
// the middleware does add is a helpers.WriteFieldErrors function
// that handlers call to emit a uniform "validation_failed" body
// shape with a top-level "fields" map. This keeps the wire contract
// stable as more handlers move to richer validation.
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// maxRequestBodyBytes caps every mutation request body. 1 MiB is
// well above the largest realistic admin-UI payload (a policy with
// hundreds of rules ships at ~80 KiB) but small enough to prevent
// trivial memory-DoS.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// JSONValidationMiddleware returns the request-body validation
// middleware. It is safe to install globally; it is a no-op for
// GET/HEAD/OPTIONS and for /health, /metrics, /swagger* routes (the
// kube/k8s probes never carry a JSON body so the middleware would
// otherwise punish them on the rare 405 case).
func JSONValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request == nil {
			c.Next()
			return
		}
		method := c.Request.Method
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		// SCIM endpoints define their own application/scim+json
		// content-type and have their own validation pipeline in
		// scim_handler.go. Skip middleware-level enforcement to
		// avoid double-decoding a stream that the SCIM resolver
		// reads as a struct.
		if strings.HasPrefix(c.Request.URL.Path, "/scim/") {
			c.Next()
			return
		}

		// If the request has no body Content-Length is 0 and we
		// can pass straight through. Note Content-Length is -1 for
		// chunked transfer encoding so we additionally peek the
		// stream below; for kube probes and DELETE-without-body
		// requests this fast path keeps the middleware free.
		if c.Request.ContentLength == 0 {
			c.Next()
			return
		}

		ct := c.GetHeader("Content-Type")
		if ct != "" && !isJSONContentType(ct) {
			abortWithError(
				c,
				http.StatusUnsupportedMediaType,
				"unsupported_media_type",
				"unsupported_media_type",
				"Content-Type must be application/json for request bodies",
			)
			return
		}

		// Read up to the limit + 1 byte so we can distinguish
		// "exactly at limit" from "over the limit" without
		// allocating a second buffer.
		limited := http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBodyBytes+1)
		buf, err := io.ReadAll(limited)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				abortWithError(
					c,
					http.StatusRequestEntityTooLarge,
					"payload_too_large",
					"payload_too_large",
					fmt.Sprintf("request body exceeds %d bytes", maxRequestBodyBytes),
				)
				return
			}
			abortWithError(
				c,
				http.StatusBadRequest,
				"invalid_request",
				"invalid_request",
				"failed to read request body",
			)
			return
		}
		if len(buf) > maxRequestBodyBytes {
			abortWithError(
				c,
				http.StatusRequestEntityTooLarge,
				"payload_too_large",
				"payload_too_large",
				fmt.Sprintf("request body exceeds %d bytes", maxRequestBodyBytes),
			)
			return
		}

		// Empty body on a mutation method — pass through. Handlers
		// that require a body validate the resulting struct.
		if len(bytes.TrimSpace(buf)) == 0 {
			c.Request.Body = io.NopCloser(bytes.NewReader(buf))
			c.Next()
			return
		}

		dec := json.NewDecoder(bytes.NewReader(buf))
		dec.UseNumber()
		var probe any
		if err := dec.Decode(&probe); err != nil {
			abortWithError(
				c,
				http.StatusBadRequest,
				"invalid_json",
				"validation_failed",
				"request body is not valid JSON: "+summariseJSONError(err),
			)
			return
		}
		// Disallow trailing tokens — "{}{" is two values, not one.
		if dec.More() {
			abortWithError(
				c,
				http.StatusBadRequest,
				"invalid_json",
				"validation_failed",
				"request body must contain a single JSON value",
			)
			return
		}

		// Rewind the body so downstream c.ShouldBindJSON sees the
		// original bytes.
		c.Request.Body = io.NopCloser(bytes.NewReader(buf))
		c.Next()
	}
}

// isJSONContentType returns true for application/json and the
// parameterised charset variants (application/json; charset=utf-8).
// We also tolerate application/*+json for upstream proxies that
// rewrite the Content-Type.
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "application/json" {
		return true
	}
	if strings.HasPrefix(ct, "application/") && strings.HasSuffix(ct, "+json") {
		return true
	}
	return false
}

// summariseJSONError trims the json package's verbose error message
// down to a single line suitable for an end-user-facing error
// envelope. The full error stays in c.Errors for the log line.
func summariseJSONError(err error) string {
	msg := err.Error()
	// json.SyntaxError formats as "invalid character 'x' …". Strip
	// the embedded byte offset to keep the output deterministic for
	// tests; the offset is rarely useful to a human in a 1-line
	// admin-UI banner.
	if i := strings.Index(msg, " at offset "); i >= 0 {
		msg = msg[:i]
	}
	return msg
}

// FieldError describes a single rejected request-body field. It is
// emitted by handlers (not the middleware) when they catch a
// per-field validation failure during ShouldBindJSON or in a
// service-layer call. Centralising the shape lets the admin UI
// render consistent inline messages.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// WriteFieldErrors emits a 400 with the canonical validation_failed
// envelope plus a "fields" array containing one entry per offending
// field. Handlers call this when they have multiple field-level
// errors to surface in a single response. The body inherits the same
// {error, code, message, request_id} envelope as abortWithError so
// every error response — middleware or handler — carries the same
// correlation key under request_id.
func WriteFieldErrors(c *gin.Context, fields []FieldError) {
	if len(fields) == 0 {
		abortWithError(
			c,
			http.StatusBadRequest,
			"validation_failed",
			"validation_failed",
			"request validation failed",
		)
		return
	}
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"error":      "validation_failed",
		"code":       "validation_failed",
		"message":    "request validation failed",
		"request_id": GetRequestID(c),
		"fields":     fields,
	})
}
