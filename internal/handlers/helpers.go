// Package handlers hosts the Gin HTTP handler layer for the ShieldNet
// 360 Access Platform. The package wires service-layer types
// (PolicyService, AccessRequestService, AccessReviewService, …) onto a
// single *gin.Engine returned by Router.
//
// Per docs/PHASES.md cross-cutting criteria, handlers MUST NOT touch
// gin.Context.Param / gin.Context.Query directly — every path
// parameter and every query parameter is read through the helpers
// defined here. Centralising the access pattern lets us add
// observability, sanitisation, and language-key plumbing in one
// place rather than scattering it across every endpoint.
package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// GetStringParam returns the path parameter named key from c, with
// surrounding whitespace stripped. Returns "" when the parameter is
// absent. Handlers MUST use this helper instead of c.Param so the
// access pattern is consistent across the codebase (per
// docs/PHASES.md cross-cutting criteria).
func GetStringParam(c *gin.Context, key string) string {
	if c == nil || key == "" {
		return ""
	}
	return strings.TrimSpace(c.Param(key))
}

// GetPtrStringQuery returns the query parameter named key from c,
// with surrounding whitespace stripped. The returned pointer is nil
// when the caller did not send the parameter at all, distinguishing
// "absent" from "empty" — which is the difference between a wildcard
// list query and a query for the empty string. A parameter sent as
// pure whitespace (e.g. "?id=%20") trims down to "" but is still
// returned as a non-nil pointer to "" so the caller can tell the
// difference between "not sent" and "sent blank".
//
// Handlers MUST use this helper instead of c.Query so the access
// pattern is consistent across the codebase (per docs/PHASES.md
// cross-cutting criteria).
func GetPtrStringQuery(c *gin.Context, key string) *string {
	if c == nil || key == "" {
		return nil
	}
	v, ok := c.GetQuery(key)
	if !ok {
		return nil
	}
	v = strings.TrimSpace(v)
	return &v
}
