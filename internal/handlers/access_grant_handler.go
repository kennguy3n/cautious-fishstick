package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// AccessGrantHandler bundles the read-only HTTP entry points for
// access grants. Two routes live here:
//
//   - GET /access/grants (list active grants by user / connector)
//   - GET /access/grants/:id/entitlements (live entitlement set
//     for the grant's user on the grant's connector)
//
// Admin-side mutations go through the review / provisioning flows.
type AccessGrantHandler struct {
	grantReader        AccessGrantReader
	entitlementsReader GrantEntitlementsReader
}

// NewAccessGrantHandler returns a handler bound to the supplied
// reader. reader must not be nil.
func NewAccessGrantHandler(reader AccessGrantReader) *AccessGrantHandler {
	return &AccessGrantHandler{grantReader: reader}
}

// WithEntitlements wires an entitlements reader onto h so the
// /entitlements route is registered. Returns h for fluent chaining
// from the router constructor. When the production wiring omits the
// entitlements reader (e.g. credential manager not configured), the
// route is not registered and clients get 404 — the same shape as
// any other unimplemented capability.
func (h *AccessGrantHandler) WithEntitlements(reader GrantEntitlementsReader) *AccessGrantHandler {
	if h != nil {
		h.entitlementsReader = reader
	}
	return h
}

// Register wires the handler's routes onto r.
func (h *AccessGrantHandler) Register(r *gin.Engine) {
	r.GET("/access/grants", h.ListGrants)
	if h != nil && h.entitlementsReader != nil {
		r.GET("/access/grants/:id/entitlements", h.ListEntitlements)
	}
}

// ListEntitlements handles GET /access/grants/:id/entitlements. It
// resolves the connector + user from the grant row, then asks the
// connector for the live entitlement set so the operator UI can
// render "what does this user actually have right now?" without
// chaining through the connector worker.
//
// Returns 400 when :id is missing, 404 when the grant does not
// exist or the connector is not registered, 502 when the connector
// call fails (network error against the upstream provider), 500
// otherwise.
func (h *AccessGrantHandler) ListEntitlements(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	if h.entitlementsReader == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, errorEnvelope{
			Error:   "app permission lookup not configured",
			Code:    "unavailable",
			Message: "app permission lookup not configured on this deployment",
		})
		return
	}
	out, err := h.entitlementsReader.ListGrantEntitlements(c.Request.Context(), id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	if out == nil {
		out = []access.Entitlement{}
	}
	c.JSON(http.StatusOK, gin.H{"grant_id": id, "entitlements": out})
}

// GrantEntitlementsReader is the read-only interface backing
// GET /access/grants/:id/entitlements. The production implementation
// looks up the grant row, fetches the connector config / secrets,
// resolves the registered connector, and calls ListEntitlements.
// Tests substitute an in-memory fake.
type GrantEntitlementsReader interface {
	ListGrantEntitlements(ctx context.Context, grantID string) ([]access.Entitlement, error)
}

// ListGrants handles GET /access/grants. user_id and connector_id
// are read from the query string; at least one must be supplied so
// the handler never surfaces an unbounded list (per
// docs/overview.md §11). Returns 200 with the active-grant array.
func (h *AccessGrantHandler) ListGrants(c *gin.Context) {
	userID := GetPtrStringQuery(c, "user_id")
	connectorID := GetPtrStringQuery(c, "connector_id")
	if userID == nil && connectorID == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "user_id or connector_id query parameter is required",
			Code:    "validation_failed",
			Message: "user_id or connector_id query parameter is required",
		})
		return
	}
	out, err := h.grantReader.ListGrants(c.Request.Context(), ListGrantsQuery{
		UserID:      userID,
		ConnectorID: connectorID,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// AccessGrantReaderAdapter adapts an *access.AccessGrantQueryService
// to the AccessGrantReader interface so the router wiring can pass
// the production service without an extra wrapper at the call site.
//
// The adapter is intentionally trivial; it lives here (not in the
// service package) so the service does not depend on the handler-
// owned interface, preserving the dependency direction in
// docs/architecture.md §1.
type AccessGrantReaderAdapter struct {
	Inner *access.AccessGrantQueryService
}

// ListGrants implements AccessGrantReader by forwarding to the
// underlying query service.
func (a *AccessGrantReaderAdapter) ListGrants(ctx context.Context, q ListGrantsQuery) ([]models.AccessGrant, error) {
	if a == nil || a.Inner == nil {
		return nil, access.ErrValidation
	}
	return a.Inner.ListActiveGrants(ctx, access.GrantQuery{
		UserID:      q.UserID,
		ConnectorID: q.ConnectorID,
	})
}
