package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// AccessGrantHandler bundles the read-only HTTP entry points for
// access grants. Only one route lives here today
// (GET /access/grants); admin-side mutations go through the
// review / provisioning flows.
type AccessGrantHandler struct {
	grantReader AccessGrantReader
}

// NewAccessGrantHandler returns a handler bound to the supplied
// reader. reader must not be nil.
func NewAccessGrantHandler(reader AccessGrantReader) *AccessGrantHandler {
	return &AccessGrantHandler{grantReader: reader}
}

// Register wires the handler's routes onto r.
func (h *AccessGrantHandler) Register(r *gin.Engine) {
	r.GET("/access/grants", h.ListGrants)
}

// ListGrants handles GET /access/grants. user_id and connector_id
// are read from the query string; at least one must be supplied so
// the handler never surfaces an unbounded list (per
// docs/PROPOSAL.md §11). Returns 200 with the active-grant array.
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
// docs/ARCHITECTURE.md §1.
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
