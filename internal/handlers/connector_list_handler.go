package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ConnectorListReader is the read-only interface backing
// GET /access/connectors. Defined in the handlers package so unit
// tests can supply an in-memory fake; the production implementation
// is *access.AccessConnectorListService wired in cmd/ztna-api.
type ConnectorListReader interface {
	ListConnectors(ctx context.Context, q access.ListConnectorsQuery) ([]access.ConnectorSummary, error)
}

// ConnectorListHandler exposes GET /access/connectors. Returns the
// per-workspace catalogue of access connectors with last-sync
// timestamps and registry-derived capability flags so the operator
// admin UI can render the connector tile grid without re-running
// the connector contract test suite.
type ConnectorListHandler struct {
	reader ConnectorListReader
}

// NewConnectorListHandler returns a handler bound to reader. reader
// must not be nil.
func NewConnectorListHandler(reader ConnectorListReader) *ConnectorListHandler {
	return &ConnectorListHandler{reader: reader}
}

// Register wires the route onto r.
func (h *ConnectorListHandler) Register(r *gin.Engine) {
	r.GET("/access/connectors", h.ListConnectors)
}

// ListConnectors handles GET /access/connectors. The workspace_id
// query parameter is required so the endpoint never serves an
// unbounded list across tenants; status is optional.
func (h *ConnectorListHandler) ListConnectors(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id query parameter is required",
			Code:    "validation_failed",
			Message: "workspace_id query parameter is required",
		})
		return
	}
	q := access.ListConnectorsQuery{
		WorkspaceID: *wsID,
		Status:      GetPtrStringQuery(c, "status"),
	}
	out, err := h.reader.ListConnectors(c.Request.Context(), q)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	if out == nil {
		out = []access.ConnectorSummary{}
	}
	c.JSON(http.StatusOK, out)
}
