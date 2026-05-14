package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ConnectorCatalogueReader is the read-only interface backing
// GET /access/connectors/catalogue. Defined in the handlers package
// so tests can supply an in-memory fake; the production wiring is
// *access.AccessConnectorCatalogueService.
type ConnectorCatalogueReader interface {
	ListCatalogue(ctx context.Context, q access.ConnectorCatalogueQuery) ([]access.ConnectorCatalogueEntry, error)
}

// ConnectorCatalogueHandler exposes GET /access/connectors/catalogue.
// The catalogue endpoint returns one row per provider currently
// registered in the binary, enriched with the workspace's connection
// state. This is the data source for the Admin UI's "available
// integrations" tile grid.
type ConnectorCatalogueHandler struct {
	reader ConnectorCatalogueReader
}

// NewConnectorCatalogueHandler returns a handler bound to reader.
// reader must not be nil.
func NewConnectorCatalogueHandler(reader ConnectorCatalogueReader) *ConnectorCatalogueHandler {
	return &ConnectorCatalogueHandler{reader: reader}
}

// Register wires the route onto r. The path uses /catalogue (singular)
// rather than /catalog to match the SN360 docs vocabulary.
func (h *ConnectorCatalogueHandler) Register(r *gin.Engine) {
	r.GET("/access/connectors/catalogue", h.ListCatalogue)
}

// ListCatalogue handles GET /access/connectors/catalogue. The
// workspace_id query parameter is required — the catalogue is per-
// workspace because the Connected / ConnectorID / Status enrichment
// is workspace-scoped, and an unbounded cross-tenant list would
// leak which providers other workspaces use.
func (h *ConnectorCatalogueHandler) ListCatalogue(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id query parameter is required",
			Code:    "validation_failed",
			Message: "workspace_id query parameter is required",
		})
		return
	}
	out, err := h.reader.ListCatalogue(c.Request.Context(), access.ConnectorCatalogueQuery{
		WorkspaceID: *wsID,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	if out == nil {
		out = []access.ConnectorCatalogueEntry{}
	}
	c.JSON(http.StatusOK, out)
}
