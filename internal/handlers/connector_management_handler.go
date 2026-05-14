package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ConnectorManagementHandler bundles the HTTP entry points for the
// connector lifecycle described in docs/ARCHITECTURE.md §2:
//
//   - POST   /access/connectors             — create a new connector
//   - DELETE /access/connectors/:id         — soft-delete + revoke grants
//   - PUT    /access/connectors/:id/secret  — rotate credentials
//   - POST   /access/connectors/:id/sync    — enqueue an out-of-band sync
//
// The handler is a thin Gin shim over ConnectorManagementService —
// all the heavy lifting (uniqueness, encryption, job enqueueing,
// SSO federation) lives in the service.
type ConnectorManagementHandler struct {
	service *access.ConnectorManagementService
}

// NewConnectorManagementHandler returns a handler bound to the
// supplied service. service must not be nil.
func NewConnectorManagementHandler(service *access.ConnectorManagementService) *ConnectorManagementHandler {
	return &ConnectorManagementHandler{service: service}
}

// Register wires the handler's routes onto r. Routes follow the
// shape in docs/PROPOSAL.md §11 ("POST /access/connectors" + verbs).
func (h *ConnectorManagementHandler) Register(r *gin.Engine) {
	g := r.Group("/access/connectors")
	g.POST("", h.CreateConnector)
	g.DELETE("/:id", h.DeleteConnector)
	g.PATCH("/:id", h.PatchConnector)
	g.PUT("/:id/secret", h.RotateSecret)
	g.POST("/:id/sync", h.TriggerSync)
}

// connectorCreateBody mirrors access.ConnectInput on the wire.
type connectorCreateBody struct {
	WorkspaceID   string                 `json:"workspace_id"`
	Provider      string                 `json:"provider"`
	ConnectorType string                 `json:"connector_type,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"`
	Secrets       map[string]interface{} `json:"secrets,omitempty"`
	Capabilities  []string               `json:"capabilities,omitempty"`
	SSORealm      string                 `json:"sso_realm,omitempty"`
	SSOAlias      string                 `json:"sso_alias,omitempty"`
	DisplayName   string                 `json:"display_name,omitempty"`
}

// CreateConnector handles POST /access/connectors. Returns 201 with
// the {connector_id, job_id} envelope on success.
func (h *ConnectorManagementHandler) CreateConnector(c *gin.Context) {
	var body connectorCreateBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	res, err := h.service.Connect(c.Request.Context(), access.ConnectInput{
		WorkspaceID:   body.WorkspaceID,
		Provider:      body.Provider,
		ConnectorType: body.ConnectorType,
		Config:        body.Config,
		Secrets:       body.Secrets,
		Capabilities:  body.Capabilities,
		SSORealm:      body.SSORealm,
		SSOAlias:      body.SSOAlias,
		DisplayName:   body.DisplayName,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, res)
}

// DeleteConnector handles DELETE /access/connectors/:id. Returns
// 200 with an empty envelope on success.
func (h *ConnectorManagementHandler) DeleteConnector(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	if err := h.service.Disconnect(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"connector_id": id, "status": "disconnected"})
}

// connectorSecretBody is the request body for PUT
// /access/connectors/:id/secret. Config is optional — when omitted
// the existing config row is preserved and only the secrets blob is
// rotated.
type connectorSecretBody struct {
	Config  map[string]interface{} `json:"config,omitempty"`
	Secrets map[string]interface{} `json:"secrets"`
}

// RotateSecret handles PUT /access/connectors/:id/secret. Returns
// 200 with the connector ID on success.
func (h *ConnectorManagementHandler) RotateSecret(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	var body connectorSecretBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if err := h.service.RotateCredentials(c.Request.Context(), id, body.Config, body.Secrets); err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"connector_id": id, "status": "rotated"})
}

// connectorPatchBody is the request body for
// PATCH /access/connectors/:id. The only mutable field today is
// access_mode (docs/PROPOSAL.md §13). Future Phase 11 follow-ups
// can extend the body — the handler ignores unknown keys.
type connectorPatchBody struct {
	AccessMode *string `json:"access_mode,omitempty"`
}

// PatchConnector handles PATCH /access/connectors/:id. Currently
// supports admin override of the connector's docs/PROPOSAL.md §13
// access_mode (one of tunnel | sso_only | api_only). Returns 200
// with the connector ID + new mode on success, 400 on a malformed
// mode, and 500 on a service-level failure.
func (h *ConnectorManagementHandler) PatchConnector(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	var body connectorPatchBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.AccessMode == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "no patchable fields supplied",
			Code:    "validation_failed",
			Message: "no patchable fields supplied",
		})
		return
	}
	mode := *body.AccessMode
	if err := h.service.UpdateAccessMode(c.Request.Context(), id, mode); err != nil {
		// writeError maps ErrValidation -> 400 and
		// ErrConnectorRowNotFound -> 404 via mapServiceError;
		// anything else surfaces as 500.
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"connector_id": id, "access_mode": mode})
}

// TriggerSync handles POST /access/connectors/:id/sync. Returns 202
// Accepted because the operation enqueues an asynchronous
// sync_identities job; the response carries the job ID so callers
// can poll its progress.
func (h *ConnectorManagementHandler) TriggerSync(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	jobID, err := h.service.TriggerSync(c.Request.Context(), id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"connector_id": id, "job_id": jobID})
}
