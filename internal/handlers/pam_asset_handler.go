package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// PAMAssetHandler bundles the HTTP entry points for the
// /pam/assets/* surface (asset CRUD + per-asset account
// management) per docs/pam/architecture.md.
//
// The handler keeps the same conventions as the rest of this
// package: path parameters are read through GetStringParam, query
// parameters through GetPtrStringQuery, and errors are translated
// to the canonical errorEnvelope by writeError + mapPAMServiceError.
type PAMAssetHandler struct {
	assetService *pam.PAMAssetService
}

// NewPAMAssetHandler returns a handler bound to the supplied service.
// service must not be nil.
func NewPAMAssetHandler(service *pam.PAMAssetService) *PAMAssetHandler {
	return &PAMAssetHandler{assetService: service}
}

// Register wires the handler's routes onto r under /pam/assets.
// Mirrors the surface in docs/pam/architecture.md.
func (h *PAMAssetHandler) Register(r *gin.Engine) {
	g := r.Group("/pam/assets")
	g.POST("", h.CreateAsset)
	g.GET("", h.ListAssets)
	g.GET("/:id", h.GetAsset)
	g.PUT("/:id", h.UpdateAsset)
	g.DELETE("/:id", h.DeleteAsset)
	g.POST("/:id/accounts", h.CreateAccount)
	g.GET("/:id/accounts", h.ListAccounts)
}

// createAssetBody mirrors pam.CreateAssetInput on the wire plus the
// workspace_id used to scope the row (taken from the body for
// dev-binary simplicity; production callers pull it from the
// authenticated session).
type createAssetBody struct {
	WorkspaceID string         `json:"workspace_id"`
	Name        string         `json:"name"`
	Protocol    string         `json:"protocol"`
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Criticality string         `json:"criticality,omitempty"`
	OwnerUserID string         `json:"owner_user_id,omitempty"`
	Config      datatypes.JSON `json:"config,omitempty"`
}

// CreateAsset handles POST /pam/assets. Returns 201 with the
// persisted asset on success; validation errors surface as 400.
func (h *PAMAssetHandler) CreateAsset(c *gin.Context) {
	var body createAssetBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	asset, err := h.assetService.CreateAsset(c.Request.Context(), body.WorkspaceID, pam.CreateAssetInput{
		Name:        body.Name,
		Protocol:    body.Protocol,
		Host:        body.Host,
		Port:        body.Port,
		Criticality: body.Criticality,
		OwnerUserID: body.OwnerUserID,
		Config:      body.Config,
	})
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusCreated, asset)
}

// GetAsset handles GET /pam/assets/:id. workspace_id is read from
// the query string so the asset stays workspace-scoped.
func (h *PAMAssetHandler) GetAsset(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id query parameter is required", "validation_failed", "workspace_id query parameter is required")
		return
	}
	asset, err := h.assetService.GetAsset(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, asset)
}

// ListAssets handles GET /pam/assets. workspace_id is required;
// optional filters are protocol, status, criticality, limit, offset.
func (h *PAMAssetHandler) ListAssets(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id query parameter is required", "validation_failed", "workspace_id query parameter is required")
		return
	}
	filters := pam.ListAssetsFilters{}
	if v := GetPtrStringQuery(c, "protocol"); v != nil {
		filters.Protocol = *v
	}
	if v := GetPtrStringQuery(c, "status"); v != nil {
		filters.Status = *v
	}
	if v := GetPtrStringQuery(c, "criticality"); v != nil {
		filters.Criticality = *v
	}
	if v := GetPtrStringQuery(c, "limit"); v != nil && *v != "" {
		if n, err := strconv.Atoi(*v); err == nil {
			filters.Limit = n
		}
	}
	if v := GetPtrStringQuery(c, "offset"); v != nil && *v != "" {
		if n, err := strconv.Atoi(*v); err == nil {
			filters.Offset = n
		}
	}
	out, err := h.assetService.ListAssets(c.Request.Context(), *wsID, filters)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// updateAssetBody mirrors pam.UpdateAssetInput on the wire. All
// fields are optional; nil pointers leave the column unchanged.
type updateAssetBody struct {
	WorkspaceID string          `json:"workspace_id"`
	Name        *string         `json:"name,omitempty"`
	Host        *string         `json:"host,omitempty"`
	Port        *int            `json:"port,omitempty"`
	Criticality *string         `json:"criticality,omitempty"`
	OwnerUserID *string         `json:"owner_user_id,omitempty"`
	Config      *datatypes.JSON `json:"config,omitempty"`
	Status      *string         `json:"status,omitempty"`
}

// UpdateAsset handles PUT /pam/assets/:id. Returns the post-update
// row on success.
func (h *PAMAssetHandler) UpdateAsset(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body updateAssetBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.WorkspaceID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id is required", "validation_failed", "workspace_id is required")
		return
	}
	asset, err := h.assetService.UpdateAsset(c.Request.Context(), body.WorkspaceID, id, pam.UpdateAssetInput{
		Name:        body.Name,
		Host:        body.Host,
		Port:        body.Port,
		Criticality: body.Criticality,
		OwnerUserID: body.OwnerUserID,
		Config:      body.Config,
		Status:      body.Status,
	})
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, asset)
}

// DeleteAsset handles DELETE /pam/assets/:id. The asset is
// soft-deleted via status=archived; the row remains queryable so
// historical sessions stay reconcilable.
func (h *PAMAssetHandler) DeleteAsset(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id query parameter is required", "validation_failed", "workspace_id query parameter is required")
		return
	}
	if err := h.assetService.DeleteAsset(c.Request.Context(), *wsID, id); err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "archived", "id": id})
}

// createAccountBody mirrors pam.CreateAccountInput on the wire.
// WorkspaceID is required so the asset lookup is tenant-scoped at
// the service layer (matches pam.PAMAssetService.CreateAccount).
type createAccountBody struct {
	WorkspaceID string  `json:"workspace_id"`
	Username    string  `json:"username"`
	AccountType string  `json:"account_type"`
	SecretID    *string `json:"secret_id,omitempty"`
	IsDefault   bool    `json:"is_default,omitempty"`
}

// CreateAccount handles POST /pam/assets/:id/accounts. The :id
// path segment is the asset ID; workspace_id is required in the
// body so the service can verify the calling workspace owns the
// asset before the row is created.
func (h *PAMAssetHandler) CreateAccount(c *gin.Context) {
	assetID := GetStringParam(c, "id")
	if assetID == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body createAccountBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.WorkspaceID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id is required", "validation_failed", "workspace_id is required")
		return
	}
	account, err := h.assetService.CreateAccount(c.Request.Context(), body.WorkspaceID, assetID, pam.CreateAccountInput{
		Username:    body.Username,
		AccountType: body.AccountType,
		SecretID:    body.SecretID,
		IsDefault:   body.IsDefault,
	})
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusCreated, account)
}

// ListAccounts handles GET /pam/assets/:id/accounts. workspace_id
// is required on the query string so the service can verify the
// calling workspace owns the asset before returning its accounts
// — without this gate a caller in workspace A who guesses an
// asset ULID in workspace B could enumerate every account on it
// (Devin Review finding on PR #95).
func (h *PAMAssetHandler) ListAccounts(c *gin.Context) {
	assetID := GetStringParam(c, "id")
	if assetID == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id query parameter is required", "validation_failed", "workspace_id query parameter is required")
		return
	}
	out, err := h.assetService.ListAccounts(c.Request.Context(), *wsID, assetID)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// writePAMError maps PAM service-layer sentinels onto the canonical
// errorEnvelope. Validation → 400, not-found → 404, everything else
// → 500.
func writePAMError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, pam.ErrValidation):
		abortWithError(c, http.StatusBadRequest, err.Error(), "validation_failed", err.Error())
	case errors.Is(err, pam.ErrAssetNotFound),
		errors.Is(err, pam.ErrAccountNotFound),
		errors.Is(err, pam.ErrSecretNotFound),
		errors.Is(err, pam.ErrLeaseNotFound),
		errors.Is(err, pam.ErrSessionNotFound):
		abortWithError(c, http.StatusNotFound, err.Error(), "not_found", err.Error())
	case errors.Is(err, pam.ErrMFARequired):
		abortWithError(c, http.StatusBadRequest, err.Error(), "mfa_required", err.Error())
	case errors.Is(err, pam.ErrMFAFailed):
		abortWithError(c, http.StatusForbidden, err.Error(), "mfa_failed", err.Error())
	case errors.Is(err, pam.ErrLeaseAlreadyTerminal):
		abortWithError(c, http.StatusConflict, err.Error(), "conflict", err.Error())
	case errors.Is(err, pam.ErrReplayUnavailable):
		// 409 Conflict — the session exists, just has no replay
		// blob to sign. Lets operators distinguish "session not
		// found" (404) from "session has no replay yet" (409).
		abortWithError(c, http.StatusConflict, err.Error(), "replay_unavailable", err.Error())
	default:
		writeError(c, http.StatusInternalServerError, err)
	}
}
