package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// PAMLeaseHandler bundles the HTTP entry points for the
// /pam/leases/* surface (list active + historical leases, revoke a
// lease) per docs/pam/architecture.md.
//
// Lease *creation* happens implicitly via POST /pam/sessions in a
// follow-up milestone — until then call sites that need a lease
// for testing invoke PAMLeaseService.RequestLease directly.
type PAMLeaseHandler struct {
	leaseService *pam.PAMLeaseService
}

// NewPAMLeaseHandler returns a handler bound to the supplied
// service. service must not be nil.
func NewPAMLeaseHandler(service *pam.PAMLeaseService) *PAMLeaseHandler {
	return &PAMLeaseHandler{leaseService: service}
}

// Register wires the handler's routes onto r under /pam/leases.
func (h *PAMLeaseHandler) Register(r *gin.Engine) {
	g := r.Group("/pam/leases")
	g.POST("", h.RequestLease)
	g.GET("", h.ListLeases)
	g.POST("/:id/approve", h.ApproveLease)
	g.POST("/:id/revoke", h.RevokeLease)
}

// requestLeaseBody mirrors pam.RequestLeaseInput on the wire.
type requestLeaseBody struct {
	WorkspaceID     string `json:"workspace_id"`
	UserID          string `json:"user_id"`
	AssetID         string `json:"asset_id"`
	AccountID       string `json:"account_id"`
	Reason          string `json:"reason,omitempty"`
	DurationMinutes int    `json:"duration_minutes"`
}

// RequestLease handles POST /pam/leases. Returns 201 with the new
// lease row (state=requested).
func (h *PAMLeaseHandler) RequestLease(c *gin.Context) {
	var body requestLeaseBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	lease, err := h.leaseService.RequestLease(c.Request.Context(), body.WorkspaceID, pam.RequestLeaseInput{
		UserID:          body.UserID,
		AssetID:         body.AssetID,
		AccountID:       body.AccountID,
		Reason:          body.Reason,
		DurationMinutes: body.DurationMinutes,
	})
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusCreated, lease)
}

// ListLeases handles GET /pam/leases. workspace_id is required;
// optional filters are user_id, asset_id, active_only, limit, offset.
func (h *PAMLeaseHandler) ListLeases(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id query parameter is required", "validation_failed", "workspace_id query parameter is required")
		return
	}
	filters := pam.ListLeasesFilters{}
	if v := GetPtrStringQuery(c, "user_id"); v != nil {
		filters.UserID = *v
	}
	if v := GetPtrStringQuery(c, "asset_id"); v != nil {
		filters.AssetID = *v
	}
	if v := GetPtrStringQuery(c, "active_only"); v != nil && *v == "true" {
		filters.ActiveOnly = true
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
	out, err := h.leaseService.ListLeases(c.Request.Context(), *wsID, filters)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// approveLeaseBody captures the approver identity + an optional
// duration override. When DurationMinutes is omitted the service
// falls back to a 60-minute default.
type approveLeaseBody struct {
	ApproverID      string `json:"approver_id"`
	DurationMinutes int    `json:"duration_minutes,omitempty"`
}

// ApproveLease handles POST /pam/leases/:id/approve.
func (h *PAMLeaseHandler) ApproveLease(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body approveLeaseBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	lease, err := h.leaseService.ApproveLease(c.Request.Context(), id, body.ApproverID, body.DurationMinutes)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, lease)
}

// revokeLeaseBody captures the free-text revocation reason. The
// reason is stored on the audit producer side; on the row itself we
// only persist revoked_at.
type revokeLeaseBody struct {
	Reason string `json:"reason,omitempty"`
}

// RevokeLease handles POST /pam/leases/:id/revoke.
func (h *PAMLeaseHandler) RevokeLease(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body revokeLeaseBody
	// Allow a missing body — revocation reason is optional.
	_ = c.ShouldBindJSON(&body)
	lease, err := h.leaseService.RevokeLease(c.Request.Context(), id, body.Reason)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, lease)
}
