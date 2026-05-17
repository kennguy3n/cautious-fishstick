package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// PAMAuditHandler bundles the HTTP entry points for the
// /pam/sessions/* surface per docs/pam/architecture.md §6:
//
//   - GET    /pam/sessions                  list (workspace-scoped)
//   - GET    /pam/sessions/:id              detail
//   - GET    /pam/sessions/:id/replay       signed S3 GET URL
//   - GET    /pam/sessions/:id/commands     command timeline
//   - GET    /pam/sessions/:id/evidence     packed export
//   - POST   /pam/sessions/:id/terminate    admin-initiated force-close
//
// Lease-backed session *creation* (POST /pam/sessions) lives on
// PAMLeaseHandler's RequestLease today — a follow-up milestone
// will introduce a dedicated POST /pam/sessions endpoint that
// also stamps the connect token + replay key, but for now the
// audit handler is read-only + terminate-only.
type PAMAuditHandler struct {
	auditService *pam.PAMAuditService
}

// NewPAMAuditHandler returns a handler bound to the supplied
// service. service must not be nil.
func NewPAMAuditHandler(service *pam.PAMAuditService) *PAMAuditHandler {
	return &PAMAuditHandler{auditService: service}
}

// Register wires the handler's routes onto r under /pam/sessions.
// The terminate POST shares the prefix so a single Group call
// covers the whole surface.
func (h *PAMAuditHandler) Register(r *gin.Engine) {
	g := r.Group("/pam/sessions")
	g.GET("", h.ListSessions)
	g.GET("/:id", h.GetSession)
	g.GET("/:id/replay", h.GetReplay)
	g.GET("/:id/commands", h.GetCommands)
	g.GET("/:id/evidence", h.GetEvidence)
	g.POST("/:id/terminate", h.TerminateSession)
}

// ListSessions handles GET /pam/sessions. workspace_id is required;
// optional filters are user_id, asset_id, state, limit, offset.
func (h *PAMAuditHandler) ListSessions(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id query parameter is required", "validation_failed", "workspace_id query parameter is required")
		return
	}
	filters := pam.ListSessionsFilters{}
	if v := GetPtrStringQuery(c, "user_id"); v != nil {
		filters.UserID = *v
	}
	if v := GetPtrStringQuery(c, "asset_id"); v != nil {
		filters.AssetID = *v
	}
	if v := GetPtrStringQuery(c, "state"); v != nil {
		filters.State = *v
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
	out, err := h.auditService.ListSessions(c.Request.Context(), *wsID, filters)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// GetSession handles GET /pam/sessions/:id. workspace_id is read
// from the query string so the lookup stays tenant-scoped — without
// the gate a caller in workspace A who guesses a session ULID in
// workspace B would leak the session metadata.
func (h *PAMAuditHandler) GetSession(c *gin.Context) {
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
	out, err := h.auditService.GetSession(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// GetReplay handles GET /pam/sessions/:id/replay. Returns the
// signed S3 GET URL + expiry; the bucket and object key never
// leave the service layer.
func (h *PAMAuditHandler) GetReplay(c *gin.Context) {
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
	replay, err := h.auditService.GetSessionReplay(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, replay)
}

// GetCommands handles GET /pam/sessions/:id/commands. Returns the
// full command timeline for the session, ordered by sequence. PAM
// sessions rarely exceed a few hundred commands so the response is
// not paginated — admin UI tables virtualise client-side.
func (h *PAMAuditHandler) GetCommands(c *gin.Context) {
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
	out, err := h.auditService.GetCommandTimeline(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// GetEvidence handles GET /pam/sessions/:id/evidence. Returns the
// EvidencePack (session row + commands + signed replay URL) in a
// single response so the admin UI's "export" button is one
// round-trip.
func (h *PAMAuditHandler) GetEvidence(c *gin.Context) {
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
	pack, err := h.auditService.ExportEvidence(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, pack)
}

// terminateSessionBody captures the operator who is force-closing
// the session and the optional free-text reason. WorkspaceID is
// required in the body so cross-tenant terminate is impossible
// (matches the lease + secret handlers' contract).
type terminateSessionBody struct {
	WorkspaceID string `json:"workspace_id"`
	ActorUserID string `json:"actor_user_id"`
	Reason      string `json:"reason,omitempty"`
}

// TerminateSession handles POST /pam/sessions/:id/terminate. Flips
// the row to state=terminated, stamps ended_at, and emits a
// pam.session.terminated audit event. The actual gateway-side
// teardown happens when the gateway picks up the event (or the
// next health tick) — the handler returns immediately so the admin
// UI is responsive.
func (h *PAMAuditHandler) TerminateSession(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body terminateSessionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.WorkspaceID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id is required", "validation_failed", "workspace_id is required")
		return
	}
	if body.ActorUserID == "" {
		abortWithError(c, http.StatusBadRequest, "actor_user_id is required", "validation_failed", "actor_user_id is required")
		return
	}
	session, err := h.auditService.TerminateSession(c.Request.Context(), body.WorkspaceID, id, body.ActorUserID, body.Reason)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, session)
}
