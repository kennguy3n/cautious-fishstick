package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// AccessRequestHandler bundles the HTTP entry points for the
// Phase 2 access-request lifecycle (CreateRequest / ListRequests /
// Approve / Deny / Cancel).
//
// Like the other handlers in this package, AccessRequestHandler
// translates HTTP into AccessRequestService calls and reads
// path / query parameters strictly through GetStringParam /
// GetPtrStringQuery.
type AccessRequestHandler struct {
	requestService *access.AccessRequestService
}

// NewAccessRequestHandler returns a handler bound to the supplied
// service. service must not be nil.
func NewAccessRequestHandler(service *access.AccessRequestService) *AccessRequestHandler {
	return &AccessRequestHandler{requestService: service}
}

// Register wires the handler's routes onto r. Routes follow the
// shape in docs/architecture.md §2 ("POST /access/requests" + verbs).
func (h *AccessRequestHandler) Register(r *gin.Engine) {
	g := r.Group("/access/requests")
	g.POST("", h.CreateRequest)
	g.GET("", h.ListRequests)
	g.GET("/:id", h.GetRequest)
	g.POST("/:id/approve", h.ApproveRequest)
	g.POST("/:id/deny", h.DenyRequest)
	g.POST("/:id/cancel", h.CancelRequest)
}

// GetRequest handles GET /access/requests/:id. Returns the request
// row along with its full state-history audit trail so the operator
// admin UI can render the "request detail" drawer without making N
// follow-up calls. Returns 400 when :id is missing, 404 when the
// request does not exist, 500 on DB errors.
func (h *AccessRequestHandler) GetRequest(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	detail, err := h.requestService.GetRequest(c.Request.Context(), id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// createRequestBody mirrors access.CreateAccessRequestInput on the
// wire. Times use RFC3339 in JSON; expires_at may be omitted for
// "no expiry".
type createRequestBody struct {
	WorkspaceID        string     `json:"workspace_id"`
	RequesterUserID    string     `json:"requester_user_id"`
	TargetUserID       string     `json:"target_user_id"`
	ConnectorID        string     `json:"connector_id"`
	ResourceExternalID string     `json:"resource_external_id"`
	Role               string     `json:"role"`
	Justification      string     `json:"justification,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
}

// CreateRequest handles POST /access/requests. Returns 201 with the
// persisted AccessRequest on success; validation errors surface as
// 400.
func (h *AccessRequestHandler) CreateRequest(c *gin.Context) {
	var body createRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	req, err := h.requestService.CreateRequest(c.Request.Context(), access.CreateAccessRequestInput{
		WorkspaceID:        body.WorkspaceID,
		RequesterUserID:    body.RequesterUserID,
		TargetUserID:       body.TargetUserID,
		ConnectorID:        body.ConnectorID,
		ResourceExternalID: body.ResourceExternalID,
		Role:               body.Role,
		Justification:      body.Justification,
		ExpiresAt:          body.ExpiresAt,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, req)
}

// ListRequests handles GET /access/requests. Filters are read from
// the query string (workspace_id, state, requester_user_id,
// target_user_id, resource_external_id). workspace_id is required;
// the rest are optional. Returns 200 with a JSON array
// (possibly empty).
func (h *AccessRequestHandler) ListRequests(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id query parameter is required",
			Code:    "validation_failed",
			Message: "workspace_id query parameter is required",
		})
		return
	}
	q := access.ListAccessRequestsQuery{
		WorkspaceID:        *wsID,
		State:              GetPtrStringQuery(c, "state"),
		RequesterUserID:    GetPtrStringQuery(c, "requester_user_id"),
		TargetUserID:       GetPtrStringQuery(c, "target_user_id"),
		ResourceExternalID: GetPtrStringQuery(c, "resource_external_id"),
	}
	out, err := h.requestService.ListRequests(c.Request.Context(), q)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// transitionBody is the shared body shape for the approve / deny /
// cancel verbs. actor_user_id is the identity recorded in the
// state-history audit trail; reason is the operator-supplied
// justification.
type transitionBody struct {
	ActorUserID string `json:"actor_user_id"`
	Reason      string `json:"reason,omitempty"`
}

// ApproveRequest handles POST /access/requests/:id/approve.
func (h *AccessRequestHandler) ApproveRequest(c *gin.Context) {
	h.transitionVerb(c, "approve")
}

// DenyRequest handles POST /access/requests/:id/deny.
func (h *AccessRequestHandler) DenyRequest(c *gin.Context) {
	h.transitionVerb(c, "deny")
}

// CancelRequest handles POST /access/requests/:id/cancel.
func (h *AccessRequestHandler) CancelRequest(c *gin.Context) {
	h.transitionVerb(c, "cancel")
}

// transitionVerb is the shared implementation for the three
// state-transition verbs. The verb is mapped to the corresponding
// service method; FSM rejections surface as 409 via mapServiceError.
func (h *AccessRequestHandler) transitionVerb(c *gin.Context, verb string) {
	id := GetStringParam(c, "id")
	if id == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	var body transitionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	ctx := c.Request.Context()
	var err error
	switch verb {
	case "approve":
		err = h.requestService.ApproveRequest(ctx, id, body.ActorUserID, body.Reason)
	case "deny":
		err = h.requestService.DenyRequest(ctx, id, body.ActorUserID, body.Reason)
	case "cancel":
		err = h.requestService.CancelRequest(ctx, id, body.ActorUserID, body.Reason)
	}
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	// Re-read the updated row so the response matches the SDK contract:
	// AccessSDKProtocol.swift / AccessSDKClient.kt / access-ipc.ts all
	// declare approveRequest / denyRequest / cancelRequest return the
	// full AccessRequest. Returning the post-transition state here lets
	// concrete SDK implementations decode the response directly without
	// a follow-up GET /access/requests/:id round-trip.
	detail, err := h.requestService.GetRequest(ctx, id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, detail.Request)
}
