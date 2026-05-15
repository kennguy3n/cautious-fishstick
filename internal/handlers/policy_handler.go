package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// PolicyHandler bundles the HTTP entry points for the access-rule
// (policy) lifecycle: draft → simulate → promote → test-access (per
// docs/overview.md §6 and docs/architecture.md §5).
//
// Handlers translate HTTP into PolicyService calls; they never talk
// to the DB directly. Sentinel-based status mapping lives in
// errors.go so the envelope shape stays consistent across the
// package.
type PolicyHandler struct {
	policyService *access.PolicyService
}

// NewPolicyHandler returns a handler bound to the supplied service.
// service must not be nil.
func NewPolicyHandler(service *access.PolicyService) *PolicyHandler {
	return &PolicyHandler{policyService: service}
}

// Register wires the handler's routes onto r. Routes follow the
// shape in docs/overview.md §11 and the workspace-prefixed
// convention used elsewhere in the SN360 admin API.
func (h *PolicyHandler) Register(r *gin.Engine) {
	g := r.Group("/workspace/policy")
	g.POST("", h.CreateDraft)
	g.GET("/drafts", h.ListDrafts)
	g.GET("/:id", h.GetPolicy)
	g.POST("/:id/simulate", h.Simulate)
	g.POST("/:id/promote", h.Promote)
	g.GET("/:id/diff", h.Diff)
	g.POST("/test-access", h.TestAccess)
}

// createDraftRequest mirrors access.CreateDraftPolicyInput on the
// wire. JSON-tagged so the admin UI / SDK can encode against a
// stable shape regardless of internal field names.
type createDraftRequest struct {
	WorkspaceID        string          `json:"workspace_id"`
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	AttributesSelector json.RawMessage `json:"attributes_selector,omitempty"`
	ResourceSelector   json.RawMessage `json:"resource_selector,omitempty"`
	Action             string          `json:"action"`
}

// CreateDraft handles POST /workspace/policy. It binds the JSON
// body, calls PolicyService.CreateDraft, and returns 201 with the
// persisted Policy on success. Validation errors surface as 400
// with the SN360 "rule" wording from the service layer.
func (h *PolicyHandler) CreateDraft(c *gin.Context) {
	var req createDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	policy, err := h.policyService.CreateDraft(c.Request.Context(), access.CreateDraftPolicyInput{
		WorkspaceID:        req.WorkspaceID,
		Name:               req.Name,
		Description:        req.Description,
		AttributesSelector: req.AttributesSelector,
		ResourceSelector:   req.ResourceSelector,
		Action:             req.Action,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, policy)
}

// ListDrafts handles GET /workspace/policy/drafts. workspace_id is
// required as a query parameter. Returns 200 with a JSON array of
// drafts (possibly empty).
func (h *PolicyHandler) ListDrafts(c *gin.Context) {
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id query parameter is required",
			Code:    "validation_failed",
			Message: "workspace_id query parameter is required",
		})
		return
	}
	drafts, err := h.policyService.ListDrafts(c.Request.Context(), *wsID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, drafts)
}

// GetPolicy handles GET /workspace/policy/:id. workspace_id is
// required as a query parameter (ListDrafts uses the same query
// shape so admins can paste between routes). The service is asked
// for the underlying row regardless of draft state, mirroring
// PolicyService.GetPolicy semantics.
func (h *PolicyHandler) GetPolicy(c *gin.Context) {
	id := GetStringParam(c, "id")
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id query parameter is required",
			Code:    "validation_failed",
			Message: "workspace_id query parameter is required",
		})
		return
	}
	policy, err := h.policyService.GetPolicy(c.Request.Context(), *wsID, id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, policy)
}

// simulateRequest is the body shape for POST
// /workspace/policy/:id/simulate. workspace_id is the only required
// field; the policy id comes from the path parameter.
type simulateRequest struct {
	WorkspaceID string `json:"workspace_id"`
}

// Simulate handles POST /workspace/policy/:id/simulate. It runs the
// impact resolver / conflict detector and stamps the resulting
// ImpactReport into draft_impact. Returns 200 with the report.
func (h *PolicyHandler) Simulate(c *gin.Context) {
	id := GetStringParam(c, "id")
	var req simulateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	report, err := h.policyService.Simulate(c.Request.Context(), req.WorkspaceID, id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, report)
}

// Diff handles GET /workspace/policy/:id/diff. Returns a structured
// before/after comparison of the draft policy against the workspace's
// current live state. Requires a workspace_id query parameter and a
// previously-simulated draft (the service surfaces ErrPolicyNotSimulated
// otherwise, mapped to 409 Conflict in errors.go).
func (h *PolicyHandler) Diff(c *gin.Context) {
	id := GetStringParam(c, "id")
	wsID := GetPtrStringQuery(c, "workspace_id")
	if wsID == nil || *wsID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "workspace_id query parameter is required",
			Code:    "validation_failed",
			Message: "workspace_id query parameter is required",
		})
		return
	}
	report, err := h.policyService.DiffPolicy(c.Request.Context(), *wsID, id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, report)
}

// promoteRequest is the body shape for POST
// /workspace/policy/:id/promote. workspace_id and actor_user_id
// are required; the policy id comes from the path parameter.
type promoteRequest struct {
	WorkspaceID string `json:"workspace_id"`
	ActorUserID string `json:"actor_user_id"`
}

// Promote handles POST /workspace/policy/:id/promote. Flips
// is_draft → false in a single transaction. Returns 200 with the
// updated Policy on success.
func (h *PolicyHandler) Promote(c *gin.Context) {
	id := GetStringParam(c, "id")
	var req promoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	policy, err := h.policyService.Promote(c.Request.Context(), req.WorkspaceID, id, req.ActorUserID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, policy)
}

// testAccessRequest mirrors access.TestAccessInput on the wire.
// Used by the admin UI's interactive sandbox to ask "would draft P
// grant user X access to resource Y?".
type testAccessRequest struct {
	WorkspaceID        string `json:"workspace_id"`
	PolicyID           string `json:"policy_id"`
	UserID             string `json:"user_id"`
	ResourceExternalID string `json:"resource_external_id"`
}

// TestAccess handles POST /workspace/policy/test-access. Returns
// 200 with a TestAccessResult describing whether the supplied user
// would gain access to the supplied resource under the supplied
// (draft or live) policy.
func (h *PolicyHandler) TestAccess(c *gin.Context) {
	var req testAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	result, err := h.policyService.TestAccess(c.Request.Context(), access.TestAccessInput{
		WorkspaceID:        req.WorkspaceID,
		PolicyID:           req.PolicyID,
		UserID:             req.UserID,
		ResourceExternalID: req.ResourceExternalID,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
