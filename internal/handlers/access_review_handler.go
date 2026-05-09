package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// AccessReviewHandler bundles the HTTP entry points for the Phase 5
// access-review (access check-up) campaigns: StartCampaign /
// SubmitDecision / CloseCampaign / AutoRevoke.
type AccessReviewHandler struct {
	reviewService *access.AccessReviewService
}

// NewAccessReviewHandler returns a handler bound to the supplied
// service. service must not be nil.
func NewAccessReviewHandler(service *access.AccessReviewService) *AccessReviewHandler {
	return &AccessReviewHandler{reviewService: service}
}

// Register wires the handler's routes onto r. The /decisions verb
// is plural in the route and accepts a body containing one decision
// — a future Phase 6 batch-decisions endpoint can drop into the same
// path with an array body without breaking existing callers.
func (h *AccessReviewHandler) Register(r *gin.Engine) {
	g := r.Group("/access/reviews")
	g.POST("", h.StartCampaign)
	g.POST("/:id/decisions", h.SubmitDecision)
	g.POST("/:id/close", h.CloseCampaign)
	g.POST("/:id/auto-revoke", h.AutoRevoke)
}

// startCampaignRequest mirrors access.StartCampaignInput on the
// wire. ScopeFilter is a JSON object passed straight through to the
// service, which understands the connector_id / user_id / role
// shape.
type startCampaignRequest struct {
	WorkspaceID        string          `json:"workspace_id"`
	Name               string          `json:"name"`
	DueAt              time.Time       `json:"due_at"`
	ScopeFilter        json.RawMessage `json:"scope_filter,omitempty"`
	AutoCertifyEnabled bool            `json:"auto_certify_enabled"`
}

// StartCampaign handles POST /access/reviews. Returns 201 with a
// JSON envelope: { "review": {...}, "decisions": [...] }.
func (h *AccessReviewHandler) StartCampaign(c *gin.Context) {
	var req startCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	review, decisions, err := h.reviewService.StartCampaign(c.Request.Context(), access.StartCampaignInput{
		WorkspaceID:        req.WorkspaceID,
		Name:               req.Name,
		DueAt:              req.DueAt,
		ScopeFilter:        req.ScopeFilter,
		AutoCertifyEnabled: req.AutoCertifyEnabled,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"review":    review,
		"decisions": decisions,
	})
}

// submitDecisionRequest mirrors AccessReviewService.SubmitDecision
// arguments. The review id comes from the path parameter; the
// grant id, decision, decided_by, and reason come from the body.
type submitDecisionRequest struct {
	GrantID   string `json:"grant_id"`
	Decision  string `json:"decision"`
	DecidedBy string `json:"decided_by"`
	Reason    string `json:"reason,omitempty"`
}

// SubmitDecision handles POST /access/reviews/:id/decisions.
// Returns 200 with a tiny acknowledgement envelope; downstream
// callers re-fetch the review to see the updated decision row.
func (h *AccessReviewHandler) SubmitDecision(c *gin.Context) {
	reviewID := GetStringParam(c, "id")
	if reviewID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	var req submitDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if err := h.reviewService.SubmitDecision(
		c.Request.Context(),
		reviewID,
		req.GrantID,
		req.Decision,
		req.DecidedBy,
		req.Reason,
	); err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"review_id": reviewID,
		"grant_id":  req.GrantID,
		"decision":  req.Decision,
	})
}

// CloseCampaign handles POST /access/reviews/:id/close. Returns
// 200 with an acknowledgement envelope.
func (h *AccessReviewHandler) CloseCampaign(c *gin.Context) {
	reviewID := GetStringParam(c, "id")
	if reviewID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	if err := h.reviewService.CloseCampaign(c.Request.Context(), reviewID); err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"review_id": reviewID,
		"state":     "closed",
	})
}

// AutoRevoke handles POST /access/reviews/:id/auto-revoke. Returns
// 200 with an acknowledgement envelope.
func (h *AccessReviewHandler) AutoRevoke(c *gin.Context) {
	reviewID := GetStringParam(c, "id")
	if reviewID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	if err := h.reviewService.AutoRevoke(c.Request.Context(), reviewID); err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"review_id":   reviewID,
		"auto_revoke": "completed",
	})
}
