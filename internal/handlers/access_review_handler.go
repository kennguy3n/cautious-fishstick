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
	g.POST("/:id/decisions/bulk", h.SubmitBulkDecisions)
	g.POST("/:id/close", h.CloseCampaign)
	g.POST("/:id/auto-revoke", h.AutoRevoke)
	g.GET("/:id/metrics", h.GetCampaignMetrics)
	g.PATCH("/:id", h.PatchCampaign)
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

// bulkDecisionItem is one row in the POST /access/reviews/:id/decisions/bulk
// payload. Maps onto access.BulkDecisionInput.
type bulkDecisionItem struct {
	GrantID  string `json:"grant_id"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// bulkDecisionsRequest is the wire shape for POST
// /access/reviews/:id/decisions/bulk. DecidedBy applies to every
// item in the batch — admins submit a bulk action under their own
// identity, not per-row authorship. Decisions carries the per-grant
// entries.
type bulkDecisionsRequest struct {
	DecidedBy string             `json:"decided_by"`
	Decisions []bulkDecisionItem `json:"decisions"`
}

// SubmitBulkDecisions handles POST /access/reviews/:id/decisions/bulk.
// Each entry in the body's decisions array is dispatched through
// the per-grant SubmitDecision flow; failures on one entry do NOT
// short-circuit the remaining entries.
//
// Returns 200 with a JSON envelope:
//
//	{
//	  "review_id": "...",
//	  "summary":   { "total": N, "succeeded": M, "failed": N-M },
//	  "results":   [ { "grant_id": "...", "decision": "...", "success": true|false, "error": "..."} ]
//	}
//
// The endpoint deliberately returns 200 even when individual rows
// failed; the per-row success flag is the source of truth. A 4xx /
// 5xx response is reserved for envelope-level failures (malformed
// JSON, missing decided_by, empty decisions, review not found / closed).
func (h *AccessReviewHandler) SubmitBulkDecisions(c *gin.Context) {
	reviewID := GetStringParam(c, "id")
	if reviewID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	var req bulkDecisionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	inputs := make([]access.BulkDecisionInput, 0, len(req.Decisions))
	for _, d := range req.Decisions {
		inputs = append(inputs, access.BulkDecisionInput{
			GrantID:  d.GrantID,
			Decision: d.Decision,
			Reason:   d.Reason,
		})
	}
	results, summary, err := h.reviewService.BulkSubmitDecisions(c.Request.Context(), reviewID, req.DecidedBy, inputs)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"review_id": reviewID,
		"summary":   summary,
		"results":   results,
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

// GetCampaignMetrics handles GET /access/reviews/:id/metrics. Returns
// the per-state decision tally + auto-certification rate.
func (h *AccessReviewHandler) GetCampaignMetrics(c *gin.Context) {
	reviewID := GetStringParam(c, "id")
	if reviewID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	metrics, err := h.reviewService.GetCampaignMetrics(c.Request.Context(), reviewID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, metrics)
}

// patchCampaignRequest is the wire shape for PATCH /access/reviews/:id.
// Only auto_certify_enabled is editable today; the field is a pointer
// so the handler can distinguish "client omitted the field" from
// "client set it to false".
type patchCampaignRequest struct {
	AutoCertifyEnabled *bool `json:"auto_certify_enabled,omitempty"`
}

// PatchCampaign handles PATCH /access/reviews/:id. Currently the only
// supported mutation is flipping auto_certify_enabled — Phase 5
// admins use this to disable AI auto-certification on a per-review
// basis. Returns 200 with the updated metrics for client convenience.
func (h *AccessReviewHandler) PatchCampaign(c *gin.Context) {
	reviewID := GetStringParam(c, "id")
	if reviewID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "id path parameter is required",
			Code:    "validation_failed",
			Message: "id path parameter is required",
		})
		return
	}
	var req patchCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if req.AutoCertifyEnabled == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "no editable fields in payload",
			Code:    "validation_failed",
			Message: "auto_certify_enabled is the only editable field; supply it explicitly",
		})
		return
	}
	if err := h.reviewService.SetAutoCertifyEnabled(c.Request.Context(), reviewID, *req.AutoCertifyEnabled); err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"review_id":            reviewID,
		"auto_certify_enabled": *req.AutoCertifyEnabled,
	})
}
