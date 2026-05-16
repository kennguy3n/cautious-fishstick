package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// AIHandler bundles the Phase 4 AI-pass-through endpoints
// (explain / suggest). The handler does not enrich the user's
// payload; it forwards to the AI agent's policy_recommendation
// skill and returns the explanation field. Callers are responsible
// for shaping the input.
type AIHandler struct {
	aiService AIInvoker
}

// NewAIHandler returns a handler bound to the supplied AI invoker.
// invoker may be nil — in which case the handler returns 503 from
// every endpoint, surfacing the "AI is intentionally unconfigured"
// signal to the admin UI.
func NewAIHandler(invoker AIInvoker) *AIHandler {
	return &AIHandler{aiService: invoker}
}

// Register wires the handler's routes onto r.
func (h *AIHandler) Register(r *gin.Engine) {
	r.POST("/access/explain", h.Explain)
	r.POST("/access/suggest", h.Suggest)
	r.POST("/access/assistant", h.Assistant)
}

// explainRequest matches the docs/architecture.md §2 description: the
// caller supplies either a policy_id or a grant_id to be explained.
// Both fields are optional; the handler enforces "at least one".
type explainRequest struct {
	PolicyID string `json:"policy_id,omitempty"`
	GrantID  string `json:"grant_id,omitempty"`
}

// explainResponse is the wire shape returned by /access/explain.
// Echoes any RiskFactors the agent returns alongside the
// explanation.
type explainResponse struct {
	Explanation string   `json:"explanation"`
	RiskFactors []string `json:"risk_factors,omitempty"`
}

// Explain handles POST /access/explain. Routes to the agent's
// policy_recommendation skill with the supplied id payload.
func (h *AIHandler) Explain(c *gin.Context) {
	if h.aiService == nil {
		writeAIUnconfigured(c)
		return
	}
	var req explainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if req.PolicyID == "" && req.GrantID == "" {
		abortWithError(c, http.StatusBadRequest, "policy_id or grant_id is required", "validation_failed", "policy_id or grant_id is required")
		return
	}
	resp, err := h.aiService.InvokeSkill(c.Request.Context(), "policy_recommendation", req)
	if err != nil {
		writeAIUpstream(c, err)
		return
	}
	c.JSON(http.StatusOK, explainResponse{
		Explanation: resp.Explanation,
		RiskFactors: resp.RiskFactors,
	})
}

// suggestRequest is the input contract for /access/suggest. The
// payload is intentionally loose — the agent's
// policy_recommendation skill accepts any user-context payload and
// returns recommended resources / roles.
type suggestRequest struct {
	UserID      string                 `json:"user_id,omitempty"`
	WorkspaceID string                 `json:"workspace_id,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// Suggest handles POST /access/suggest. Forwards the user-context
// payload to the agent's policy_recommendation skill and returns
// the recommendation envelope verbatim.
func (h *AIHandler) Suggest(c *gin.Context) {
	if h.aiService == nil {
		writeAIUnconfigured(c)
		return
	}
	var req suggestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	resp, err := h.aiService.InvokeSkill(c.Request.Context(), "policy_recommendation", req)
	if err != nil {
		writeAIUpstream(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// writeAIUnconfigured emits the canonical 503 response for the
// "AI agent isn't configured" condition. Operator-facing wording
// uses the SN360 vocabulary (docs/architecture.md §9) — "AI assistant".
func writeAIUnconfigured(c *gin.Context) {
	abortWithError(c, http.StatusServiceUnavailable, aiclient.ErrAIUnconfigured.Error(), "ai_unconfigured", "AI assistant is not configured for this workspace")
}

// writeAIUpstream emits a 502 response wrapping the upstream error.
// Distinct from writeAIUnconfigured because the failure mode is
// different — the agent IS configured but not responding.
func writeAIUpstream(c *gin.Context, err error) {
	abortWithError(c, http.StatusBadGateway, err.Error(), "ai_upstream_failed", "AI assistant request failed")
}
