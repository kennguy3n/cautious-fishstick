package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// assistantRequest is the wire shape for POST /access/assistant. It
// is the Phase 4 "AI assistant chat" surface from docs/PROPOSAL.md
// §11: a free-form natural-language question paired with optional
// hints (workspace, focused entity, explicit skill override).
//
// The Skill field is an explicit escape hatch. When set, the
// handler bypasses intent classification and dispatches directly
// to the named skill — useful for power-users and for the
// frontend's "explain selection" shortcut buttons which already
// know which skill to call.
type assistantRequest struct {
	Query       string                 `json:"query"`
	WorkspaceID string                 `json:"workspace_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	GrantID     string                 `json:"grant_id,omitempty"`
	ConnectorID string                 `json:"connector_id,omitempty"`
	Skill       string                 `json:"skill,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// assistantResponse is the rich envelope returned by
// /access/assistant. The Intent string surfaces which skill the
// handler routed to so the chat UI can render the matched
// intent as a chip alongside the answer.
type assistantResponse struct {
	Intent string                  `json:"intent"`
	Skill  string                  `json:"skill"`
	Result *aiclient.SkillResponse `json:"result"`
}

// classifyIntent maps a free-text query to one of the four
// canonical AI skills documented in docs/PROPOSAL.md §11
// ("Phase 4 AI agent skills"):
//
//   - risk_assessment           — "is this risky?"
//   - policy_recommendation     — "explain / suggest a policy"
//   - access_anomaly_detection  — "is this user behaving normally?"
//   - connector_setup           — "how do I connect X?"
//
// The classifier is intentionally keyword-based, not
// model-driven: this endpoint is a routing surface, not a fully
// agentic LLM, and the Python access-ai-agent is the source of
// truth for the actual answer. The keyword table here only needs
// to pick the right skill bucket; the agent receives the raw
// query as part of its payload.
//
// Returned skill names match the strings the Python agent
// registers (see internal/pkg/aiclient/client.go and the agent's
// skill registry). Falling through with no match maps to
// policy_recommendation because Phase 4 designates it as the
// default "ask anything" skill.
func classifyIntent(query string) string {
	q := strings.ToLower(query)
	switch {
	case containsAny(q, "risk", "risky", "threat", "danger", "compromise"):
		return "risk_assessment"
	case containsAny(q, "anomaly", "anomalous", "unusual", "abnormal", "weird", "suspicious"):
		return "access_anomaly_detection"
	case containsAny(q, "connect ", "connector", "integrate", "integration", "set up", "setup", "configure"):
		return "connector_setup"
	default:
		return "policy_recommendation"
	}
}

// containsAny returns true if haystack contains any of the
// needles. Empty needles are ignored.
func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// Assistant handles POST /access/assistant. Classifies the
// caller's natural-language query into one of the Phase 4 AI
// skills, dispatches to the access-ai-agent, and returns the
// raw SkillResponse alongside the matched intent.
//
// Skill-override: if the request supplies a non-empty Skill,
// the classifier is bypassed and the handler dispatches to that
// skill directly. The intent is reported as "override" so the
// chat UI can render an explicit override badge.
//
// Errors:
//
//   - 400 — query missing
//   - 503 — AI invoker not configured (ErrAIUnconfigured)
//   - 502 — agent reachable but call failed
func (h *AIHandler) Assistant(c *gin.Context) {
	if h.aiService == nil {
		writeAIUnconfigured(c)
		return
	}
	var req assistantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, errorEnvelope{
			Error:   "query is required",
			Code:    "validation_failed",
			Message: "query is required",
		})
		return
	}

	intent := "override"
	skill := req.Skill
	if skill == "" {
		skill = classifyIntent(req.Query)
		intent = skill
	}

	// Forward the full request (including the natural-language
	// query and any caller-supplied context) verbatim — the agent
	// is responsible for interpreting payload fields it
	// recognises and ignoring the rest.
	payload := map[string]interface{}{
		"query":        req.Query,
		"workspace_id": req.WorkspaceID,
		"user_id":      req.UserID,
		"policy_id":    req.PolicyID,
		"grant_id":     req.GrantID,
		"connector_id": req.ConnectorID,
		"context":      req.Context,
	}

	resp, err := h.aiService.InvokeSkill(c.Request.Context(), skill, payload)
	if err != nil {
		writeAIUpstream(c, err)
		return
	}
	c.JSON(http.StatusOK, assistantResponse{
		Intent: intent,
		Skill:  skill,
		Result: resp,
	})
}
