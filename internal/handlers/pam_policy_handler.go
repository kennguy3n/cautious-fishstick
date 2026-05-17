package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// PAMPolicyHandler exposes the command-policy engine over HTTP so
// the pam-gateway can evaluate operator-typed commands without a
// direct DB connection. The single route is intentionally minimal:
//
//	POST /pam/policy/evaluate
//	{
//	  "workspace_id": "...",
//	  "session_id":   "...",
//	  "input":        "rm -rf /"
//	}
//
//	200 OK
//	{
//	  "action": "deny",
//	  "reason": "command 'rm -rf /' matched policy ..."
//	}
//
// "action" is one of "allow" | "deny" | "step_up". On any
// service-layer error the handler returns a 5xx envelope and the
// gateway falls open (allows the command) per the existing
// listener semantics.
type PAMPolicyHandler struct {
	adapter *pam.SessionPolicyAdapter
}

// NewPAMPolicyHandler returns a handler bound to the supplied
// adapter. adapter must not be nil; the router only registers
// the route when the dependency is present.
func NewPAMPolicyHandler(adapter *pam.SessionPolicyAdapter) *PAMPolicyHandler {
	return &PAMPolicyHandler{adapter: adapter}
}

// Register wires the handler's single route onto r. Mounting
// under /pam/policy leaves room for follow-up CRUD routes on
// pam_command_policies (list/create/delete) without a second
// handler.
func (h *PAMPolicyHandler) Register(r *gin.Engine) {
	g := r.Group("/pam/policy")
	g.POST("/evaluate", h.Evaluate)
}

// evaluateBody mirrors the gateway-side request shape exactly so
// the JSON tags match the gateway's marshalled struct.
type evaluateBody struct {
	WorkspaceID string `json:"workspace_id"`
	SessionID   string `json:"session_id"`
	Input       string `json:"input"`
}

// evaluateResponse is the canonical {action, reason} pair the
// gateway's APIPolicyEvaluator decodes. "matched_policy_id" is an
// optional debugging hint — useful for the admin UI but the
// gateway ignores it.
type evaluateResponse struct {
	Action          string `json:"action"`
	Reason          string `json:"reason,omitempty"`
	MatchedPolicyID string `json:"matched_policy_id,omitempty"`
}

// Evaluate handles POST /pam/policy/evaluate. Empty input is
// short-circuited to allow before touching the DB so a control-
// character flush from the operator's terminal does not generate
// a round trip.
func (h *PAMPolicyHandler) Evaluate(c *gin.Context) {
	var body evaluateBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.WorkspaceID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id is required", "validation_failed", "workspace_id is required")
		return
	}
	if body.SessionID == "" {
		abortWithError(c, http.StatusBadRequest, "session_id is required", "validation_failed", "session_id is required")
		return
	}
	action, reason, err := h.adapter.EvaluateCommand(c.Request.Context(), body.WorkspaceID, body.SessionID, body.Input)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, evaluateResponse{
		Action: action,
		Reason: reason,
	})
}
