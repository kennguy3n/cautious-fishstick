package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// PAMSecretHandler bundles the HTTP entry points for the
// /pam/secrets/* surface (vault, metadata read, step-up MFA reveal,
// rotation, rotation history) per docs/pam/architecture.md.
//
// The handler keeps the same conventions as the rest of the
// handlers package: path parameters are read through GetStringParam,
// errors flow through writePAMError so the canonical
// errorEnvelope shape stays consistent.
type PAMSecretHandler struct {
	broker      *pam.SecretBrokerService
	mfaVerifier pam.MFAVerifier
}

// NewPAMSecretHandler returns a handler bound to broker. mfaVerifier
// may be nil; when nil the reveal endpoint returns 503 so the
// production binary cannot accidentally serve un-MFA'd reveals.
func NewPAMSecretHandler(broker *pam.SecretBrokerService, mfaVerifier pam.MFAVerifier) *PAMSecretHandler {
	return &PAMSecretHandler{broker: broker, mfaVerifier: mfaVerifier}
}

// Register wires the handler's routes onto r under /pam/secrets.
func (h *PAMSecretHandler) Register(r *gin.Engine) {
	g := r.Group("/pam/secrets")
	g.POST("", h.VaultSecret)
	g.GET("/:id", h.GetSecretMetadata)
	g.POST("/:id/reveal", h.RevealSecret)
	g.POST("/:id/rotate", h.RotateSecret)
	g.GET("/:id/history", h.GetRotationHistory)
}

// vaultSecretBody mirrors pam.VaultSecretInput on the wire.
// Plaintext is accepted as a UTF-8 string for simplicity; the
// gateway / API client is responsible for encoding binary
// credentials (e.g. SSH private keys) as PEM before submitting.
type vaultSecretBody struct {
	WorkspaceID    string         `json:"workspace_id"`
	SecretType     string         `json:"secret_type"`
	Plaintext      string         `json:"plaintext"`
	RotationPolicy datatypes.JSON `json:"rotation_policy,omitempty"`
}

// VaultSecret handles POST /pam/secrets. Returns 201 with the
// persisted (ciphertext-redacted) row on success.
func (h *PAMSecretHandler) VaultSecret(c *gin.Context) {
	var body vaultSecretBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	secret, err := h.broker.VaultSecret(c.Request.Context(), body.WorkspaceID, pam.VaultSecretInput{
		SecretType:     body.SecretType,
		Plaintext:      []byte(body.Plaintext),
		RotationPolicy: body.RotationPolicy,
	})
	if err != nil {
		writePAMError(c, err)
		return
	}
	// The model's JSON tag for Ciphertext is `-` so it is omitted
	// automatically. The handler does not need to redact further.
	c.JSON(http.StatusCreated, secret)
}

// GetSecretMetadata handles GET /pam/secrets/:id. Returns metadata
// only — Ciphertext is never exposed.
func (h *PAMSecretHandler) GetSecretMetadata(c *gin.Context) {
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
	secret, err := h.broker.GetSecretMetadata(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, secret)
}

// revealSecretBody carries the step-up MFA assertion alongside the
// usual workspace scoping. UserID is required so the MFA verifier
// can scope the challenge to a specific identity.
type revealSecretBody struct {
	WorkspaceID  string `json:"workspace_id"`
	UserID       string `json:"user_id"`
	MFAAssertion string `json:"mfa_assertion"`
}

// revealSecretResponse is the response shape from RevealSecret. The
// plaintext is intentionally a top-level string field rather than
// echoing the full PAMSecret struct — the latter would risk
// reflecting other metadata back through a sensitive endpoint.
type revealSecretResponse struct {
	SecretID  string `json:"secret_id"`
	Plaintext string `json:"plaintext"`
}

// RevealSecret handles POST /pam/secrets/:id/reveal. Gates on the
// supplied MFA assertion via the configured MFAVerifier; returns
// 400 if the assertion is missing, 403 if it fails to verify, 200
// with plaintext on success.
func (h *PAMSecretHandler) RevealSecret(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body revealSecretBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.WorkspaceID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id is required", "validation_failed", "workspace_id is required")
		return
	}
	// user_id is required so the MFA verifier can scope the
	// challenge to a specific identity. Without this guard a client
	// could submit {"user_id":""} and the verifier would either
	// reject it with an opaque error, accept it against no user
	// (NoOpMFAVerifier in dev/test), or panic in a production
	// verifier with stricter expectations (Devin Review finding on
	// PR #95).
	if body.UserID == "" {
		abortWithError(c, http.StatusBadRequest, "user_id is required", "validation_failed", "user_id is required")
		return
	}
	if body.MFAAssertion == "" {
		abortWithError(c, http.StatusBadRequest, pam.ErrMFARequired.Error(), "mfa_required", pam.ErrMFARequired.Error())
		return
	}
	if h.mfaVerifier == nil {
		// Production binary configured WITHOUT an MFA verifier —
		// refuse to serve so we never accidentally bypass the gate.
		abortWithError(c, http.StatusServiceUnavailable, "mfa verifier not configured", "unavailable", "mfa verifier not configured")
		return
	}
	if err := h.mfaVerifier.VerifyStepUp(c.Request.Context(), body.UserID, pam.MFAScopeSecretReveal, []byte(body.MFAAssertion)); err != nil {
		abortWithError(c, http.StatusForbidden, pam.ErrMFAFailed.Error(), "mfa_failed", err.Error())
		return
	}
	plaintext, err := h.broker.RevealSecret(c.Request.Context(), body.WorkspaceID, id, []byte(body.MFAAssertion))
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, revealSecretResponse{
		SecretID:  id,
		Plaintext: string(plaintext),
	})
}

// rotateSecretBody captures the workspace scoping for a rotation.
type rotateSecretBody struct {
	WorkspaceID string `json:"workspace_id"`
}

// RotateSecret handles POST /pam/secrets/:id/rotate. Returns the
// post-rotation (ciphertext-redacted) row.
func (h *PAMSecretHandler) RotateSecret(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		abortWithError(c, http.StatusBadRequest, "id path parameter is required", "validation_failed", "id path parameter is required")
		return
	}
	var body rotateSecretBody
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if body.WorkspaceID == "" {
		abortWithError(c, http.StatusBadRequest, "workspace_id is required", "validation_failed", "workspace_id is required")
		return
	}
	secret, err := h.broker.RotateSecret(c.Request.Context(), body.WorkspaceID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, secret)
}

// GetRotationHistory handles GET /pam/secrets/:id/history. Returns
// the rotation-event audit trail derived from the row's
// LastRotatedAt timestamp; the full Kafka-backed audit trail lands
// in a follow-up milestone.
//
// workspace_id is required as a query parameter so the lookup is
// tenant-scoped — without it a caller who knew a secret ULID from
// another workspace could probe rotation timestamps.
func (h *PAMSecretHandler) GetRotationHistory(c *gin.Context) {
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
	history, err := h.broker.GetRotationHistory(c.Request.Context(), *wsID, id)
	if err != nil {
		writePAMError(c, err)
		return
	}
	c.JSON(http.StatusOK, history)
}
