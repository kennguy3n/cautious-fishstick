package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// errorEnvelope is the canonical 4xx / 5xx body shape. Operator-
// facing strings use the SN360 vocabulary (docs/connectors.md) —
// "rule" not "policy", "access check-up" not "review campaign" — so
// admin-UI translations stay in lockstep with the service layer.
// RequestID is the X-Request-ID stamped by RequestIDMiddleware and
// echoed here so a client filing a support ticket can quote a single
// correlation key.
type errorEnvelope struct {
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// writeError serialises err to the response with the HTTP status
// inferred from the wrapped sentinel, falling back to status when no
// sentinel matches. The function is the single place handlers write
// error responses so the envelope shape stays consistent.
func writeError(c *gin.Context, status int, err error) {
	if err == nil {
		c.AbortWithStatus(status)
		return
	}
	resolvedStatus, code := mapServiceError(err, status)
	abortWithError(c, resolvedStatus, err.Error(), code, err.Error())
}

// abortWithError is the canonical way to abort a request with an error
// envelope. It guarantees RequestID is populated from
// RequestIDMiddleware so every error body carries the same correlation
// key swagger advertises, regardless of which handler emitted it.
func abortWithError(c *gin.Context, status int, errText, code, message string) {
	c.AbortWithStatusJSON(status, errorEnvelope{
		Error:     errText,
		Code:      code,
		Message:   message,
		RequestID: GetRequestID(c),
	})
}

// mapServiceError translates well-known service-layer sentinels onto
// (status, code) pairs. status falls through unchanged when no
// sentinel matches; the default code is "internal_error".
func mapServiceError(err error, status int) (int, string) {
	switch {
	case errors.Is(err, access.ErrValidation):
		return http.StatusBadRequest, "validation_failed"
	case errors.Is(err, access.ErrPolicyNotFound),
		errors.Is(err, access.ErrRequestNotFound),
		errors.Is(err, access.ErrReviewNotFound),
		errors.Is(err, access.ErrDecisionNotFound),
		errors.Is(err, access.ErrGrantNotFound),
		errors.Is(err, access.ErrConnectorRowNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrUnknownProvider):
		return http.StatusBadRequest, "validation_failed"
	case errors.Is(err, access.ErrConnectorAlreadyExists):
		return http.StatusConflict, "conflict"
	case errors.Is(err, access.ErrPolicyAlreadyPromoted),
		errors.Is(err, access.ErrPolicyNotSimulated),
		errors.Is(err, access.ErrPolicyNotDraft),
		errors.Is(err, access.ErrReviewClosed),
		errors.Is(err, access.ErrInvalidDecision),
		errors.Is(err, access.ErrAlreadyRevoked),
		errors.Is(err, access.ErrInvalidStateTransition):
		return http.StatusConflict, "conflict"
	case errors.Is(err, access.ErrConnectorNotFound),
		errors.Is(err, access.ErrProvisioningUnavailable):
		// ErrConnectorNotFound is the registry-layer "provider not
		// blank-imported into the binary" failure — a deployment
		// misconfiguration, not a missing user-facing resource.
		// Surface it as 503 (alongside ErrProvisioningUnavailable)
		// so operators see a loud platform-health error rather than
		// a quiet 404. The DB-row-missing case has its own sentinel
		// (ErrConnectorRowNotFound, mapped to 404 above).
		return http.StatusServiceUnavailable, "unavailable"
	}
	return status, "internal_error"
}
