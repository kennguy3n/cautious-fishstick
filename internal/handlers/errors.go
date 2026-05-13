package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// errorEnvelope is the canonical 4xx / 5xx body shape. Operator-
// facing strings use the SN360 vocabulary (PROPOSAL §8) — "rule" not
// "policy", "access check-up" not "review campaign" — so admin-UI
// translations stay in lockstep with the service layer.
type errorEnvelope struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
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
	c.AbortWithStatusJSON(resolvedStatus, errorEnvelope{
		Error:   err.Error(),
		Code:    code,
		Message: err.Error(),
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
		errors.Is(err, access.ErrGrantNotFound):
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
	case errors.Is(err, access.ErrConnectorNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrProvisioningUnavailable):
		return http.StatusServiceUnavailable, "unavailable"
	}
	return status, "internal_error"
}
