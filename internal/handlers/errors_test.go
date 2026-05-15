package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// invokeWriteError runs writeError inside a real gin engine and
// returns the recorded response so tests can assert on both
// status code and JSON envelope shape.
func invokeWriteError(t *testing.T, status int, err error) (*httptest.ResponseRecorder, errorEnvelope) {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	writeError(c, status, err)
	if rec.Code == 0 {
		t.Fatal("rec.Code = 0; gin never wrote a status")
	}
	if rec.Body.Len() == 0 {
		return rec, errorEnvelope{}
	}
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return rec, env
}

// TestMapServiceError_Sentinels asserts every documented sentinel
// lands on its canonical (status, code) pair. A future PR that adds
// a new sentinel MUST extend mapServiceError AND extend this table
// to keep the contract honest.
func TestMapServiceError_Sentinels(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"validation", access.ErrValidation, http.StatusBadRequest, "validation_failed"},
		{"unknown_provider", access.ErrUnknownProvider, http.StatusBadRequest, "validation_failed"},
		{"policy_not_found", access.ErrPolicyNotFound, http.StatusNotFound, "not_found"},
		{"request_not_found", access.ErrRequestNotFound, http.StatusNotFound, "not_found"},
		{"review_not_found", access.ErrReviewNotFound, http.StatusNotFound, "not_found"},
		{"decision_not_found", access.ErrDecisionNotFound, http.StatusNotFound, "not_found"},
		{"grant_not_found", access.ErrGrantNotFound, http.StatusNotFound, "not_found"},
		{"connector_row_not_found", access.ErrConnectorRowNotFound, http.StatusNotFound, "not_found"},
		{"connector_already_exists", access.ErrConnectorAlreadyExists, http.StatusConflict, "conflict"},
		{"policy_already_promoted", access.ErrPolicyAlreadyPromoted, http.StatusConflict, "conflict"},
		{"policy_not_simulated", access.ErrPolicyNotSimulated, http.StatusConflict, "conflict"},
		{"policy_not_draft", access.ErrPolicyNotDraft, http.StatusConflict, "conflict"},
		{"review_closed", access.ErrReviewClosed, http.StatusConflict, "conflict"},
		{"invalid_decision", access.ErrInvalidDecision, http.StatusConflict, "conflict"},
		{"already_revoked", access.ErrAlreadyRevoked, http.StatusConflict, "conflict"},
		{"invalid_state_transition", access.ErrInvalidStateTransition, http.StatusConflict, "conflict"},
		{"connector_not_found", access.ErrConnectorNotFound, http.StatusServiceUnavailable, "unavailable"},
		{"provisioning_unavailable", access.ErrProvisioningUnavailable, http.StatusServiceUnavailable, "unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, gotCode := mapServiceError(tt.err, http.StatusTeapot)
			if gotStatus != tt.wantStatus {
				t.Errorf("status = %d; want %d", gotStatus, tt.wantStatus)
			}
			if gotCode != tt.wantCode {
				t.Errorf("code = %q; want %q", gotCode, tt.wantCode)
			}
		})
	}
}

// TestMapServiceError_UnknownErrorFallsThrough asserts an error
// that wraps no known sentinel returns (fallback status,
// "internal_error"). Callers pass an HTTP-500 fallback so a stray
// implementation error doesn't become a silent 200.
func TestMapServiceError_UnknownErrorFallsThrough(t *testing.T) {
	gotStatus, gotCode := mapServiceError(errors.New("db: connection refused"), http.StatusInternalServerError)
	if gotStatus != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", gotStatus)
	}
	if gotCode != "internal_error" {
		t.Errorf("code = %q; want internal_error", gotCode)
	}
}

// TestMapServiceError_WrappedSentinelStillMatches verifies
// fmt.Errorf("...: %w", sentinel) still trips errors.Is so handlers
// can stack context around a sentinel without breaking the mapping.
func TestMapServiceError_WrappedSentinelStillMatches(t *testing.T) {
	wrapped := fmt.Errorf("inserting access_request: %w", access.ErrValidation)
	gotStatus, gotCode := mapServiceError(wrapped, http.StatusInternalServerError)
	if gotStatus != http.StatusBadRequest || gotCode != "validation_failed" {
		t.Fatalf("(status,code) = (%d,%q); want (400,validation_failed)", gotStatus, gotCode)
	}
}

// TestWriteError_NilErrAbortsWithStatus asserts writeError(c, 500,
// nil) aborts the request with the supplied status and writes no
// body. Handlers occasionally call writeError with a bare status to
// short-circuit (e.g. an upstream timeout) — the path must not
// panic on a nil err.
func TestWriteError_NilErrAbortsWithStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	writeError(c, http.StatusInternalServerError, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q; want empty on nil err", rec.Body.String())
	}
}

// TestWriteError_EnvelopeShape asserts the canonical error envelope
// includes "error", "code", "message". The admin UI parses on these
// names so the contract is part of the public API.
func TestWriteError_EnvelopeShape(t *testing.T) {
	rec, env := invokeWriteError(t, http.StatusInternalServerError, access.ErrValidation)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (mapped from ErrValidation)", rec.Code)
	}
	if env.Error == "" {
		t.Error("error field is empty; want sentinel error text")
	}
	if env.Code != "validation_failed" {
		t.Errorf("code = %q; want validation_failed", env.Code)
	}
	if env.Message == "" {
		t.Error("message field is empty; want sentinel error text")
	}
}

// TestWriteError_PreservesStatusForUnknownErr asserts that an
// unrecognised error preserves the caller-supplied status (so a 404
// from a router handler stays a 404 even if the wrapped error is a
// generic "missing").
func TestWriteError_PreservesStatusForUnknownErr(t *testing.T) {
	rec, env := invokeWriteError(t, http.StatusNotFound, errors.New("missing"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404 (caller-supplied)", rec.Code)
	}
	if env.Code != "internal_error" {
		t.Errorf("code = %q; want internal_error for unknown sentinel", env.Code)
	}
}

// TestWriteError_ContentTypeIsJSON asserts the response Content-
// Type is application/json so the admin UI parses the envelope
// rather than rendering raw text.
func TestWriteError_ContentTypeIsJSON(t *testing.T) {
	rec, _ := invokeWriteError(t, http.StatusInternalServerError, access.ErrValidation)
	if ct := rec.Header().Get("Content-Type"); ct == "" || ct[:16] != "application/json" {
		t.Errorf("Content-Type = %q; want application/json", ct)
	}
}
