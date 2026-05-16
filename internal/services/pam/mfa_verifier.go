package pam

import (
	"context"
	"errors"
	"log"
)

// MFAVerifier is the narrow contract SecretBrokerService uses to
// gate sensitive operations (secret reveal) on a step-up MFA
// challenge. The production implementation will dispatch to the
// existing passkey / TOTP verifier in cmd/ztna-api; tests substitute
// a stub.
//
// scope is the operation being authorised (e.g. "pam.secret.reveal",
// "pam.session.start"). The verifier may use scope to scope the MFA
// session, prevent token reuse across operations, and audit which
// surface triggered the prompt.
//
// assertion is the wire payload submitted by the user agent — for
// passkey it is the WebAuthn assertion, for TOTP it is the 6-digit
// code. The interface treats it as opaque bytes so callers do not
// need to switch on the credential type.
type MFAVerifier interface {
	VerifyStepUp(ctx context.Context, userID string, scope string, assertion []byte) error
}

// Sentinel MFA errors. Mapped to HTTP status codes by the handler
// layer (ErrMFARequired → 400, ErrMFAFailed → 403).
var (
	// ErrMFARequired is returned by the handler layer when the
	// request body does not carry an MFA assertion. The
	// SecretBrokerService never returns this — it expects callers
	// (handlers) to enforce the assertion present-check first.
	ErrMFARequired = errors.New("pam: step-up MFA assertion required")

	// ErrMFAFailed is returned when the supplied MFA assertion did
	// not verify against the user's enrolled credentials.
	ErrMFAFailed = errors.New("pam: step-up MFA verification failed")
)

// NoOpMFAVerifier is the dev / test implementation of MFAVerifier
// that accepts any non-empty assertion. Empty assertions still
// return ErrMFAFailed so handlers that fail to enforce the assertion
// present-check still surface a visible error.
//
// PRODUCTION CALL SITES MUST WIRE A REAL VERIFIER. The constructor
// emits a single warning log line on first use so a deployment that
// accidentally ships with the no-op gate is immediately visible in
// service logs.
type NoOpMFAVerifier struct {
	// warned tracks whether the warning log has been emitted yet.
	// Concurrent callers may race here; the worst case is a few
	// duplicate warnings which is harmless. We deliberately avoid
	// a mutex so the verifier stays lock-free on the hot path.
	warned bool
}

// NewNoOpMFAVerifier returns a new no-op verifier. Logs a single
// warning at construction time so an operator running with the
// dev binary sees an explicit "MFA is disabled" message.
func NewNoOpMFAVerifier() *NoOpMFAVerifier {
	log.Printf("pam: NoOpMFAVerifier wired — step-up MFA is DISABLED (development mode only)")
	return &NoOpMFAVerifier{warned: true}
}

// VerifyStepUp succeeds for any non-empty assertion. Empty
// assertions return ErrMFAFailed so the handler layer cannot
// accidentally skip the gate entirely.
func (v *NoOpMFAVerifier) VerifyStepUp(_ context.Context, userID string, scope string, assertion []byte) error {
	if !v.warned {
		log.Printf("pam: NoOpMFAVerifier accepting step-up assertion for user=%s scope=%s (development mode only)", userID, scope)
		v.warned = true
	}
	if len(assertion) == 0 {
		return ErrMFAFailed
	}
	return nil
}
