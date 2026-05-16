package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// stubMFAVerifier captures every VerifyStepUp call and returns the
// pre-seeded error (or nil) so the handler tests can drive the MFA
// gate through happy + failure paths without a real implementation.
type stubMFAVerifier struct {
	calls int
	err   error
}

func (s *stubMFAVerifier) VerifyStepUp(_ context.Context, _ string, _ string, _ []byte) error {
	s.calls++
	return s.err
}

// newPAMSecretEngine wires a router with the SecretBrokerService
// (PassthroughEncryptor for deterministic round-trip in tests) and
// the supplied mfaVerifier.
func newPAMSecretEngine(t *testing.T, verifier pam.MFAVerifier) (http.Handler, *pam.SecretBrokerService) {
	t.Helper()
	db := newTestDB(t)
	broker, err := pam.NewSecretBrokerService(db, access.PassthroughEncryptor{})
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	r := Router(Dependencies{
		SecretBrokerService: broker,
		PAMMFAVerifier:      verifier,
		DisableRateLimiter:  true,
	})
	return r, broker
}

func validVaultSecretBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id": "ws-1",
		"secret_type":  "password",
		"plaintext":    "hunter2",
	}
}

func TestPAMSecretHandler_VaultSecret_HappyPath(t *testing.T) {
	r, _ := newPAMSecretEngine(t, &stubMFAVerifier{})
	w := doJSON(t, r, http.MethodPost, "/pam/secrets", validVaultSecretBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	// Ciphertext is tagged json:"-" on the model so the response
	// MUST NOT include it. Guard against an accidental tag flip.
	if got := w.Body.String(); contains(got, "ciphertext") || contains(got, "hunter2") {
		t.Fatalf("vault response leaked ciphertext / plaintext: %s", got)
	}
}

func TestPAMSecretHandler_VaultSecret_ValidationReturns400(t *testing.T) {
	r, _ := newPAMSecretEngine(t, &stubMFAVerifier{})
	body := validVaultSecretBody()
	body["secret_type"] = "unknown"
	w := doJSON(t, r, http.MethodPost, "/pam/secrets", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPAMSecretHandler_GetSecretMetadata_NoCiphertextInResponse(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/secrets/"+secret.ID+"?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if body := w.Body.String(); contains(body, "ciphertext") {
		t.Fatalf("metadata response leaked ciphertext: %s", body)
	}
}

func TestPAMSecretHandler_GetSecretMetadata_NotFoundReturns404(t *testing.T) {
	r, _ := newPAMSecretEngine(t, &stubMFAVerifier{})
	w := doJSON(t, r, http.MethodGet, "/pam/secrets/nope?workspace_id=ws-1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}

func TestPAMSecretHandler_RevealSecret_WithValidMFA(t *testing.T) {
	verifier := &stubMFAVerifier{}
	r, broker := newPAMSecretEngine(t, verifier)
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id":  "ws-1",
		"user_id":       "user-1",
		"mfa_assertion": "passkey-assertion",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/reveal", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	if verifier.calls != 1 {
		t.Fatalf("MFA verifier calls = %d; want 1", verifier.calls)
	}
	if !contains(w.Body.String(), "hunter2") {
		t.Fatalf("response missing plaintext: %s", w.Body.String())
	}
}

func TestPAMSecretHandler_RevealSecret_MissingAssertionReturns400(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id": "ws-1",
		"user_id":      "user-1",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/reveal", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

// TestPAMSecretHandler_RevealSecret_MissingUserIDReturns400 covers
// the user_id validation: without it the MFA verifier would receive
// an empty subject which the NoOpMFAVerifier silently accepts and a
// production verifier's behaviour is undefined (Devin Review finding
// on PR #95). The handler must reject the request before the MFA
// gate runs.
func TestPAMSecretHandler_RevealSecret_MissingUserIDReturns400(t *testing.T) {
	verifier := &stubMFAVerifier{}
	r, broker := newPAMSecretEngine(t, verifier)
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id":  "ws-1",
		"mfa_assertion": "passkey-assertion",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/reveal", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
	if verifier.calls != 0 {
		t.Fatalf("MFA verifier should not be called when user_id is missing, got %d calls", verifier.calls)
	}
}

func TestPAMSecretHandler_RevealSecret_FailedMFAReturns403(t *testing.T) {
	verifier := &stubMFAVerifier{err: errors.New("token expired")}
	r, broker := newPAMSecretEngine(t, verifier)
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id":  "ws-1",
		"user_id":       "user-1",
		"mfa_assertion": "bad",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/reveal", body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s; want 403", w.Code, w.Body.String())
	}
}

func TestPAMSecretHandler_RevealSecret_NilVerifierReturns503(t *testing.T) {
	// Wire the broker without an MFA verifier — the production
	// binary must refuse to serve the reveal endpoint so a
	// misconfigured deploy cannot accidentally serve un-MFA'd
	// reveals.
	db := newTestDB(t)
	broker, err := pam.NewSecretBrokerService(db, access.PassthroughEncryptor{})
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	r := Router(Dependencies{
		SecretBrokerService: broker,
		PAMMFAVerifier:      nil,
		DisableRateLimiter:  true,
	})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id":  "ws-1",
		"user_id":       "u",
		"mfa_assertion": "any",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/reveal", body)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", w.Code)
	}
}

func TestPAMSecretHandler_RotateSecret_HappyPath(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{"workspace_id": "ws-1"}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/rotate", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestPAMSecretHandler_RotateSecret_MissingWorkspaceReturns400(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{}
	w := doJSON(t, r, http.MethodPost, "/pam/secrets/"+secret.ID+"/rotate", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPAMSecretHandler_GetRotationHistory_HappyPath(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/secrets/"+secret.ID+"/history?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

// TestPAMSecretHandler_GetRotationHistory_MissingWorkspaceReturns400 covers
// the workspace_id query-string requirement closing the cross-tenant
// rotation-history gap (Devin Review finding on PR #95).
func TestPAMSecretHandler_GetRotationHistory_MissingWorkspaceReturns400(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/secrets/"+secret.ID+"/history", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

// TestPAMSecretHandler_GetRotationHistory_CrossWorkspaceReturns404 asserts
// the service-layer workspace filter blocks history reads for secrets
// owned by another workspace.
func TestPAMSecretHandler_GetRotationHistory_CrossWorkspaceReturns404(t *testing.T) {
	r, broker := newPAMSecretEngine(t, &stubMFAVerifier{})
	secret, err := broker.VaultSecret(context.Background(), "ws-1", pam.VaultSecretInput{
		SecretType: "password",
		Plaintext:  []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/secrets/"+secret.ID+"/history?workspace_id=ws-other", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}

// contains is a tiny substring helper used by the response-shape
// assertions above. Kept local to this test file to avoid a new
// public helper just for the negative leak checks.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
