// Package gateway is the PAM gateway's protocol-side library — the
// SSH (and, in follow-up milestones, K8s + DB) listeners, the
// session-authorisation client that talks to ztna-api, and the
// secret-injection helper that hands credentials to the target
// connection on the operator's behalf.
//
// The package is intentionally split out from cmd/pam-gateway so
// service-level tests can exercise the SSH path with an httptest
// stand-in for ztna-api instead of booting the binary.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuthorizedSession is the shape ztna-api returns from
// POST /pam/sessions/authorize. The session-id is recorded in
// every audit event the gateway emits so an operator can pivot
// from a Kafka audit row to the full session timeline.
//
// WorkspaceID accompanies SessionID so the command-policy engine
// (Milestone 9) can scope per-workspace rules without a second
// round trip — it is required by EvaluateCommand.
type AuthorizedSession struct {
	SessionID   string `json:"session_id"`
	WorkspaceID string `json:"workspace_id"`
	LeaseID     string `json:"lease_id"`
	AssetID     string `json:"asset_id"`
	AccountID   string `json:"account_id"`
	Protocol    string `json:"protocol"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port"`
	Username    string `json:"username"`
}

// SessionAuthorizer is the narrow contract the SSH listener uses
// to validate a one-shot connect token against the control plane.
// The production implementation is APIAuthorizer; tests substitute
// a stub that returns deterministic AuthorizedSession structs.
type SessionAuthorizer interface {
	AuthorizeConnectToken(ctx context.Context, token string) (*AuthorizedSession, error)
}

// SecretInjector is the narrow contract the SSH listener uses to
// fetch the decrypted credential for a session's account. The
// production implementation is APISecretInjector; tests substitute
// a stub that returns canned bytes.
type SecretInjector interface {
	InjectSecret(ctx context.Context, sessionID, accountID string) (secretType string, plaintext []byte, err error)
}

// APIAuthorizer is the production SessionAuthorizer that calls
// ztna-api over HTTPS. The struct is safe for concurrent use.
type APIAuthorizer struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAPIAuthorizer returns a new authorizer bound to baseURL +
// apiKey. client is reused across calls; pass http.DefaultClient
// for a sane default.
func NewAPIAuthorizer(baseURL, apiKey string, client *http.Client) *APIAuthorizer {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &APIAuthorizer{baseURL: baseURL, apiKey: apiKey, client: client}
}

// AuthorizeConnectToken posts the supplied one-shot token to
// /pam/sessions/authorize and decodes the resulting session.
// Returns an error when the API rejects the token, the response is
// not JSON, or the resulting session is missing required fields.
func (a *APIAuthorizer) AuthorizeConnectToken(ctx context.Context, token string) (*AuthorizedSession, error) {
	if a == nil {
		return nil, errors.New("gateway: APIAuthorizer is nil")
	}
	if token == "" {
		return nil, errors.New("gateway: empty connect token")
	}
	body, err := json.Marshal(map[string]string{"connect_token": token})
	if err != nil {
		return nil, fmt.Errorf("gateway: marshal authorize body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/pam/sessions/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gateway: build authorize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway: POST authorize: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("gateway: read authorize body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway: authorize: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var sess AuthorizedSession
	if err := json.Unmarshal(respBody, &sess); err != nil {
		return nil, fmt.Errorf("gateway: decode authorize body: %w", err)
	}
	if sess.SessionID == "" || sess.TargetHost == "" || sess.TargetPort == 0 {
		return nil, fmt.Errorf("gateway: authorize: incomplete session payload")
	}
	return &sess, nil
}

// APISecretInjector is the production SecretInjector that calls
// ztna-api over HTTPS to fetch the decrypted credential for a
// session.
type APISecretInjector struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAPISecretInjector returns a new injector bound to baseURL +
// apiKey.
func NewAPISecretInjector(baseURL, apiKey string, client *http.Client) *APISecretInjector {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &APISecretInjector{baseURL: baseURL, apiKey: apiKey, client: client}
}

// injectResponse mirrors ztna-api's
// POST /pam/sessions/:id/inject-secret response body.
type injectResponse struct {
	SessionID  string `json:"session_id"`
	SecretType string `json:"secret_type"`
	Plaintext  string `json:"plaintext"`
}

// InjectSecret fetches the credential for the supplied session +
// account. The plaintext is held only in memory for the lifetime of
// the connection — neither this method nor its caller writes it to
// disk.
func (i *APISecretInjector) InjectSecret(ctx context.Context, sessionID, accountID string) (string, []byte, error) {
	if i == nil {
		return "", nil, errors.New("gateway: APISecretInjector is nil")
	}
	if sessionID == "" {
		return "", nil, errors.New("gateway: empty session id")
	}
	if accountID == "" {
		return "", nil, errors.New("gateway: empty account id")
	}
	body, err := json.Marshal(map[string]string{"account_id": accountID})
	if err != nil {
		return "", nil, fmt.Errorf("gateway: marshal inject body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.baseURL+"/pam/sessions/"+sessionID+"/inject-secret", bytes.NewReader(body))
	if err != nil {
		return "", nil, fmt.Errorf("gateway: build inject request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if i.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+i.apiKey)
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("gateway: POST inject: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, fmt.Errorf("gateway: read inject body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("gateway: inject: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var out injectResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", nil, fmt.Errorf("gateway: decode inject body: %w", err)
	}
	if out.Plaintext == "" {
		return "", nil, errors.New("gateway: inject: empty plaintext")
	}
	return out.SecretType, []byte(out.Plaintext), nil
}
