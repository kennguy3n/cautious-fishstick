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

// APIPolicyEvaluator is the gateway-side HTTP client that
// satisfies CommandPolicyEvaluator by calling
// POST /pam/policy/evaluate on ztna-api. The handler delegates to
// pam.SessionPolicyAdapter which loads the session row + asset
// metadata and runs the command through PAMCommandPolicyService.
//
// The struct is safe for concurrent use. A nil receiver returns
// ("allow", "", nil) so the SSH/K8s listener's "no evaluator
// configured" default keeps working.
type APIPolicyEvaluator struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAPIPolicyEvaluator returns a new evaluator bound to baseURL +
// apiKey. client is reused across calls; pass nil for a sane
// 5-second-timeout default. Mirroring NewAPIAuthorizer keeps the
// constructor signatures uniform across the api_*.go family.
func NewAPIPolicyEvaluator(baseURL, apiKey string, client *http.Client) *APIPolicyEvaluator {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &APIPolicyEvaluator{baseURL: baseURL, apiKey: apiKey, client: client}
}

// evaluateRequest is the on-the-wire body the handler decodes.
type evaluateRequest struct {
	WorkspaceID string `json:"workspace_id"`
	SessionID   string `json:"session_id"`
	Input       string `json:"input"`
}

// evaluateResponse is the on-the-wire body the handler returns.
// MatchedPolicyID is decoded but currently ignored — the listener
// only needs (action, reason) — keeping it in the struct lets
// admin tooling that taps the wire log surface the policy id
// without a second deserialiser.
type evaluateResponse struct {
	Action          string `json:"action"`
	Reason          string `json:"reason,omitempty"`
	MatchedPolicyID string `json:"matched_policy_id,omitempty"`
}

// EvaluateCommand satisfies CommandPolicyEvaluator. It POSTs the
// supplied (workspace_id, session_id, input) tuple to
// /pam/policy/evaluate and decodes the response. Empty input
// short-circuits to ("allow", "", nil) so a stray carriage return
// on the operator's terminal does not generate a round trip.
//
// A nil receiver returns ("allow", "", nil) so call sites can
// nil-check the wiring without a defensive guard at every use.
func (e *APIPolicyEvaluator) EvaluateCommand(
	ctx context.Context,
	workspaceID, sessionID, input string,
) (string, string, error) {
	if e == nil {
		return "allow", "", nil
	}
	if input == "" {
		return "allow", "", nil
	}
	if workspaceID == "" {
		return "", "", errors.New("gateway: APIPolicyEvaluator: empty workspace_id")
	}
	if sessionID == "" {
		return "", "", errors.New("gateway: APIPolicyEvaluator: empty session_id")
	}
	body, err := json.Marshal(evaluateRequest{
		WorkspaceID: workspaceID,
		SessionID:   sessionID,
		Input:       input,
	})
	if err != nil {
		return "", "", fmt.Errorf("gateway: marshal evaluate body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/pam/policy/evaluate", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("gateway: build evaluate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("gateway: POST evaluate: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("gateway: read evaluate body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("gateway: evaluate: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var out evaluateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", "", fmt.Errorf("gateway: decode evaluate body: %w", err)
	}
	if out.Action == "" {
		return "", "", errors.New("gateway: evaluate: empty action in response")
	}
	return out.Action, out.Reason, nil
}
