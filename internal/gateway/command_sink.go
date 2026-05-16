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

// APICommandSink is the production CommandSink that POSTs append-command
// requests to ztna-api's /pam/sessions/:id/commands endpoint. The
// gateway intentionally does not write the pam_session_commands rows
// directly: it owns no DB credentials, and routing audit writes
// through the control plane keeps the gateway's runtime footprint
// minimal.
//
// APICommandSink is safe for concurrent use.
type APICommandSink struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAPICommandSink returns a sink bound to baseURL + apiKey. client
// is reused across calls; pass nil for a sensible default
// (Timeout=5s).
func NewAPICommandSink(baseURL, apiKey string, client *http.Client) *APICommandSink {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &APICommandSink{baseURL: baseURL, apiKey: apiKey, client: client}
}

// AppendCommand marshals in into JSON and POSTs it to
// {baseURL}/pam/sessions/{session_id}/commands. Non-2xx responses
// surface as a wrapped error including the truncated body for
// diagnostics. The sink does NOT retry — the parser's caller is
// responsible for retries (today: best-effort, logged).
func (s *APICommandSink) AppendCommand(ctx context.Context, in AppendCommandInput) error {
	if s == nil {
		return errors.New("gateway: APICommandSink is nil")
	}
	if in.SessionID == "" {
		return errors.New("gateway: AppendCommand: empty session id")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("gateway: marshal command: %w", err)
	}
	url := s.baseURL + "/pam/sessions/" + in.SessionID + "/commands"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gateway: build append-command request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: POST append-command: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("gateway: read append-command response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gateway: append-command: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return nil
}
