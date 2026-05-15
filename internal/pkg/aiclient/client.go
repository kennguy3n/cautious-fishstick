// Package aiclient is the Go-side stub for the access-ai-agent A2A
// (agent-to-agent) skill server per docs/overview.md §7.1 and
// docs/architecture.md §8.
//
// The client speaks plain JSON over HTTPS — `POST {baseURL}/a2a/invoke`
// with an `X-API-Key` header. The Python A2A server hosts five
// skills (access_risk_assessment, access_review_automation,
// access_anomaly_detection, connector_setup_assistant, and
// policy_recommendation) and routes by skill_name in the request
// body.
//
// Failure semantics: AI is decision-support, not critical path
// (PROPOSAL §5.3). InvokeSkill never panics; transport / decode
// errors surface to the caller, but the access platform's
// service layer wraps the call site with a fallback that defaults to
// risk_score=medium so a momentarily-unreachable AI never blocks an
// access request.
package aiclient

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

// SkillResponse is the unified response envelope returned by the
// Python A2A server. Every skill populates a subset of the fields:
//
//   - access_risk_assessment    → RiskScore + RiskFactors
//   - access_review_automation  → Decision + Reason
//   - access_anomaly_detection  → Anomalies (slice of structured
//     observations on a single grant's recent usage)
//   - policy_recommendation     → Explanation (+ RiskFactors when
//     surfacing rationale)
//
// Unknown fields in the JSON payload are intentionally allowed
// (encoding/json default) so server-side schema additions don't break
// existing Go callers.
type SkillResponse struct {
	RiskScore   string         `json:"risk_score,omitempty"`
	RiskFactors []string       `json:"risk_factors,omitempty"`
	Decision    string         `json:"decision,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	Explanation string         `json:"explanation,omitempty"`
	Anomalies   []AnomalyEvent `json:"anomalies,omitempty"`
}

// AnomalyEvent is one entry in the access_anomaly_detection response.
// Each event carries a kind (taxonomy below), a free-text reason
// the AI agent generated, a severity bucket, and a confidence score
// in [0.0, 1.0].
//
// Severity uses the same low/medium/high vocabulary as risk score
// so the admin UI can render a unified "trust signal" badge across
// risk + anomaly streams. Confidence is informative only — callers
// SHOULD treat all surfaced anomalies as potentially actionable
// regardless of confidence.
type AnomalyEvent struct {
	// Kind taxonomies the anomaly. Phase 6 stub values:
	//   "geo_unusual"           – grant used from an unusual region
	//   "time_unusual"          – grant used at unusual hours
	//   "frequency_spike"       – usage frequency outside baseline
	//   "scope_expansion"       – grant role widened beyond baseline
	//   "stale_grant"           – grant unused for an extended window
	Kind string `json:"kind"`
	// Reason is a short human-readable summary the admin UI surfaces.
	Reason string `json:"reason,omitempty"`
	// Severity is one of "low", "medium", "high".
	Severity string `json:"severity,omitempty"`
	// Confidence is the AI's self-reported confidence in [0.0, 1.0].
	Confidence float64 `json:"confidence,omitempty"`
}

// AIClient is the thin HTTP wrapper around the access-ai-agent
// service. The zero value is NOT safe to use; construct via
// NewAIClient.
//
// AIClient is safe for concurrent use — the embedded *http.Client is
// the standard library's, and the rest of the struct is read-only
// after construction.
type AIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// defaultTimeout is the per-request timeout applied when the caller
// does not pass an *http.Client. AI is decision-support; we'd rather
// time out and fall back to risk_score=medium than block an HTTP
// handler for tens of seconds.
const defaultTimeout = 5 * time.Second

// NewAIClient returns an *AIClient configured to POST against
// baseURL. baseURL should be the agent's root URL (e.g.
// "https://access-ai-agent.internal:8443"); the "/a2a/invoke" suffix
// is appended internally.
//
// apiKey is sent in the X-API-Key request header per
// docs/overview.md §10.3 (AI agent only authenticated via shared
// secret on the cluster-internal network).
//
// Both arguments may be empty. An AIClient with an empty baseURL is a
// signal to callers that AI is intentionally unconfigured; in that
// case InvokeSkill returns ErrAIUnconfigured and the caller's
// fallback path runs.
func NewAIClient(baseURL, apiKey string) *AIClient {
	return &AIClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// SetHTTPClient overrides the internal *http.Client. Intended for
// tests that want to supply a stub transport, and for callers that
// need a custom timeout / TLS config.
func (c *AIClient) SetHTTPClient(h *http.Client) {
	if h == nil {
		return
	}
	c.httpClient = h
}

// BaseURL returns the configured base URL. Useful for tests and
// log lines that want to surface "AI is calling X" without exposing
// the API key. Never logs the API key itself.
func (c *AIClient) BaseURL() string { return c.baseURL }

// ErrAIUnconfigured is returned by InvokeSkill when the client was
// constructed with an empty baseURL. Callers errors.Is this and treat
// it as "AI is intentionally not wired up; run the fallback path".
var ErrAIUnconfigured = errors.New("aiclient: AI agent base URL not configured")

// ErrAIRequestFailed is returned by InvokeSkill when the HTTP request
// completes with a non-2xx status code. The error message includes
// the status code and a truncated body excerpt; the body is bounded
// to avoid blowing up logs on a misbehaving server.
var ErrAIRequestFailed = errors.New("aiclient: AI request failed")

// invokePayload is the request body shape consumed by the A2A
// /a2a/invoke endpoint. The Python server routes by skill_name and
// passes payload through to the matching skill handler.
type invokePayload struct {
	SkillName string      `json:"skill_name"`
	Payload   interface{} `json:"payload,omitempty"`
}

// maxResponseBody bounds the bytes we read from the AI response to
// avoid pathological / hostile responses pinning a goroutine. 1 MiB
// is generous for a structured risk-assessment payload.
const maxResponseBody = 1 << 20

// InvokeSkill posts a JSON envelope to the agent's /a2a/invoke
// endpoint and returns the decoded SkillResponse. Failure modes:
//
//   - baseURL is empty                   → ErrAIUnconfigured
//   - context expiry / transport failure → underlying ctx err / *url.Error
//   - non-2xx status                     → ErrAIRequestFailed wrapping body
//   - malformed JSON in 2xx body         → wrapping json.Unmarshal err
//
// InvokeSkill never logs the API key. Callers MUST treat error
// returns as "AI unavailable" and run their fallback path; the
// access-platform service layer wraps every InvokeSkill call this
// way.
func (c *AIClient) InvokeSkill(ctx context.Context, skillName string, payload interface{}) (*SkillResponse, error) {
	if c == nil || c.baseURL == "" {
		return nil, ErrAIUnconfigured
	}
	if skillName == "" {
		return nil, errors.New("aiclient: skill_name is required")
	}

	body := invokePayload{SkillName: skillName, Payload: payload}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aiclient: marshal request: %w", err)
	}

	url := c.baseURL + "/a2a/invoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("aiclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aiclient: post %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("aiclient: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status=%d body=%q", ErrAIRequestFailed, resp.StatusCode, truncateBody(respBody))
	}

	var out SkillResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("aiclient: decode response: %w", err)
	}
	return &out, nil
}

// truncateBody clamps the response body excerpt embedded in
// ErrAIRequestFailed to a manageable size. Logs and error messages
// stay readable when the agent returns a multi-megabyte HTML page.
func truncateBody(b []byte) string {
	const maxLen = 256
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "..."
}

// AnomalyDetectionPayload is the canonical request shape for the
// access_anomaly_detection skill. The Go service layer marshals
// one of these per grant into a /a2a/invoke call and the Python
// agent returns SkillResponse.Anomalies.
//
// UsageData is intentionally typed as map[string]interface{} so
// the service layer can pass through whatever recent-usage
// observations it has (sign-in counts, geo histogram, last-seen
// timestamp, etc.) without locking the schema in Go.
type AnomalyDetectionPayload struct {
	GrantID   string                 `json:"grant_id"`
	UserID    string                 `json:"user_id,omitempty"`
	Role      string                 `json:"role,omitempty"`
	Resource  string                 `json:"resource_external_id,omitempty"`
	UsageData map[string]interface{} `json:"usage_data,omitempty"`
}

// DetectAnomalies posts an AnomalyDetectionPayload to the
// access_anomaly_detection skill and returns the (possibly empty)
// AnomalyEvent slice from the response. Failure modes mirror
// InvokeSkill — callers wrap with DetectAnomaliesWithFallback to
// get the PROPOSAL §5.3 fallback (empty list on unreachable AI).
func (c *AIClient) DetectAnomalies(ctx context.Context, grantID string, usageData map[string]interface{}) ([]AnomalyEvent, error) {
	payload := AnomalyDetectionPayload{
		GrantID:   grantID,
		UsageData: usageData,
	}
	resp, err := c.InvokeSkill(ctx, "access_anomaly_detection", payload)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return resp.Anomalies, nil
}
