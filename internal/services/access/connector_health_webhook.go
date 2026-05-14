// Package access — ConnectorHealthWebhook.
//
// T28 — Connector health webhook notifications.
//
// The platform already surfaces per-connector health via
// GET /access/connectors/:id/health. T28 layers a push channel on
// top: when a connector's health enters the "needs attention" state
// (audit cursor stale beyond the configured window OR credential
// expired in the past) the platform POSTs a structured envelope to
// a configurable URL.
//
// The webhook is best-effort: failures are returned but never abort
// the caller (the underlying health-check pipeline is the source of
// truth; webhooks are a notification side effect). Implementations
// MUST be idempotent on the receiving side — callers will fire the
// same envelope on every sweep until the operator resolves the
// underlying condition.
package access

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

// ConnectorHealthEvent is the JSON envelope POSTed to the webhook
// receiver. EventType distinguishes the two trigger conditions so
// downstream routing (PagerDuty / Slack / on-call rotation) can fan
// the events out to different recipients.
type ConnectorHealthEvent struct {
	EventType             string     `json:"event_type"` // "stale_audit" or "credential_expired"
	ConnectorID           string     `json:"connector_id"`
	WorkspaceID           string     `json:"workspace_id"`
	Provider              string     `json:"provider"`
	ConnectorType         string     `json:"connector_type"`
	Status                string     `json:"status"`
	StaleAudit            bool       `json:"stale_audit"`
	CredentialExpiredTime *time.Time `json:"credential_expired_time,omitempty"`
	LastAuditSyncTime     *time.Time `json:"last_audit_sync_time,omitempty"`
	DetectedAt            time.Time  `json:"detected_at"`
}

// ConnectorHealthWebhookConfig configures the dispatcher. WebhookURL
// is the absolute URL the dispatcher POSTs to; an empty URL turns
// dispatch into a no-op (useful for environments where the operator
// hasn't configured an outbound channel yet). Timeout bounds each
// POST attempt; 0 means "use the default 5s".
type ConnectorHealthWebhookConfig struct {
	WebhookURL string
	Timeout    time.Duration
	// HTTPClient is optional; when nil the dispatcher constructs a
	// new client with Timeout. Tests inject httptest.Server.Client().
	HTTPClient *http.Client
}

// ConnectorHealthWebhookDispatcher fans health events out to the
// configured webhook receiver. Construct via
// NewConnectorHealthWebhookDispatcher.
type ConnectorHealthWebhookDispatcher struct {
	cfg ConnectorHealthWebhookConfig
}

// NewConnectorHealthWebhookDispatcher returns a dispatcher bound to
// cfg. An empty cfg.WebhookURL is permitted — Dispatch becomes a
// no-op in that case so callers don't have to branch on whether
// the operator has configured a destination.
func NewConnectorHealthWebhookDispatcher(cfg ConnectorHealthWebhookConfig) *ConnectorHealthWebhookDispatcher {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &ConnectorHealthWebhookDispatcher{cfg: cfg}
}

// Configured reports whether a webhook URL is set. Health-check
// pipelines short-circuit when this returns false to avoid building
// the event envelope at all.
func (d *ConnectorHealthWebhookDispatcher) Configured() bool {
	return d != nil && d.cfg.WebhookURL != ""
}

// Dispatch POSTs ev to the configured webhook. Returns the response
// status code on success (200..299) and an error otherwise. A nil
// dispatcher or empty webhook URL returns (0, nil) — both are
// documented no-op signals.
func (d *ConnectorHealthWebhookDispatcher) Dispatch(ctx context.Context, ev ConnectorHealthEvent) (int, error) {
	if !d.Configured() {
		return 0, nil
	}
	if ev.EventType == "" {
		return 0, errors.New("connector health webhook: event_type is required")
	}
	if ev.ConnectorID == "" {
		return 0, errors.New("connector health webhook: connector_id is required")
	}
	if ev.DetectedAt.IsZero() {
		ev.DetectedAt = time.Now().UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return 0, fmt.Errorf("connector health webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("connector health webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "shieldnet-access/health-webhook")

	resp, err := d.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("connector health webhook: do: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("connector health webhook: status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// EvaluateAndDispatch checks ev against the health-event rules and
// fires the appropriate notification(s):
//
//   - StaleAudit=true                  → event_type=stale_audit
//   - CredentialExpiredTime <= now      → event_type=credential_expired
//
// Both conditions may trigger simultaneously — they fire as two
// separate POSTs so receivers can deduplicate per event_type.
//
// All POSTs are bounded by ctx. The function returns the count of
// successful dispatches and the first non-retryable error
// encountered. A nil dispatcher / empty webhook URL is a no-op
// (0, nil).
func (d *ConnectorHealthWebhookDispatcher) EvaluateAndDispatch(
	ctx context.Context,
	connectorID, workspaceID, provider, connectorType, status string,
	credentialExpiredTime *time.Time,
	staleAudit bool,
	lastAuditSyncTime *time.Time,
	now time.Time,
) (int, error) {
	if !d.Configured() {
		return 0, nil
	}
	base := ConnectorHealthEvent{
		ConnectorID:           connectorID,
		WorkspaceID:           workspaceID,
		Provider:              provider,
		ConnectorType:         connectorType,
		Status:                status,
		StaleAudit:            staleAudit,
		CredentialExpiredTime: credentialExpiredTime,
		LastAuditSyncTime:     lastAuditSyncTime,
		DetectedAt:            now.UTC(),
	}
	dispatched := 0
	var firstErr error

	if staleAudit {
		ev := base
		ev.EventType = "stale_audit"
		if _, err := d.Dispatch(ctx, ev); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			dispatched++
		}
	}
	if credentialExpiredTime != nil && !credentialExpiredTime.After(now) {
		ev := base
		ev.EventType = "credential_expired"
		if _, err := d.Dispatch(ctx, ev); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			dispatched++
		}
	}
	return dispatched, firstErr
}
