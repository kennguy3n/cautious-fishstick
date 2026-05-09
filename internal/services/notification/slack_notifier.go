package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// SlackBlock is one entry in a Slack Block Kit payload. The wire
// shape is `{"type": "section", "text": {...}}` etc. Only the
// section + mrkdwn block types are needed for the Phase 5
// reviewer / requester rollups; new block types can be added under
// the same struct without breaking existing callers.
type SlackBlock struct {
	Type string         `json:"type"`
	Text *SlackBlockText `json:"text,omitempty"`
}

// SlackBlockText is the text payload nested inside a SlackBlock.
type SlackBlockText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// slackPayload is the wire shape Slack incoming-webhooks accept. The
// `blocks` array is rendered as Block Kit; `text` is a plain-text
// fallback shown in notification previews and in clients without
// Block Kit support.
type slackPayload struct {
	Text   string       `json:"text,omitempty"`
	Blocks []SlackBlock `json:"blocks,omitempty"`
}

// SlackNotifier is the Phase 5 Slack-backed Notifier. Posts a Block
// Kit message to a configured incoming-webhook URL.
//
// Failure semantics: errors from the HTTP POST are logged and
// returned so the NotificationService dispatch loop can surface
// them in PerChannel.Failed; they MUST NOT roll back the caller's
// lifecycle write.
//
// Empty WebhookURL puts the notifier in "log-only mode" — Send
// formats the message, logs it, and returns nil. This matches the
// dev / test posture where Slack is intentionally unconfigured.
type SlackNotifier struct {
	webhookURL string
	httpClient *http.Client
}

// NewSlackNotifier returns a notifier configured to POST to the
// supplied incoming-webhook URL. Pass an empty URL to put the
// notifier in log-only mode. httpClient may be nil — Send falls
// back to a 10s-timeout default.
func NewSlackNotifier(webhookURL string, httpClient *http.Client) *SlackNotifier {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &SlackNotifier{webhookURL: webhookURL, httpClient: httpClient}
}

// Name satisfies Notifier. Returns the stable channel identifier
// surfaced in NotifyResult.PerChannel for observability.
func (s *SlackNotifier) Name() string { return "slack" }

// Send satisfies Notifier. Renders the notification as a Block Kit
// payload and POSTs it to the webhook.
//
// An empty WebhookURL short-circuits to a logged warning so dev /
// test binaries that don't have Slack configured stay healthy. A
// non-2xx response surfaces as an error wrapping the status code
// so the dispatch loop can roll it up into PerChannel.Failed.
func (s *SlackNotifier) Send(ctx context.Context, n Notification) error {
	if s == nil {
		return errors.New("notification: slack: nil notifier")
	}
	if s.webhookURL == "" {
		log.Printf("notification: slack: log-only mode; would post recipient=%s subject=%q", n.RecipientUserID, n.Subject)
		return nil
	}

	payload := s.formatPayload(n)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notification: slack: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("notification: slack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notification: slack: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Bound the body excerpt — Slack returns plain-text
		// error pages on misconfigured webhooks and we don't
		// want the log line ballooning.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notification: slack: post failed: status=%d body=%q", resp.StatusCode, string(body))
	}
	return nil
}

// formatPayload renders the Block Kit envelope for a single
// notification. Keep it simple: a section block with the subject as
// a header, a section block with the body, and the plain-text
// fallback set to the subject so notification previews stay
// readable on mobile.
func (s *SlackNotifier) formatPayload(n Notification) slackPayload {
	return slackPayload{
		Text: n.Subject,
		Blocks: []SlackBlock{
			{
				Type: "section",
				Text: &SlackBlockText{
					Type: "mrkdwn",
					Text: "*" + n.Subject + "*",
				},
			},
			{
				Type: "section",
				Text: &SlackBlockText{
					Type: "mrkdwn",
					Text: n.Body,
				},
			},
		},
	}
}
