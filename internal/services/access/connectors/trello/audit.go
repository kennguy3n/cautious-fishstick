package trello

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// FetchAccessAuditLogs streams Trello organization-action events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /1/organizations/{id}/actions?since={ts}&before={id}&limit=50
//
// Trello surfaces audit-style events through the generic /actions feed.
// Pagination is reverse-chronological with a `before={id}` cursor; the
// handler is invoked once per page with the chronologically advancing
// `nextSince` so callers can persist the monotonic cursor between runs.
// Tenants whose token is not a Workspace admin receive 401/403 which
// collapses to access.ErrAuditNotAvailable so the worker soft-skips
// the tenant rather than looping.
func (c *TrelloAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	before := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "50")
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		if before != "" {
			q.Set("before", before)
		}
		path := "/organizations/" + url.PathEscape(cfg.OrganizationID) + "/actions"
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path, q)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("trello: actions: status %d: %s", resp.StatusCode, string(body))
		}
		var actions []trelloAction
		if err := json.Unmarshal(body, &actions); err != nil {
			return fmt.Errorf("trello: decode actions: %w", err)
		}
		// Trello returns newest-first; reverse so the batch is
		// chronological and the cursor advances monotonically.
		reversed := make([]trelloAction, 0, len(actions))
		for i := len(actions) - 1; i >= 0; i-- {
			reversed = append(reversed, actions[i])
		}
		batch := make([]*access.AuditLogEntry, 0, len(reversed))
		batchMax := cursor
		for i := range reversed {
			entry := mapTrelloAction(&reversed[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		if len(actions) < 50 {
			return nil
		}
		// `actions[len-1]` is the oldest in this page; use its id as
		// the `before` cursor so the next call returns even older
		// actions. (Reverse-chronological pagination.)
		before = actions[len(actions)-1].ID
	}
}

type trelloAction struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Date            string                 `json:"date"`
	IDMemberCreator string                 `json:"idMemberCreator"`
	MemberCreator   trelloAuditMember      `json:"memberCreator"`
	Data            map[string]interface{} `json:"data,omitempty"`
}

type trelloAuditMember struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
	FullName string `json:"fullName,omitempty"`
}

func mapTrelloAction(a *trelloAction) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ID) == "" {
		return nil
	}
	ts := parseTrelloTime(a.Date)
	var targetID, targetType string
	if a.Data != nil {
		if card, ok := a.Data["card"].(map[string]interface{}); ok {
			if id, ok := card["id"].(string); ok && id != "" {
				targetID = id
				targetType = "card"
			}
		}
		if targetID == "" {
			if board, ok := a.Data["board"].(map[string]interface{}); ok {
				if id, ok := board["id"].(string); ok && id != "" {
					targetID = id
					targetType = "board"
				}
			}
		}
		if targetID == "" {
			if mem, ok := a.Data["member"].(map[string]interface{}); ok {
				if id, ok := mem["id"].(string); ok && id != "" {
					targetID = id
					targetType = "member"
				}
			}
		}
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(a)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          a.ID,
		EventType:        strings.TrimSpace(a.Type),
		Action:           strings.TrimSpace(a.Type),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.IDMemberCreator),
		TargetExternalID: targetID,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseTrelloTime parses Trello's action.date timestamps. Trello emits
// RFC3339 with millisecond precision; older payloads omit fractions.
func parseTrelloTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*TrelloAccessConnector)(nil)
