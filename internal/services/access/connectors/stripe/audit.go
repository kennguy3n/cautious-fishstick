package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// FetchAccessAuditLogs streams Stripe `/v1/events` records into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/events?limit=100&created[gte]={epoch}&starting_after={id}
//
// Stripe's event log is the closest public surface to an audit feed —
// every API and dashboard mutation emits an event. Pagination uses the
// canonical `starting_after` cursor with the last record's id; `has_more`
// terminates the loop. The handler is invoked once per page in
// chronological order so callers can persist `nextSince` as a monotonic
// cursor. Restricted keys without `rak_read_only` on Events surface as
// 401/403 → access.ErrAuditNotAvailable.
func (c *StripeAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	startingAfter := ""
	base := c.baseURL()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(pageSize))
		if !since.IsZero() {
			q.Set("created[gte]", strconv.FormatInt(since.UTC().Unix(), 10))
		}
		if startingAfter != "" {
			q.Set("starting_after", startingAfter)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"/v1/events?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("stripe: audit events: %w", err)
		}
		body, readErr := readStripeBody(resp)
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("stripe: audit events: status %d: %s", resp.StatusCode, string(body))
		}
		var page stripeEventPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("stripe: decode events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		lastID := ""
		for i := range page.Data {
			entry := mapStripeEvent(&page.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
			lastID = page.Data[i].ID
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		if !page.HasMore || lastID == "" {
			return nil
		}
		startingAfter = lastID
	}
}

type stripeEventPage struct {
	Object  string        `json:"object"`
	HasMore bool          `json:"has_more"`
	Data    []stripeEvent `json:"data"`
}

type stripeEvent struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Created    int64           `json:"created"`
	APIVersion string          `json:"api_version"`
	Account    string          `json:"account"`
	Data       json.RawMessage `json:"data"`
	Request    struct {
		ID             string `json:"id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"request"`
}

func mapStripeEvent(e *stripeEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	if e.Created <= 0 {
		return nil
	}
	ts := time.Unix(e.Created, 0).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         e.ID,
		EventType:       strings.TrimSpace(e.Type),
		Action:          stripeAction(e.Type),
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(e.Account),
		TargetExternalID: strings.TrimSpace(e.Request.ID),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

func stripeAction(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	// Stripe event types are dotted: "customer.created", "account.updated".
	// Surface the trailing verb for quick classification.
	if i := strings.LastIndex(t, "."); i >= 0 && i+1 < len(t) {
		return t[i+1:]
	}
	return t
}

func readStripeBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("stripe: empty response")
	}
	defer resp.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= max {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

var _ access.AccessAuditor = (*StripeAccessConnector)(nil)
