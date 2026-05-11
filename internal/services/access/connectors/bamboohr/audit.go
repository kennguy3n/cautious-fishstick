package bamboohr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// FetchAccessAuditLogs streams BambooHR employee-change events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/employees/changed?since={RFC3339}&type=all
//
// BambooHR returns the full delta in one response (no cursor), so we
// emit a single page. Each `employees` map entry surfaces as one
// AuditLogEntry whose action mirrors the change type ("Inserted",
// "Updated", "Deleted") and whose timestamp is the `lastChanged`
// value. Tenants whose plan doesn't expose the changed endpoint return
// 403/404 which collapses to access.ErrAuditNotAvailable.
func (c *BambooHRAccessConnector) FetchAccessAuditLogs(
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
	if since.IsZero() {
		// BambooHR's /employees/changed requires a `since` parameter.
		// Default to 7 days ago to seed the first backfill — the worker
		// will advance the cursor monotonically thereafter.
		since = time.Now().Add(-7 * 24 * time.Hour)
	}

	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("type", "all")
	fullURL := c.baseURL(cfg) + "/v1/employees/changed?" + q.Encode()

	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("bamboohr: audit changed: %w", err)
	}
	body, readErr := readBambooResponse(resp)
	if readErr != nil {
		return readErr
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bamboohr: audit changed: status %d: %s", resp.StatusCode, string(body))
	}

	var page bambooChangedPage
	if err := json.Unmarshal(body, &page); err != nil {
		return fmt.Errorf("bamboohr: decode changed: %w", err)
	}

	type kv struct {
		EmployeeID string
		Change     bambooChangedEmployee
	}
	pairs := make([]kv, 0, len(page.Employees))
	for id, change := range page.Employees {
		change.EmployeeID = id
		pairs = append(pairs, kv{EmployeeID: id, Change: change})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return parseBambooTime(pairs[i].Change.LastChanged).Before(parseBambooTime(pairs[j].Change.LastChanged))
	})

	batch := make([]*access.AuditLogEntry, 0, len(pairs))
	batchMax := since
	for i := range pairs {
		entry := mapBambooChangedEvent(&pairs[i].Change)
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
	return nil
}

type bambooChangedPage struct {
	Employees map[string]bambooChangedEmployee `json:"employees"`
}

type bambooChangedEmployee struct {
	EmployeeID  string `json:"-"`
	Action      string `json:"action"`
	LastChanged string `json:"lastChanged"`
}

func mapBambooChangedEvent(c *bambooChangedEmployee) *access.AuditLogEntry {
	if c == nil || strings.TrimSpace(c.EmployeeID) == "" {
		return nil
	}
	ts := parseBambooTime(c.LastChanged)
	action := strings.ToLower(strings.TrimSpace(c.Action))
	if action == "" {
		action = "updated"
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%s:%s", c.EmployeeID, c.LastChanged),
		EventType:        "employee." + action,
		Action:           action,
		Timestamp:        ts,
		TargetExternalID: c.EmployeeID,
		TargetType:       "employee",
		Outcome:          "success",
	}
}

// parseBambooTime parses BambooHR's lastChanged timestamps, trying
// RFC3339Nano first (with fractional seconds) and falling back to
// plain RFC3339. The API has been observed to emit both shapes.
func parseBambooTime(s string) time.Time {
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

func readBambooResponse(resp *http.Response) ([]byte, error) {
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

var _ access.AccessAuditor = (*BambooHRAccessConnector)(nil)
