package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// FetchAccessAuditLogs streams Salesforce EventLogFile records into the
// access audit pipeline via the SOQL REST API. Implements
// access.AccessAuditor.
//
// Endpoint (Task 11):
//
//	GET /services/data/v59.0/query?q=SELECT+Id,EventType,LogDate,LogFileLength
//	    +FROM+EventLogFile+WHERE+LogDate+>+{since}
//	    +ORDER+BY+LogDate+ASC
//
// Pagination uses Salesforce's `nextRecordsUrl` field; the handler is
// called per page in chronological LogDate order; `nextSince` is the
// timestamp of the newest LogDate in the batch.
func (c *SalesforceAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	since time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base := c.instanceBase(cfg)

	soql := "SELECT Id,EventType,LogDate,LogFileLength FROM EventLogFile"
	if !since.IsZero() {
		soql += " WHERE LogDate > " + since.UTC().Format(time.RFC3339)
	}
	soql += " ORDER BY LogDate ASC"

	q := url.Values{}
	q.Set("q", soql)
	nextURL := base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()

	cursor := since
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page sfEventLogPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("salesforce: decode event log page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Records))
		batchMax := cursor
		for i := range page.Records {
			entry := mapSalesforceEventLog(&page.Records[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax); err != nil {
			return err
		}
		cursor = batchMax
		next := strings.TrimSpace(page.NextRecordsURL)
		if next == "" {
			return nil
		}
		// nextRecordsUrl is a path relative to the instance host;
		// resolve it through instanceBase so urlOverride works in tests.
		if strings.HasPrefix(next, "/") {
			nextURL = base + next
		} else {
			nextURL = next
		}
	}
	return nil
}

type sfEventLogPage struct {
	Done           bool                `json:"done"`
	TotalSize      int                 `json:"totalSize"`
	NextRecordsURL string              `json:"nextRecordsUrl"`
	Records        []sfEventLogRecord  `json:"records"`
}

type sfEventLogRecord struct {
	Attributes struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"attributes"`
	ID            string `json:"Id"`
	EventType     string `json:"EventType"`
	LogDate       string `json:"LogDate"`
	LogFileLength int64  `json:"LogFileLength"`
}

func mapSalesforceEventLog(r *sfEventLogRecord) *access.AuditLogEntry {
	if r == nil || r.ID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339, r.LogDate)
	return &access.AuditLogEntry{
		EventID:   r.ID,
		EventType: r.EventType,
		Action:    r.EventType,
		Timestamp: ts,
		Outcome:   "success",
		RawData: map[string]interface{}{
			"log_file_length": r.LogFileLength,
			"log_file_url":    r.Attributes.URL,
		},
	}
}

var _ access.AccessAuditor = (*SalesforceAccessConnector)(nil)
