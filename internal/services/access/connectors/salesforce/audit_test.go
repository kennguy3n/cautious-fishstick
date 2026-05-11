package salesforce

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/services/data/v59.0/query") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"done":           false,
				"totalSize":      2,
				"nextRecordsUrl": "/services/data/v59.0/query/01g000-2000",
				"records": []map[string]interface{}{
					{
						"attributes": map[string]interface{}{"type": "EventLogFile", "url": "/services/data/v59.0/sobjects/EventLogFile/0AT1"},
						"Id":         "0AT1",
						"EventType":  "Login",
						"LogDate":    "2024-01-01T10:00:00.000+0000",
					},
				},
			})
		case 1:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"done":      true,
				"totalSize": 2,
				"records": []map[string]interface{}{
					{
						"attributes": map[string]interface{}{"type": "EventLogFile"},
						"Id":         "0AT2",
						"EventType":  "Logout",
						"LogDate":    "2024-01-01T11:00:00.000+0000",
					},
				},
			})
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		func(batch []*access.AuditLogEntry, _ time.Time) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].EventType != "Login" || collected[1].EventType != "Logout" {
		t.Errorf("event types = %s, %s", collected[0].EventType, collected[1].EventType)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), time.Now().Add(-time.Hour),
		func(_ []*access.AuditLogEntry, _ time.Time) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}
