package okta

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
	var nextLink string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("page") == "" {
			nextLink = "<" + "https://corp.okta.com" + r.URL.Path + "?page=2>; rel=\"next\""
			w.Header().Set("Link", nextLink)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"uuid":      "e-1",
					"published": "2024-01-01T10:00:00Z",
					"eventType": "user.session.start",
					"actor":     map[string]interface{}{"id": "u-1", "alternateId": "alice@example.com"},
					"outcome":   map[string]interface{}{"result": "SUCCESS"},
					"client":    map[string]interface{}{"ipAddress": "203.0.113.1"},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"uuid":      "e-2",
				"published": "2024-01-01T11:00:00Z",
				"eventType": "user.session.end",
				"actor":     map[string]interface{}{"id": "u-2", "alternateId": "bob@example.com"},
				"outcome":   map[string]interface{}{"result": "FAILURE"},
				"target":    []map[string]interface{}{{"id": "app-1", "type": "AppInstance"}},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].Outcome != "success" || collected[0].IPAddress != "203.0.113.1" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" || collected[1].TargetExternalID != "app-1" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected 401 error")
	}
}
