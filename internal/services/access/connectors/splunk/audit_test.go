package splunk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func splunkAuditConfig(base string) map[string]interface{} {
	return map[string]interface{}{"base_url": base}
}
func splunkAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "splunk.token"}
}

func TestSplunkFetchAccessAuditLogs_MapsAndPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/audit/events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		body := map[string]interface{}{
			"paging": map[string]interface{}{"total": 1, "offset": 0},
			"entry": []map[string]interface{}{
				{
					"name":      "audit-event-1",
					"published": "2024-05-01T10:00:00Z",
					"content": map[string]interface{}{
						"action":      "login",
						"object":      "alice",
						"object_type": "user",
						"user":        "alice",
						"_time":       "2024-05-01T10:00:00Z",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), splunkAuditConfig(srv.URL), splunkAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].ActorExternalID != "alice" || collected[0].TargetType != "user" {
		t.Errorf("entry = %+v", collected[0])
	}
	want := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)
	if !nextSince.Equal(want) {
		t.Errorf("nextSince = %s, want %s", nextSince, want)
	}
}

func TestSplunkFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), splunkAuditConfig(srv.URL), splunkAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestSplunkFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), splunkAuditConfig(srv.URL), splunkAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
