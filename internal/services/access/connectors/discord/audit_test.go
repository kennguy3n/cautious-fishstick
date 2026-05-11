package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// snowflake builds a Discord snowflake whose timestamp is at the
// supplied UTC instant.
func snowflake(ts time.Time) string {
	ms := ts.UTC().UnixMilli() - discordEpochMs
	if ms < 0 {
		ms = 0
	}
	return fmt.Sprintf("%d", uint64(ms)<<22)
}

func TestDiscordFetchAccessAuditLogs_MapsAndFiltersBySince(t *testing.T) {
	older := snowflake(time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC))
	newer := snowflake(time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/audit-logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bot ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"audit_log_entries": []map[string]interface{}{
				{"id": newer, "user_id": "user-1", "target_id": "tgt-1", "action_type": 20},
				{"id": older, "user_id": "user-2", "target_id": "tgt-2", "action_type": 50},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	since := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d; want 1 (older entry must be filtered by since)", len(collected))
	}
	if collected[0].EventType != "member_change" {
		t.Errorf("event_type = %s; want member_change", collected[0].EventType)
	}
	if !lastSince.After(since) {
		t.Errorf("lastSince = %s; want > since", lastSince)
	}
}

func TestDiscordFetchAccessAuditLogs_NotAvailableOnForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestDiscordFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil non-ErrAuditNotAvailable", err)
	}
}
