package ping_identity

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
	calls := 0
	var nextHref string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/"+testEnvID+"/as/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"Bearer"}`))
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/environments/") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("missing bearer auth: %q", got)
		}
		calls++
		if calls == 1 {
			nextHref = "http://" + r.Host + "/v1/environments/" + testEnvID + "/activities?cursor=p2"
			_ = json.NewEncoder(w).Encode(pingActivitiesPage{
				Embedded: struct {
					Activities []pingActivity `json:"activities"`
				}{
					Activities: []pingActivity{
						{
							ID:         "a1",
							RecordedAt: "2024-10-01T08:00:00.000Z",
							Action: struct {
								Type   string `json:"type"`
								Result struct {
									Status string `json:"status"`
								} `json:"result"`
							}{Type: "USER.AUTHENTICATION", Result: struct {
								Status string `json:"status"`
							}{Status: "SUCCESS"}},
							Actors: struct {
								User struct {
									ID       string `json:"id"`
									Username string `json:"username"`
								} `json:"user"`
								Client struct {
									IP        string `json:"ip"`
									UserAgent string `json:"user_agent"`
								} `json:"client"`
							}{User: struct {
								ID       string `json:"id"`
								Username string `json:"username"`
							}{ID: "u1", Username: "alice@example.com"}},
						},
					},
				},
				Links: struct {
					Next struct {
						Href string `json:"href"`
					} `json:"next"`
				}{Next: struct {
					Href string `json:"href"`
				}{Href: nextHref}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(pingActivitiesPage{
			Embedded: struct {
				Activities []pingActivity `json:"activities"`
			}{
				Activities: []pingActivity{
					{
						ID:         "a2",
						RecordedAt: "2024-10-01T09:00:00Z",
						Action: struct {
							Type   string `json:"type"`
							Result struct {
								Status string `json:"status"`
							} `json:"result"`
						}{Type: "USER.PASSWORD_RESET", Result: struct {
							Status string `json:"status"`
						}{Status: "FAILED"}},
					},
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != 2 {
		t.Errorf("activity calls = %d; want 2", calls)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2", len(collected))
	}
	if collected[0].ActorEmail != "alice@example.com" || collected[0].Outcome != "success" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 Outcome = %q; want failure", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+testEnvID+"/as/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"Bearer"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+testEnvID+"/as/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"Bearer"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected provider error")
	}
	if err == access.ErrAuditNotAvailable {
		t.Fatalf("err = ErrAuditNotAvailable; want generic error")
	}
}
