package microsoft

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
	page1SignIn := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":                "si-1",
				"createdDateTime":   "2024-01-01T10:00:00Z",
				"userId":            "u-1",
				"userPrincipalName": "u1@corp.example",
				"appDisplayName":    "Office 365",
				"ipAddress":         "203.0.113.1",
				"clientAppUsed":     "Browser",
				"status":            map[string]interface{}{"errorCode": 0},
			},
		},
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/auditLogs/signIns") && !strings.Contains(r.URL.RawQuery, "page=next"):
			page1SignIn["@odata.nextLink"] = server.URL + "/v1.0/auditLogs/signIns?page=next"
			_ = json.NewEncoder(w).Encode(page1SignIn)
		case strings.Contains(r.URL.Path, "/auditLogs/signIns"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                "si-2",
						"createdDateTime":   "2024-01-01T11:00:00Z",
						"userId":            "u-2",
						"userPrincipalName": "u2@corp.example",
						"status":            map[string]interface{}{"errorCode": 50001, "failureReason": "user blocked"},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/auditLogs/directoryAudits"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                  "da-1",
						"activityDateTime":    "2024-01-01T12:00:00Z",
						"activityDisplayName": "Add user",
						"category":            "UserManagement",
						"operationType":       "Add",
						"result":              "success",
						"initiatedBy": map[string]interface{}{
							"user": map[string]interface{}{"id": "admin-1", "userPrincipalName": "admin@corp.example"},
						},
						"targetResources": []map[string]interface{}{
							{"id": "u-99", "type": "User", "displayName": "New User"},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}

	var collected []*access.AuditLogEntry
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var lastCursor time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), since,
		func(batch []*access.AuditLogEntry, nextSince time.Time) error {
			collected = append(collected, batch...)
			lastCursor = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 3 {
		t.Fatalf("expected 3 entries; got %d", len(collected))
	}
	if collected[0].EventType != "signIn" || collected[0].Action != "login" {
		t.Errorf("first entry = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("second entry outcome = %q", collected[1].Outcome)
	}
	if collected[2].EventType != "UserManagement" || collected[2].TargetExternalID != "u-99" {
		t.Errorf("third entry = %+v", collected[2])
	}
	if lastCursor.Before(time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("lastCursor = %v; expected at least 11:00Z", lastCursor)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken"}}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), time.Now().Add(-time.Hour),
		func(_ []*access.AuditLogEntry, _ time.Time) error { return nil })
	if err == nil {
		t.Fatal("expected 401 to propagate as error")
	}
}
