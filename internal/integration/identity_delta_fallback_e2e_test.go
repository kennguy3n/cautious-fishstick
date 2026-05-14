package integration_test

// T27 — IdentityDeltaSyncer hardening regression tests.
//
// These tests wire the real Auth0 and Okta connectors into the
// IdentityDeltaSyncOrchestrator (see
// internal/services/access/identity_delta_orchestrator.go) and pin
// the documented expired-cursor fallback behaviour:
//
//   1. The connector translates the provider-specific expired-cursor
//      response (Auth0: 400 with "log_id … invalid or expired";
//      Okta: 410 Gone with errorCode E0000031) to
//      access.ErrDeltaTokenExpired.
//
//   2. The orchestrator drops the persisted delta-link cursor and
//      falls back to a full SyncIdentities pass; the orchestrator's
//      Run() return-value reports Mode="delta_then_full_fallback".

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/auth0"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
)

// setUnexportedField uses reflect+unsafe to overwrite a private
// connector field (urlOverride / httpClient) from this integration
// test package. The connectors deliberately keep these as package-
// private so production callers can't hot-swap the HTTP transport;
// tests in the connector's own package use them directly. The
// orchestrator's regression tests need the same hook from outside
// the connector package, so we go through reflect.
func setUnexportedField(target interface{}, name string, value interface{}) {
	v := reflect.ValueOf(target).Elem().FieldByName(name)
	if !v.IsValid() {
		panic("integration: no such field: " + name)
	}
	v = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	v.Set(reflect.ValueOf(value))
}

type memDeltaCursorStore struct {
	cursors map[string]string
	setLog  []string
}

func (m *memDeltaCursorStore) Get(_ context.Context, connectorID, kind string) (string, error) {
	return m.cursors[connectorID+"|"+kind], nil
}
func (m *memDeltaCursorStore) Set(_ context.Context, connectorID, kind, deltaLink string) error {
	m.cursors[connectorID+"|"+kind] = deltaLink
	m.setLog = append(m.setLog, deltaLink)
	return nil
}

// TestIdentityDelta_Auth0_ExpiredCursor_FallsBackToFullSync verifies
// the orchestrator's expired-cursor fallback path with the real
// Auth0 connector wired against an httptest.Server.
func TestIdentityDelta_Auth0_ExpiredCursor_FallsBackToFullSync(t *testing.T) {
	var fullSyncHit int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "tok",
				"token_type":   "Bearer",
			})
		case "/api/v2/logs":
			// Auth0 surfaces 400 + "log_id … expired" for an
			// expired cursor.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"statusCode":400,"error":"Bad Request","message":"log_id is invalid or expired"}`))
		case "/api/v2/users":
			fullSyncHit++
			_, _ = w.Write([]byte(`[
				{"user_id":"auth0|u1","email":"a@x.com","name":"A"},
				{"user_id":"auth0|u2","email":"b@x.com","name":"B"}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := auth0.New()
	setUnexportedField(c, "urlOverride", server.URL)

	store := &memDeltaCursorStore{cursors: map[string]string{
		"01HAUTH0CONN|identity": "expired-log-id",
	}}

	cfg := map[string]interface{}{
		"domain":     "uney.auth0.com",
		"identifier": "https://uney.auth0.com/api/v2/",
	}
	secrets := map[string]interface{}{"client_id": "cid", "client_secret": "csec"}

	orch := access.NewIdentityDeltaSyncOrchestrator(store)
	var seen []*access.Identity
	res, err := orch.Run(context.Background(), "01HAUTH0CONN", c, cfg, secrets,
		func(batch []*access.Identity, _ []string) error {
			seen = append(seen, batch...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != "delta_then_full_fallback" {
		t.Fatalf("mode = %q; want delta_then_full_fallback", res.Mode)
	}
	if fullSyncHit == 0 {
		t.Fatal("expected full sync to fire after 400 expired-log-id")
	}
	if len(seen) < 2 {
		t.Errorf("identities = %d; want >= 2", len(seen))
	}
	if got := store.cursors["01HAUTH0CONN|identity"]; got != "" {
		t.Errorf("cursor = %q; want empty after fallback", got)
	}
}

// TestIdentityDelta_Okta_410_FallsBackToFullSync mirrors the Auth0
// test using a 410 Gone from the Okta system-log endpoint.
func TestIdentityDelta_Okta_410_FallsBackToFullSync(t *testing.T) {
	var fullSyncHit int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/logs":
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"errorCode":"E0000031","errorSummary":"Provided since is outside retention"}`))
		case "/api/v1/users":
			fullSyncHit++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[
				{"id":"00u_1","profile":{"login":"a@x.com","email":"a@x.com","firstName":"A","lastName":"x"},"status":"ACTIVE"},
				{"id":"00u_2","profile":{"login":"b@x.com","email":"b@x.com","firstName":"B","lastName":"x"},"status":"ACTIVE"}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := okta.New()
	setUnexportedField(c, "urlOverride", server.URL)

	store := &memDeltaCursorStore{cursors: map[string]string{
		"01HOKTACONN|identity": "https://uney.okta.com/api/v1/logs?since=2020-01-01T00:00:00Z",
	}}

	cfg := map[string]interface{}{"okta_domain": "uney.okta.com"}
	secrets := map[string]interface{}{"api_token": "00testtoken"}

	orch := access.NewIdentityDeltaSyncOrchestrator(store)
	var seen []*access.Identity
	res, err := orch.Run(context.Background(), "01HOKTACONN", c, cfg, secrets,
		func(batch []*access.Identity, _ []string) error {
			seen = append(seen, batch...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != "delta_then_full_fallback" {
		t.Fatalf("mode = %q; want delta_then_full_fallback", res.Mode)
	}
	if fullSyncHit == 0 {
		t.Fatal("expected full sync to fire after 410 Gone")
	}
	if len(seen) < 2 {
		t.Errorf("identities = %d; want >= 2", len(seen))
	}
	if got := store.cursors["01HOKTACONN|identity"]; got != "" {
		t.Errorf("cursor = %q; want empty after fallback", got)
	}
}
