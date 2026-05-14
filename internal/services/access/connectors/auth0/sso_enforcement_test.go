package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			_, _ = w.Write([]byte(`[{"name":"corp-saml","strategy":"samlp"},{"name":"okta","strategy":"okta"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true (details=%q)", details)
	}
}

func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			_, _ = w.Write([]byte(`[{"name":"corp-saml","strategy":"samlp"},{"name":"Username-Password","strategy":"auth0"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (details=%q)", details)
	}
	if details == "" {
		t.Error("details=\"\"; want a reason")
	}
}

// TestCheckSSOEnforcement_EnabledClientsArrayFixture is the Phase 11 batch 6
// round-4 regression test. Real Auth0 tenants return the `enabled_clients`
// field on every connection as a JSON array of client-ID strings (not a
// bool). A previous revision of the probe declared the field as `*bool`,
// which caused json.Decoder.Decode to raise json.UnmarshalTypeError and the
// caller to map every Auth0 tenant to "unknown" sso-enforcement. This test
// exercises the realistic shape end-to-end so the bug cannot reappear.
func TestCheckSSOEnforcement_EnabledClientsArrayFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			// Mirror the real Auth0 GET /api/v2/connections payload:
			// every connection carries an `enabled_clients` array of
			// client-ID strings, plus assorted metadata fields the
			// probe deliberately ignores.
			_, _ = w.Write([]byte(`[
				{
					"id": "con_1",
					"name": "corp-saml",
					"strategy": "samlp",
					"enabled_clients": ["clientA", "clientB", "clientC"],
					"realms": ["corp-saml"],
					"is_domain_connection": false
				},
				{
					"id": "con_2",
					"name": "okta-prod",
					"strategy": "okta",
					"enabled_clients": ["clientA"],
					"realms": ["okta-prod"],
					"is_domain_connection": false
				}
			]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement decoded the realistic Auth0 fixture with an unexpected error: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true on enterprise-only fixture (details=%q)", details)
	}
}

func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}
