package ga4

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func ga4ValidConfig() map[string]interface{} {
	return map[string]interface{}{"account": "1234567"}
}
func ga4ValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "ga4_demo_token"}
}

// TestGA4ConnectorFlow_FullLifecycle locks in the Phase 10 contract: the
// caller addresses a GA4 admin entirely by the user's email address (the
// same value that ProvisionAccess sends as `emailAddress` and that
// SyncIdentities surfaces as Identity.ExternalID). RevokeAccess and
// ListEntitlements resolve email → resource name client-side via
// /v1beta/accounts/{account}/userLinks pagination before issuing the
// per-resource DELETE / GET. The mock fakes that flow exactly.
func TestGA4ConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const userLinkID = "u_alice"
	const role = "predefinedRoles/admin"
	const resourceName = "accounts/1234567/userLinks/" + userLinkID

	var mu sync.Mutex
	state := "" // "" = absent, role = present
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("authorization header missing")
		}
		listPath := "/v1beta/accounts/1234567/userLinks"
		resourcePath := "/v1beta/" + resourceName
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == listPath:
			body, _ := io.ReadAll(r.Body)
			var payload map[string]interface{}
			_ = json.Unmarshal(body, &payload)
			if got, _ := payload["emailAddress"].(string); got != email {
				t.Errorf("emailAddress = %q, want %q", got, email)
			}
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"status":"ALREADY_EXISTS"}}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["` + role + `"]}`))
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			if state == "" {
				_, _ = w.Write([]byte(`{"userLinks":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"userLinks":[{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["` + state + `"]}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == resourcePath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := ga4ValidConfig()
	secrets := ga4ValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, role)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

// TestGA4ConnectorFlow_RevokeAcceptsResourceName confirms that callers
// addressing the userLink by its full resource name (as exposed by
// SyncIdentities via Identity.RawData["name"]) still resolve correctly
// through the same list+filter helper.
func TestGA4ConnectorFlow_RevokeAcceptsResourceName(t *testing.T) {
	const email = "bob@example.com"
	const userLinkID = "u_bob"
	const role = "predefinedRoles/viewer"
	const resourceName = "accounts/1234567/userLinks/" + userLinkID

	var mu sync.Mutex
	present := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1beta/accounts/1234567/userLinks":
			if !present {
				_, _ = w.Write([]byte(`{"userLinks":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"userLinks":[{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["` + role + `"]}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1beta/"+resourceName:
			present = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: resourceName, ResourceExternalID: role}
	if err := c.RevokeAccess(context.Background(), ga4ValidConfig(), ga4ValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess by resource name: %v", err)
	}
	if present {
		t.Fatalf("expected DELETE to clear state")
	}
}

func TestGA4ConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		ga4ValidConfig(), ga4ValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "predefinedRoles/admin"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
