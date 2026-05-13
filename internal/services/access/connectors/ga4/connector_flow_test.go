package ga4

import (
	"context"
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

func TestGA4ConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "u_alice"
	const email = "alice@example.com"
	const role = "predefinedRoles/admin"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("authorization header missing")
		}
		userLinksPath := "/v1beta/accounts/1234567/userLinks"
		userPath := userLinksPath + "/" + userID
		emailPath := userLinksPath + "/" + email
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == userLinksPath:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"status":"ALREADY_EXISTS"}}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"accounts/1234567/userLinks/` + userID + `","emailAddress":"` + email + `","directRoles":["` + role + `"]}`))
		case r.Method == http.MethodDelete && (r.URL.Path == userPath || r.URL.Path == emailPath):
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && (r.URL.Path == userPath || r.URL.Path == emailPath):
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"name":"accounts/1234567/userLinks/` + userID + `","emailAddress":"` + email + `","directRoles":["` + state + `"]}`))
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
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, role)
	}
	revokeGrant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: role}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, revokeGrant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
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
