package splunk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userName = "ada"
	const roleName = "power"
	exists := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/services/authentication/users":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "name="+userName) {
				t.Errorf("body = %s", string(body))
			}
			if exists {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"messages":[{"type":"ERROR","text":"User already exists"}]}`))
				return
			}
			exists = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"entry":[{"name":"` + userName + `","content":{"roles":["` + roleName + `"]}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/services/authentication/users/"+userName:
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entry": []map[string]interface{}{{
					"name":    userName,
					"content": map[string]interface{}{"roles": []string{roleName}, "email": "ada@example.com"},
				}},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/services/authentication/users/"+userName:
			exists = false
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	secrets := map[string]interface{}{"token": "tok"}
	cfg := map[string]interface{}{"base_url": srv.URL}
	grant := access.AccessGrant{
		UserExternalID:     userName,
		ResourceExternalID: roleName,
		Scope:              map[string]interface{}{"password": "S3cret!"},
	}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userName)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].Role != roleName {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userName)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{"base_url": srv.URL},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "ada", ResourceExternalID: "power"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
