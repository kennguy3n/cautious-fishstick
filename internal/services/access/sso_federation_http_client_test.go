package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPKeycloakClient_CreateGetUpdateDelete exercises the production
// HTTPKeycloakClient against an httptest.Server that mocks the
// Keycloak Admin REST API. No live Keycloak instance is required.
func TestHTTPKeycloakClient_CreateGetUpdateDelete(t *testing.T) {
	const realm = "shieldnet"
	const alias = "acme"

	created := false
	updated := false
	deleted := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("expected Bearer auth; got %q", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/"+realm+"/identity-providers/instances":
			created = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/"+realm+"/identity-providers/instances/"+alias:
			if !created {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(KeycloakIdentityProvider{
				Alias:      alias,
				ProviderID: "oidc",
				Enabled:    true,
				Config:     map[string]string{"issuer": "https://idp.example"},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/"+realm+"/identity-providers/instances/"+alias:
			updated = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/admin/realms/"+realm+"/identity-providers/instances/"+alias:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	tokenCount := 0
	client := NewHTTPKeycloakClient(srv.URL, func(_ context.Context) (string, error) {
		tokenCount++
		return "test-token", nil
	})

	// First Get: 404.
	if _, err := client.GetIdentityProvider(context.Background(), realm, alias); !errors.Is(err, ErrKeycloakIdPNotFound) {
		t.Fatalf("first Get: want ErrKeycloakIdPNotFound; got %v", err)
	}

	idp := KeycloakIdentityProvider{
		Alias:      alias,
		ProviderID: "oidc",
		Enabled:    true,
		Config:     map[string]string{"issuer": "https://idp.example"},
	}
	if err := client.CreateIdentityProvider(context.Background(), realm, idp); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := client.GetIdentityProvider(context.Background(), realm, alias)
	if err != nil {
		t.Fatalf("Get after create: %v", err)
	}
	if got.Alias != alias || got.ProviderID != "oidc" {
		t.Fatalf("Get returned %#v", got)
	}

	if err := client.UpdateIdentityProvider(context.Background(), realm, alias, idp); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := client.DeleteIdentityProvider(context.Background(), realm, alias); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if !created || !updated || !deleted {
		t.Errorf("flags: created=%v updated=%v deleted=%v", created, updated, deleted)
	}
	if tokenCount < 4 {
		t.Errorf("token provider called %d times; expected at least 4", tokenCount)
	}
}

func TestHTTPKeycloakClient_RejectsMissingBaseURL(t *testing.T) {
	client := &HTTPKeycloakClient{Token: func(_ context.Context) (string, error) { return "t", nil }}
	if err := client.CreateIdentityProvider(context.Background(), "r", KeycloakIdentityProvider{Alias: "a"}); err == nil {
		t.Fatal("expected error for missing base URL")
	}
}

func TestHTTPKeycloakClient_PropagatesTokenError(t *testing.T) {
	client := NewHTTPKeycloakClient("https://keycloak.example", func(_ context.Context) (string, error) {
		return "", errors.New("token denied")
	})
	if err := client.CreateIdentityProvider(context.Background(), "r", KeycloakIdentityProvider{Alias: "a"}); err == nil {
		t.Fatal("expected token error to propagate")
	}
}

func TestHTTPKeycloakClient_DeleteSwallowsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	client := NewHTTPKeycloakClient(srv.URL, func(_ context.Context) (string, error) { return "t", nil })
	if err := client.DeleteIdentityProvider(context.Background(), "r", "a"); err != nil {
		t.Fatalf("Delete of missing IdP should succeed; got %v", err)
	}
}

func TestHTTPKeycloakClient_PropagatesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	t.Cleanup(srv.Close)
	client := NewHTTPKeycloakClient(srv.URL, func(_ context.Context) (string, error) { return "t", nil })
	err := client.CreateIdentityProvider(context.Background(), "r", KeycloakIdentityProvider{Alias: "a"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error; got %v", err)
	}
}
