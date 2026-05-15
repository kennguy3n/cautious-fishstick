//go:build integration

// sso_federation_service_integration_test.go — drives the
// ConfigureBroker → HTTPKeycloakClient → REST surface end-to-end
// against an httptest.NewServer faux-Keycloak.
//
// The non-integration sso_federation_service_test.go file already
// covers the matrix of SAML / OIDC paths against an in-memory
// KeycloakClient mock. This integration variant exercises the real
// HTTP marshaling code path — request body shape, URL escaping, the
// 404→ErrKeycloakIdPNotFound conversion, and the "PUT on existing,
// POST on missing" idempotency branch.
//
// Keeping this file behind the integration build tag means the
// extra ~300ms of network round-trip stays out of the unit-test
// hot path while still being part of `make test-integration` /
// the integration-test CI workflow.
package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fauxKeycloak is the minimal HTTP surface ConfigureBroker drives.
// State is held in memory; calls are recorded so tests can assert
// "first call → POST, second call → PUT".
type fauxKeycloak struct {
	mu       sync.Mutex
	idps     map[string]map[string]KeycloakIdentityProvider
	calls    []string
	wantAuth string
}

// requireBearer is the assertion every Keycloak admin call must
// carry the configured bearer token. Test infrastructure helper —
// per Go test style we mark t.Helper so the failure points at the
// caller.
func (f *fauxKeycloak) requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	got := r.Header.Get("Authorization")
	if got != "Bearer "+f.wantAuth {
		t.Errorf("Authorization header = %q; want %q", got, "Bearer "+f.wantAuth)
	}
}

func (f *fauxKeycloak) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requireBearer(t, r)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)

		// Parse /admin/realms/{realm}/identity-providers/instances[/{alias}]
		path := strings.TrimPrefix(r.URL.Path, "/admin/realms/")
		parts := strings.SplitN(path, "/", 4)
		if len(parts) < 3 || parts[1] != "identity-providers" {
			http.NotFound(w, r)
			return
		}
		realm := parts[0]
		var alias string
		if len(parts) == 4 {
			alias = parts[3]
		}

		switch r.Method {
		case http.MethodGet:
			idp, ok := f.idps[realm][alias]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(idp)
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var idp KeycloakIdentityProvider
			if err := json.Unmarshal(body, &idp); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if f.idps[realm] == nil {
				f.idps[realm] = map[string]KeycloakIdentityProvider{}
			}
			f.idps[realm][idp.Alias] = idp
			w.WriteHeader(http.StatusCreated)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var idp KeycloakIdentityProvider
			if err := json.Unmarshal(body, &idp); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, ok := f.idps[realm][alias]; !ok {
				http.NotFound(w, r)
				return
			}
			f.idps[realm][alias] = idp
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if _, ok := f.idps[realm][alias]; !ok {
				http.NotFound(w, r)
				return
			}
			delete(f.idps[realm], alias)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// newFauxKeycloak spins up the in-memory Keycloak and returns a
// (server, client, faux) triple for the test to drive.
func newFauxKeycloak(t *testing.T) (*httptest.Server, *HTTPKeycloakClient, *fauxKeycloak) {
	t.Helper()
	f := &fauxKeycloak{idps: map[string]map[string]KeycloakIdentityProvider{}, wantAuth: "test-token"}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	client := NewHTTPKeycloakClient(srv.URL, func(_ context.Context) (string, error) {
		return f.wantAuth, nil
	})
	return srv, client, f
}

// TestIntegration_ConfigureBroker_CreatesThenUpdates exercises the
// real HTTP create-then-update idempotency branch end-to-end:
//   - First ConfigureBroker call → POST to the create endpoint.
//   - Second call with the same (realm, alias) → PUT to the update endpoint.
//
// Asserts both the call ordering and that the persisted IdP matches
// the supplied metadata.
func TestIntegration_ConfigureBroker_CreatesThenUpdates(t *testing.T) {
	_, client, faux := newFauxKeycloak(t)
	svc := NewSSOFederationService(client)

	meta := &SSOMetadata{
		Protocol:    "oidc",
		EntityID:    "https://idp.example.com",
		MetadataURL: "https://idp.example.com/.well-known/openid-configuration",
		SSOLoginURL: "https://idp.example.com/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "workspace-a", "alias-1", "Alias One", meta); err != nil {
		t.Fatalf("first ConfigureBroker: %v", err)
	}
	// Update with a rotated metadata URL — must hit PUT, not POST again.
	meta.MetadataURL = "https://idp.example.com/.well-known/openid-configuration-rotated"
	if _, _, err := svc.ConfigureBroker(context.Background(), "workspace-a", "alias-1", "Alias One", meta); err != nil {
		t.Fatalf("second ConfigureBroker: %v", err)
	}

	faux.mu.Lock()
	defer faux.mu.Unlock()
	wantPrefix := []string{
		"GET /admin/realms/workspace-a/identity-providers/instances/alias-1",
		"POST /admin/realms/workspace-a/identity-providers/instances",
		"GET /admin/realms/workspace-a/identity-providers/instances/alias-1",
		"PUT /admin/realms/workspace-a/identity-providers/instances/alias-1",
	}
	if len(faux.calls) != len(wantPrefix) {
		t.Fatalf("call sequence = %v; want %v", faux.calls, wantPrefix)
	}
	for i, want := range wantPrefix {
		if faux.calls[i] != want {
			t.Errorf("calls[%d] = %q; want %q", i, faux.calls[i], want)
		}
	}
	got := faux.idps["workspace-a"]["alias-1"]
	if got.Config["metadataUrl"] != "https://idp.example.com/.well-known/openid-configuration-rotated" {
		t.Errorf("idp.Config.metadataUrl = %q; want rotated URL", got.Config["metadataUrl"])
	}
	if got.ProviderID != "oidc" {
		t.Errorf("idp.ProviderID = %q; want %q", got.ProviderID, "oidc")
	}
}

// TestIntegration_ConfigureBroker_UnsupportedWithoutMetadata is the
// service-layer contract for connectors that do not advertise SSO:
// ConfigureBroker(nil metadata) → ErrSSOFederationUnsupported. The
// integration variant asserts this contract is preserved when the
// real HTTPKeycloakClient is wired (the unit test exercises the
// same path against the in-memory mock).
func TestIntegration_ConfigureBroker_UnsupportedWithoutMetadata(t *testing.T) {
	_, client, _ := newFauxKeycloak(t)
	svc := NewSSOFederationService(client)
	_, _, err := svc.ConfigureBroker(context.Background(), "ws", "alias", "", nil)
	if err != ErrSSOFederationUnsupported {
		t.Fatalf("err = %v; want ErrSSOFederationUnsupported", err)
	}
}

// TestIntegration_DeleteBroker_RemovesIdP exercises the DELETE
// path against the faux server.
func TestIntegration_DeleteBroker_RemovesIdP(t *testing.T) {
	_, client, faux := newFauxKeycloak(t)
	svc := NewSSOFederationService(client)

	meta := &SSOMetadata{
		Protocol:            "saml",
		EntityID:            "https://idp.example.com/saml",
		SSOLoginURL:         "https://idp.example.com/saml/sso",
		SigningCertificates: []string{"MIIC..."},
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "ws", "alias-del", "Del", meta); err != nil {
		t.Fatalf("seed ConfigureBroker: %v", err)
	}
	if _, ok := faux.idps["ws"]["alias-del"]; !ok {
		t.Fatalf("IdP not seeded by ConfigureBroker")
	}
	if err := svc.DeleteBroker(context.Background(), "ws", "alias-del"); err != nil {
		t.Fatalf("DeleteBroker: %v", err)
	}
	if _, ok := faux.idps["ws"]["alias-del"]; ok {
		t.Fatalf("IdP still present after DeleteBroker")
	}
}
