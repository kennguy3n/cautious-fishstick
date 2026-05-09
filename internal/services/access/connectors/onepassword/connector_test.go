package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"account_url": "https://uney.1password.com"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"scim_bridge_token": "scim-bearer-token"}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_AcceptsServiceAccountToken(t *testing.T) {
	c := New()
	secrets := map[string]interface{}{"service_account_token": "ops_service_token"}
	if err := c.Validate(context.Background(), validConfig(), secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		secrets map[string]interface{}
	}{
		{"missing account_url", map[string]interface{}{}, validSecrets()},
		{"bad account_url", map[string]interface{}{"account_url": "not a url"}, validSecrets()},
		{"non-http account_url", map[string]interface{}{"account_url": "ftp://uney.1password.com"}, validSecrets()},
		{"missing token", validConfig(), map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Validate(context.Background(), tc.cfg, tc.secrets); err == nil {
				t.Fatalf("Validate(%s) expected error", tc.name)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })

	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*OnePasswordAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *OnePasswordAccessConnector", got)
	}
}

func TestStubsReturnErrNotImplemented(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionAccess: got %v", err)
	}
	if err := c.RevokeAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeAccess: got %v", err)
	}
	if _, err := c.ListEntitlements(context.Background(), nil, nil, "user"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ListEntitlements: got %v", err)
	}
}

func TestGetSSOMetadata_NilForVault(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md != nil {
		t.Fatalf("md = %+v, want nil for vault", md)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["provider"] != ProviderName {
		t.Fatalf("provider = %v", md["provider"])
	}
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer scim-bearer-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/scim/v2/Users" {
			http.NotFound(w, r)
			return
		}
		startIndex := r.URL.Query().Get("startIndex")
		w.Header().Set("Content-Type", "application/scim+json")
		if startIndex == "1" || startIndex == "" {
			body := scimListResponse{
				Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
				TotalResults: 3,
				StartIndex:   1,
				ItemsPerPage: 2,
				Resources: []scimUser{
					{ID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Active: true,
						Emails: []scimEmail{{Value: "alice@example.com", Primary: true}}},
					{ID: "u2", UserName: "bob@example.com", DisplayName: "Bob", Active: false},
				},
			}
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		body := scimListResponse{
			Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			TotalResults: 3,
			StartIndex:   3,
			ItemsPerPage: 1,
			Resources: []scimUser{
				{ID: "u3", UserName: "carol@example.com", DisplayName: "Carol", Active: true},
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	cfg := map[string]interface{}{"account_url": server.URL}
	var collected []*access.Identity
	if err := c.SyncIdentities(context.Background(), cfg, validSecrets(), "", func(batch []*access.Identity, _ string) error {
		collected = append(collected, batch...)
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(collected) != 3 {
		t.Fatalf("collected %d, want 3", len(collected))
	}
	if collected[0].Email != "alice@example.com" {
		t.Fatalf("first email = %q", collected[0].Email)
	}
	if collected[1].Status != "disabled" {
		t.Fatalf("second status = %q", collected[1].Status)
	}
}

func TestCountIdentities_ReadsTotalResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults": 17, "Resources": []}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	cfg := map[string]interface{}{"account_url": server.URL}
	n, err := c.CountIdentities(context.Background(), cfg, validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 17 {
		t.Fatalf("CountIdentities = %d, want 17", n)
	}
}

func TestConnect_ReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"invalid token"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	cfg := map[string]interface{}{"account_url": server.URL}
	if err := c.Connect(context.Background(), cfg, validSecrets()); err == nil {
		t.Fatal("Connect expected error on 401")
	}
}

func TestVerifyPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults":0,"Resources":[]}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	cfg := map[string]interface{}{"account_url": server.URL}
	missing, err := c.VerifyPermissions(context.Background(), cfg, validSecrets(), []string{"sync_identity", "list_entitlements"})
	if err != nil {
		t.Fatalf("VerifyPermissions: %v", err)
	}
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "list_entitlements") {
		t.Fatalf("missing = %v", missing)
	}
}
