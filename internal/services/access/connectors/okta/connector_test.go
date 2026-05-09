package okta

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
	return map[string]interface{}{"okta_domain": "uney.okta.com"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "00abcdef"}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_AcceptsCommonOktaTLDs(t *testing.T) {
	c := New()
	cases := []string{
		"foo.okta.com",
		"https://foo.okta.com",
		"https://bar.oktapreview.com/",
		"baz.okta-emea.com",
	}
	for _, d := range cases {
		t.Run(d, func(t *testing.T) {
			cfg := map[string]interface{}{"okta_domain": d}
			if err := c.Validate(context.Background(), cfg, validSecrets()); err != nil {
				t.Fatalf("Validate(%q): %v", d, err)
			}
		})
	}
}

func TestValidate_RejectsMissingFieldsAndBadDomain(t *testing.T) {
	c := New()
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		secrets map[string]interface{}
	}{
		{"missing domain", map[string]interface{}{}, validSecrets()},
		{"bad domain", map[string]interface{}{"okta_domain": "evil.example.com"}, validSecrets()},
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
	if _, ok := got.(*OktaAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *OktaAccessConnector", got)
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

func TestGetSSOMetadata(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if !strings.Contains(md.MetadataURL, "uney.okta.com") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
}

func TestParseNextLink(t *testing.T) {
	header := `<https://uney.okta.com/api/v1/users?after=abc>; rel="next", <https://uney.okta.com/api/v1/users>; rel="self"`
	got := parseNextLink(header)
	if got != "https://uney.okta.com/api/v1/users?after=abc" {
		t.Fatalf("parseNextLink = %q", got)
	}
	if parseNextLink("") != "" {
		t.Fatal("parseNextLink with empty should be empty")
	}
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", `<https://uney.okta.com/api/v1/users?after=p2>; rel="next"`)
			users := []oktaUser{
				{
					ID:     "u1",
					Status: "ACTIVE",
					Profile: struct {
						Login     string `json:"login"`
						Email     string `json:"email"`
						FirstName string `json:"firstName"`
						LastName  string `json:"lastName"`
					}{Login: "alice@example.com", Email: "alice@example.com", FirstName: "Alice"},
				},
			}
			_ = json.NewEncoder(w).Encode(users)
			return
		}
		users := []oktaUser{
			{
				ID:     "u2",
				Status: "DEPROVISIONED",
				Profile: struct {
					Login     string `json:"login"`
					Email     string `json:"email"`
					FirstName string `json:"firstName"`
					LastName  string `json:"lastName"`
				}{Login: "bob@example.com", Email: "bob@example.com", LastName: "Bob"},
			},
		}
		_ = json.NewEncoder(w).Encode(users)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(batch []*access.Identity, _ string) error {
		collected = append(collected, batch...)
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d, want 2", len(collected))
	}
	if collected[0].Email != "alice@example.com" {
		t.Fatalf("first = %+v", collected[0])
	}
	if collected[1].Status != "deprovisioned" {
		t.Fatalf("second status = %q", collected[1].Status)
	}
}

func TestSyncIdentitiesDelta_410ReturnsErrDeltaTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"errorCode":"E0000031"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), server.URL+"/api/v1/logs?since=stale", func(_ []*access.Identity, _ []string, _ string) error {
		return nil
	})
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v, want ErrDeltaTokenExpired", err)
	}
}

func TestSyncIdentitiesDelta_400WithExpiredCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorCode":"E0000031","errorSummary":"since cursor expired"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), server.URL+"/api/v1/logs?since=stale", func(_ []*access.Identity, _ []string, _ string) error {
		return nil
	})
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v, want ErrDeltaTokenExpired", err)
	}
}
