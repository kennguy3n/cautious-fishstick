package duo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"api_hostname": "api-12345678.duosecurity.com"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"integration_key": "DI" + strings.Repeat("X", 18),
		"secret_key":      strings.Repeat("Y", 40),
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
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
		{"missing host", map[string]interface{}{}, validSecrets()},
		{"bad host", map[string]interface{}{"api_hostname": "evil.example.com"}, validSecrets()},
		{"missing ikey", validConfig(), map[string]interface{}{"secret_key": "y"}},
		{"missing skey", validConfig(), map[string]interface{}{"integration_key": "x"}},
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
	if _, ok := got.(*DuoAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *DuoAccessConnector", got)
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

func TestGetSSOMetadata_NilForMFA(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md != nil {
		t.Fatalf("md = %+v, want nil for MFA-only provider", md)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["provider"] != ProviderName {
		t.Fatalf("provider = %v", md["provider"])
	}
	if md["integration_key"] == nil || md["integration_key"] == "" {
		t.Fatalf("integration_key missing: %v", md)
	}
}

func TestSignDuoRequest_DeterministicForFixedInputs(t *testing.T) {
	got := signDuoRequest("GET", "api-XYZ.duosecurity.com", "/admin/v1/users", map[string]string{
		"limit":  "300",
		"offset": "0",
	}, "DI" + strings.Repeat("X", 18), strings.Repeat("Y", 40), "Tue, 21 Aug 2012 17:29:18 -0000")
	if !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("auth header missing Basic prefix: %q", got)
	}
	got2 := signDuoRequest("GET", "API-XYZ.duosecurity.com", "/admin/v1/users", map[string]string{
		"offset": "0",
		"limit":  "300",
	}, "DI" + strings.Repeat("X", 18), strings.Repeat("Y", 40), "Tue, 21 Aug 2012 17:29:18 -0000")
	if got != got2 {
		t.Fatalf("signature must be stable across host case + param ordering\n a=%q\n b=%q", got, got2)
	}
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing Basic auth header")
		}
		if r.URL.Path != "/admin/v1/users" {
			http.NotFound(w, r)
			return
		}
		offset := r.URL.Query().Get("offset")
		w.Header().Set("Content-Type", "application/json")
		if offset == "0" || offset == "" {
			next := 300
			body := duoUsersResponse{
				Stat: "OK",
				Response: []duoUser{
					{UserID: "u1", Username: "alice", Email: "alice@example.com", RealName: "Alice A", Status: "active"},
				},
				Metadata: &duoMetadata{NextOffset: &next},
			}
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		body := duoUsersResponse{
			Stat: "OK",
			Response: []duoUser{
				{UserID: "u2", Username: "bob", Email: "", RealName: "Bob B", Status: "DISABLED"},
			},
			Metadata: &duoMetadata{},
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC) }

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
		t.Fatalf("first email = %q", collected[0].Email)
	}
	if collected[1].Email != "bob" {
		t.Fatalf("second email fallback to username failed: %q", collected[1].Email)
	}
	if collected[1].Status != "disabled" {
		t.Fatalf("second status = %q (lowercased)", collected[1].Status)
	}
}

func TestCountIdentities_ReadsUserCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/info/summary" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"stat":"OK","response":{"user_count":7,"integration_count":3}}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC) }

	n, err := c.CountIdentities(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 7 {
		t.Fatalf("CountIdentities = %d, want 7", n)
	}
}

func TestConnect_ReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"stat":"FAIL","code":40103,"message":"Invalid signature"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC) }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect expected error on 401")
	}
}
