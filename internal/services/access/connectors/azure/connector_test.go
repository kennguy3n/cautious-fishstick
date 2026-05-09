package azure

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"tenant_id": "tenant-1", "subscription_id": "sub-1"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"client_id": "id-12345678", "client_secret": "secret-1234567890"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{"tenant_id": "x"}, validSecrets()); err == nil {
		t.Error("missing subscription_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing secrets")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestConnect_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v", err)
	}
}

func TestSync_DecodesUsersAndPaginates(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			next := "/users?$skiptoken=NEXT"
			_, _ = w.Write([]byte(`{"value":[{"id":"u1","displayName":"Alice","userPrincipalName":"alice@uney.com","mail":"alice@uney.com","accountEnabled":true}],"@odata.nextLink":"` + r.Header.Get("X-Server-URL") + next + `"}`))
			// Caller will resync from path with "/users?$skiptoken=NEXT" — strip happens server-side.
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"u2","displayName":"Bob","userPrincipalName":"bob@uney.com","accountEnabled":false}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) < 1 || got[0].DisplayName != "Alice" {
		t.Fatalf("got = %+v", got)
	}
}

func TestCount_ParsesPlainInt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/users/$count") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`42`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	n, err := c.CountIdentities(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 42 {
		t.Errorf("count = %d; want 42", n)
	}
}

func TestGetCredentialsMetadata_NoNetwork(t *testing.T) {
	c := New()
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "", errors.New("disabled")
	}
	c.urlOverride = "http://127.0.0.1:1"
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["tenant_id"] != "tenant-1" {
		t.Errorf("tenant_id = %v", md["tenant_id"])
	}
}

// TestGetCredentialsMetadata_PicksEarliestExpiry guards against a regression
// where the earliest-expiry search would silently emit an empty
// client_secret_expires_at if the first PasswordCredential happened to have
// an empty EndDateTime (a non-expiring credential). Microsoft Graph does
// not guarantee ordering of passwordCredentials, so this scenario is
// reachable in production whenever an app has a non-expiring + expiring
// credential pair.
func TestGetCredentialsMetadata_PicksEarliestExpiry(t *testing.T) {
	cases := []struct {
		name            string
		applicationsResp string
		want            string // empty => field must be absent
	}{
		{
			name: "first credential has empty endDateTime",
			applicationsResp: `{"value":[{"passwordCredentials":[
				{"endDateTime":"","displayName":"perpetual"},
				{"endDateTime":"2030-01-01T00:00:00Z","displayName":"later"},
				{"endDateTime":"2027-06-15T00:00:00Z","displayName":"earlier"}
			]}]}`,
			want: "2027-06-15T00:00:00Z",
		},
		{
			name: "all credentials have empty endDateTime",
			applicationsResp: `{"value":[{"passwordCredentials":[
				{"endDateTime":"","displayName":"a"},
				{"endDateTime":"","displayName":"b"}
			]}]}`,
			want: "",
		},
		{
			name: "single expiring credential",
			applicationsResp: `{"value":[{"passwordCredentials":[
				{"endDateTime":"2028-12-31T23:59:59Z","displayName":"only"}
			]}]}`,
			want: "2028-12-31T23:59:59Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/applications") {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.applicationsResp))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
			md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
			if err != nil {
				t.Fatalf("GetCredentialsMetadata: %v", err)
			}
			got, present := md["client_secret_expires_at"]
			if tc.want == "" {
				if present {
					t.Errorf("client_secret_expires_at = %v; want field absent", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("client_secret_expires_at = %v; want %q", got, tc.want)
			}
		})
	}
}

// TestGetCredentialsMetadata_EscapesClientIDInFilter guards against an OData
// filter-injection regression where a client_id containing a single quote
// would break out of the OData string literal in the $filter. The fix
// doubles single quotes per OData rules and URL-encodes the literal, so the
// embedded value remains a valid OData string and the underlying request
// path is well-formed.
func TestGetCredentialsMetadata_EscapesClientIDInFilter(t *testing.T) {
	const evilClientID = "abc' or 1 eq 1 or '1' eq '1"
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	secrets := map[string]interface{}{"client_id": evilClientID, "client_secret": "secret-1234567890"}
	if _, err := c.GetCredentialsMetadata(context.Background(), validConfig(), secrets); err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	// Server-side decoded query must contain the original value with single
	// quotes doubled, and never the unescaped raw value.
	q, err := url.ParseQuery(captured)
	if err != nil {
		t.Fatalf("parse query %q: %v", captured, err)
	}
	got := q.Get("$filter")
	wantDoubled := "abc'' or 1 eq 1 or ''1'' eq ''1"
	wantFilter := "appId eq '" + wantDoubled + "'"
	if got != wantFilter {
		t.Errorf("$filter = %q; want %q", got, wantFilter)
	}
	// The decoded literal must start and end with a single quote and have
	// every embedded quote doubled, so the OData parser treats the entire
	// payload as one string and never re-enters operator context.
	if !strings.HasPrefix(got, "appId eq '") || !strings.HasSuffix(got, "'") {
		t.Errorf("$filter is not bounded by single quotes: %q", got)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "appId eq '"), "'")
	for i := 0; i < len(inner); i++ {
		if inner[i] != '\'' {
			continue
		}
		if i+1 >= len(inner) || inner[i+1] != '\'' {
			t.Errorf("unescaped single quote at position %d in %q", i, inner)
			break
		}
		i++ // skip the paired quote
	}
}
