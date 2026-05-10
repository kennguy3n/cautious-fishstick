package microsoft

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// noNetworkRoundTripper fails any HTTP attempt with a sentinel error so a
// test can prove a method made zero outbound requests.
type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{
		"tenant_id": "11111111-1111-1111-1111-111111111111",
		"client_id": "22222222-2222-2222-2222-222222222222",
	}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"client_secret": "super-secret",
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
		config  map[string]interface{}
		secrets map[string]interface{}
	}{
		{"missing tenant_id", map[string]interface{}{"client_id": "22222222-2222-2222-2222-222222222222"}, validSecrets()},
		{"missing client_id", map[string]interface{}{"tenant_id": "11111111-1111-1111-1111-111111111111"}, validSecrets()},
		{"missing client_secret", validConfig(), map[string]interface{}{}},
		{"bad tenant uuid", map[string]interface{}{"tenant_id": "not-a-uuid", "client_id": "22222222-2222-2222-2222-222222222222"}, validSecrets()},
		{"bad client uuid", map[string]interface{}{"tenant_id": "11111111-1111-1111-1111-111111111111", "client_id": "not-a-uuid"}, validSecrets()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Validate(context.Background(), tc.config, tc.secrets); err == nil {
				t.Fatalf("Validate(%s) expected error, got nil", tc.name)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	// Inject an HTTP transport that fails every call. Validate must succeed
	// regardless because it is contractually pure-local.
	prevDefault := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prevDefault })

	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate made a network call or failed: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*M365AccessConnector); !ok {
		t.Fatalf("registered type = %T, want *M365AccessConnector", got)
	}
}

func TestProvisionRevokeListEntitlements_RequireGrantFields(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{}); err == nil {
		t.Fatal("ProvisionAccess with empty grant: expected error")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "r"}); err == nil {
		t.Fatal("RevokeAccess without UserExternalID: expected error")
	}
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), ""); err == nil {
		t.Fatal("ListEntitlements without user id: expected error")
	}
}

func TestProvisionAccess_HappyAndIdempotent(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"created", http.StatusCreated},
		{"conflict_idempotent", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen *http.Request
			var seenBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r
				seenBody, _ = io.ReadAll(r.Body)
				if !strings.HasSuffix(r.URL.Path, "/users/u-1/appRoleAssignments") {
					t.Fatalf("path = %q, want .../users/u-1/appRoleAssignments", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(server.Close)

			c := New()
			c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
				return &serverFirstFakeClient{base: server.URL, http: server.Client()}
			}
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID:     "u-1",
				ResourceExternalID: "sp-1",
				Role:               "appRole-A",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seen == nil || seen.Method != http.MethodPost {
				t.Fatalf("expected POST, got %v", seen)
			}
			var body graphAppRoleAssignment
			if err := json.Unmarshal(seenBody, &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.PrincipalID != "u-1" || body.ResourceID != "sp-1" || body.AppRoleID != "appRole-A" {
				t.Fatalf("body = %+v, want principalId/resourceId/appRoleId set", body)
			}
		})
	}
}

func TestProvisionAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied"}}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "sp-1", Role: "appRole-A",
	})
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error %q missing status code", err.Error())
	}
}

func TestRevokeAccess_DeletesMatchingAssignment(t *testing.T) {
	var deletePath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			page := graphAppRoleAssignmentsPage{
				Value: []graphAppRoleAssignment{
					{ID: "a-1", PrincipalID: "u-1", ResourceID: "other", AppRoleID: "x"},
					{ID: "a-2", PrincipalID: "u-1", ResourceID: "sp-1", AppRoleID: "appRole-A"},
				},
			}
			_ = json.NewEncoder(w).Encode(page)
		case http.MethodDelete:
			deletePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "sp-1", Role: "appRole-A",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.HasSuffix(deletePath, "/appRoleAssignments/a-2") {
		t.Fatalf("DELETE path = %q, want it to end with /appRoleAssignments/a-2", deletePath)
	}
}

func TestRevokeAccess_NoMatchingAssignmentIsIdempotent(t *testing.T) {
	deleteCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(graphAppRoleAssignmentsPage{Value: nil})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "missing", Role: "x",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if deleteCalled {
		t.Fatal("DELETE should not be called when no matching assignment")
	}
}

func TestRevokeAccess_404OnDeleteIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			page := graphAppRoleAssignmentsPage{
				Value: []graphAppRoleAssignment{
					{ID: "a-1", PrincipalID: "u-1", ResourceID: "sp-1", AppRoleID: "appRole-A"},
				},
			}
			_ = json.NewEncoder(w).Encode(page)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "sp-1", Role: "appRole-A",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestListEntitlements_PagesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "skiptoken=p2") {
			page := graphAppRoleAssignmentsPage{
				Value: []graphAppRoleAssignment{
					{ID: "a-1", PrincipalID: "u-1", ResourceID: "sp-1", AppRoleID: "role-1"},
				},
				NextLink: server2URL(r) + "?skiptoken=p2",
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		page := graphAppRoleAssignmentsPage{
			Value: []graphAppRoleAssignment{
				{ID: "a-2", PrincipalID: "u-1", ResourceID: "sp-2", AppRoleID: "role-2"},
			},
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entitlements, want 2", len(got))
	}
	if got[0].ResourceExternalID != "sp-1" || got[0].Role != "role-1" || got[0].Source != "direct" {
		t.Fatalf("entitlement[0] = %+v", got[0])
	}
	if got[1].ResourceExternalID != "sp-2" || got[1].Role != "role-2" {
		t.Fatalf("entitlement[1] = %+v", got[1])
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1"); err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestGetSSOMetadata_ReturnsOIDCURL(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q, want oidc", md.Protocol)
	}
	if !strings.Contains(md.MetadataURL, "11111111-1111-1111-1111-111111111111") {
		t.Fatalf("MetadataURL %q missing tenant id", md.MetadataURL)
	}
	if !strings.HasSuffix(md.MetadataURL, "/.well-known/openid-configuration") {
		t.Fatalf("MetadataURL %q must end with the discovery suffix", md.MetadataURL)
	}
}

func TestGetSSOMetadata_RejectsInvalidConfig(t *testing.T) {
	c := New()
	if _, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{}, nil); err == nil {
		t.Fatal("GetSSOMetadata with empty config: expected error")
	}
}

// fakeGraphClient fulfills httpDoer with a hand-rolled responder so the test
// drives SyncIdentities through one full pagination cycle without hitting a
// real graph.microsoft.com.
type fakeGraphClient struct {
	responses []fakeResponse
	idx       int
}

type fakeResponse struct {
	status int
	body   string
}

func (f *fakeGraphClient) Do(_ *http.Request) (*http.Response, error) {
	if f.idx >= len(f.responses) {
		return nil, errors.New("fakeGraphClient: out of canned responses")
	}
	r := f.responses[f.idx]
	f.idx++
	resp := &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}

func TestSyncIdentities_PagesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two-page response cycle.
		if !strings.Contains(r.URL.RawQuery, "skiptoken=p2") {
			page := graphUsersPage{
				Value: []graphUser{
					{ID: "u1", DisplayName: "Alice", Mail: "alice@example.com", AccountEnabled: true},
				},
				NextLink: server2URL(r) + "?skiptoken=p2",
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		page := graphUsersPage{
			Value: []graphUser{
				{ID: "u2", UserPrincipalName: "bob@example.com", AccountEnabled: false},
			},
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}

	var collected []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(batch []*access.Identity, _ string) error {
		collected = append(collected, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d identities, want 2", len(collected))
	}
	if collected[0].Email != "alice@example.com" {
		t.Fatalf("first email = %q, want alice@example.com", collected[0].Email)
	}
	if collected[1].Email != "bob@example.com" {
		t.Fatalf("second email = %q, want bob@example.com", collected[1].Email)
	}
	if collected[1].Status != "disabled" {
		t.Fatalf("disabled user status = %q, want disabled", collected[1].Status)
	}
}

func TestSyncIdentitiesDelta_GoneReturnsErrDeltaTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"error":{"code":"SyncStateNotFound"}}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=stale", func(_ []*access.Identity, _ []string, _ string) error {
		return nil
	})
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got err %v, want access.ErrDeltaTokenExpired", err)
	}
}

func TestExtractRolesFromJWT_HappyAndMalformed(t *testing.T) {
	if _, err := extractRolesFromJWT("not.a.jwt.with.too.many.parts"); err == nil {
		t.Fatal("expected error on malformed JWT")
	}
	if _, err := extractRolesFromJWT(""); err == nil {
		t.Fatal("expected error on empty JWT")
	}

	// Construct a minimal JWT with a roles claim. We do not sign it; we
	// only need parseable shape.
	payloadB64 := "eyJyb2xlcyI6WyJVc2VyLlJlYWQuQWxsIl19" // {"roles":["User.Read.All"]}
	roles, err := extractRolesFromJWT("header." + payloadB64 + ".sig")
	if err != nil {
		t.Fatalf("extractRolesFromJWT: %v", err)
	}
	if len(roles) != 1 || roles[0] != "User.Read.All" {
		t.Fatalf("roles = %v, want [User.Read.All]", roles)
	}
}

// serverFirstFakeClient routes the connector's Graph URLs to a local httptest
// server, but otherwise behaves like the OAuth2 client. It rewrites the host
// of each outgoing request to the test server.
type serverFirstFakeClient struct {
	base string
	http *http.Client
}

func (s *serverFirstFakeClient) Do(req *http.Request) (*http.Response, error) {
	// Rewrite to the test server while preserving the path & query.
	rewritten := s.base + req.URL.Path
	if req.URL.RawQuery != "" {
		rewritten += "?" + req.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(req.Context(), req.Method, rewritten, req.Body)
	if err != nil {
		return nil, err
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	return s.http.Do(out)
}

func server2URL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}
