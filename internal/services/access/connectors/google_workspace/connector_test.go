package google_workspace

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// noNetworkRoundTripper fails any HTTP attempt. Used to prove a method does
// not perform network I/O.
type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

// makeServiceAccountKeyJSON builds a synthetic but well-formed service-account
// key JSON. The PEM key is real (so any consumer that JWT-signs against it
// will not crash) but the file points at an invented project / email.
func makeServiceAccountKeyJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(key, t)})

	payload := map[string]interface{}{
		"type":           "service_account",
		"project_id":     "proj-test",
		"private_key_id": "kid-1",
		"private_key":    string(pemBytes),
		"client_email":   "svc@proj-test.iam.gserviceaccount.com",
		"client_id":      "999",
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func pkcs8(k *rsa.PrivateKey, t *testing.T) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return b
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{
		"domain":      "example.com",
		"admin_email": "admin@example.com",
	}
}

func validSecrets(t *testing.T) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"service_account_key": makeServiceAccountKeyJSON(t),
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets(t)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name   string
		cfg    map[string]interface{}
		sec    map[string]interface{}
		wantOK bool
	}{
		{"missing domain", map[string]interface{}{"admin_email": "a@b.com"}, validSecrets(t), false},
		{"bad domain", map[string]interface{}{"domain": "noTLD", "admin_email": "a@b.com"}, validSecrets(t), false},
		{"missing admin", map[string]interface{}{"domain": "example.com"}, validSecrets(t), false},
		{"bad admin", map[string]interface{}{"domain": "example.com", "admin_email": "no-at-sign"}, validSecrets(t), false},
		{"missing key", validConfig(), map[string]interface{}{}, false},
		{"bad key json", validConfig(), map[string]interface{}{"service_account_key": "not-json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Validate(context.Background(), tc.cfg, tc.sec)
			if (err == nil) != tc.wantOK {
				t.Fatalf("Validate(%s) err = %v, wantOK=%v", tc.name, err, tc.wantOK)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })

	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets(t)); err != nil {
		t.Fatalf("Validate hit the network or failed: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*GoogleWorkspaceAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *GoogleWorkspaceAccessConnector", got)
	}
}

func TestStubsReturnErrNotImplemented(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionAccess: got %v, want ErrNotImplemented", err)
	}
	if err := c.RevokeAccess(context.Background(), nil, nil, access.AccessGrant{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeAccess: got %v, want ErrNotImplemented", err)
	}
	if _, err := c.ListEntitlements(context.Background(), nil, nil, "user"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ListEntitlements: got %v, want ErrNotImplemented", err)
	}
}

func TestGetSSOMetadata(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if !strings.HasSuffix(md.MetadataURL, "/.well-known/openid-configuration") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
}

func TestGetCredentialsMetadata_ReturnsKeyID(t *testing.T) {
	c := New()
	got, err := c.GetCredentialsMetadata(context.Background(), nil, validSecrets(t))
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if got["private_key_id"] != "kid-1" {
		t.Fatalf("private_key_id = %v, want kid-1", got["private_key_id"])
	}
	if got["client_email"] != "svc@proj-test.iam.gserviceaccount.com" {
		t.Fatalf("client_email = %v", got["client_email"])
	}
}

// fakeDirectoryClient routes Admin SDK calls to a local httptest server.
type fakeDirectoryClient struct {
	base string
	c    *http.Client
}

func (f *fakeDirectoryClient) Do(req *http.Request) (*http.Response, error) {
	rewritten := f.base + req.URL.Path
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
	return f.c.Do(out)
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageToken") == "" {
			page := directoryUsersPage{
				Users: []directoryUser{
					{ID: "1", PrimaryEmail: "alice@example.com", Suspended: false, Name: struct {
						FullName string `json:"fullName"`
					}{FullName: "Alice"}},
				},
				NextPageToken: "p2",
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		page := directoryUsersPage{
			Users: []directoryUser{
				{ID: "2", PrimaryEmail: "bob@example.com", Suspended: true, Name: struct {
					FullName string `json:"fullName"`
				}{FullName: "Bob"}},
			},
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	var collected []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(t), "", func(batch []*access.Identity, _ string) error {
		collected = append(collected, batch...)
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d, want 2", len(collected))
	}
	if collected[0].DisplayName != "Alice" || collected[0].Status != "active" {
		t.Fatalf("first identity = %+v", collected[0])
	}
	if collected[1].Status != "suspended" {
		t.Fatalf("second status = %q, want suspended", collected[1].Status)
	}
}

// drainBody is a defensive helper to make sure body reads do not leak fds in
// any other tests in this package.
func drainBody(r io.Reader) {
	_, _ = io.Copy(io.Discard, r)
}
