package quickbooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{}  { return map[string]interface{}{"realm_id": "1234567890"} }
func validSecrets() map[string]interface{} { return map[string]interface{}{"access_token": "qbAAAA1234bbbbCCCC"} }

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing realm_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
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

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth")
		}
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, "FROM Employee") {
			t.Errorf("query = %q", query)
		}
		if calls == 1 {
			emps := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				emps = append(emps, map[string]interface{}{
					"Id":               fmt.Sprintf("%d", i+1),
					"DisplayName":      fmt.Sprintf("Employee %d", i+1),
					"Active":           true,
					"PrimaryEmailAddr": map[string]interface{}{"Address": fmt.Sprintf("e%d@x.com", i+1)},
				})
			}
			b, _ := json.Marshal(map[string]interface{}{
				"QueryResponse": map[string]interface{}{
					"Employee":      emps,
					"startPosition": 1,
					"maxResults":    pageSize,
				},
			})
			_, _ = w.Write(b)
			return
		}
		if !strings.Contains(query, "STARTPOSITION 101") {
			t.Errorf("expected STARTPOSITION 101, got %q", query)
		}
		_, _ = w.Write([]byte(`{"QueryResponse":{"Employee":[{"Id":"999","DisplayName":"Last","Active":false,"PrimaryEmailAddr":{"Address":"last@x.com"}}],"startPosition":101,"maxResults":1}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if got[len(got)-1].Status != "inactive" {
		t.Errorf("expected last inactive")
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("token_short = %q", short)
	}
}

// ---------- Phase 10 advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *QuickBooksAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"Employee":{"Id":"42","SyncToken":"3","Title":""}}`))
		case http.MethodPost:
			b := make([]byte, 256)
			n, _ := r.Body.Read(b)
			posted = string(b[:n])
			_, _ = w.Write([]byte(`{"Employee":{}}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "Admin",
	}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if !strings.Contains(posted, `"Title":"Admin"`) || !strings.Contains(posted, `"sparse":true`) {
		t.Errorf("posted = %q", posted)
	}
}

func TestProvisionAccess_AlreadyHasRoleIdempotent(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"Employee":{"Id":"42","SyncToken":"3","Title":"Admin"}}`))
		case http.MethodPost:
			called = true
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "Admin",
	}); err != nil {
		t.Fatalf("idempotent provision: %v", err)
	}
	if called {
		t.Error("POST should not be called when title already matches")
	}
}

func TestProvisionAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "Admin",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_ClearsTitle(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"Employee":{"Id":"42","SyncToken":"3","Title":"Admin"}}`))
		case http.MethodPost:
			b := make([]byte, 256)
			n, _ := r.Body.Read(b)
			posted = string(b[:n])
			_, _ = w.Write([]byte(`{"Employee":{}}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "Admin",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.Contains(posted, `"Title":""`) {
		t.Errorf("posted = %q", posted)
	}
}

func TestRevokeAccess_NotFoundIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "Admin",
	}); err != nil {
		t.Fatalf("missing employee should be idempotent; got %v", err)
	}
}

func TestListEntitlements_ExtractsTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Employee":{"Id":"42","Title":"Admin"}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "42")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "Admin" {
		t.Fatalf("got = %+v", got)
	}
}

func TestProvisionRevoke_RejectMissing(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "x"}); err == nil {
		t.Error("provision should require user id")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u"}); err == nil {
		t.Error("revoke should require resource id")
	}
}

var _ = json.RawMessage(nil)
var _ = fmt.Sprintf
