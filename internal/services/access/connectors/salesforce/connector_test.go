package salesforce

import (
	"context"
	"errors"
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

func validConfig() map[string]interface{} {
	return map[string]interface{}{"instance_url": "https://acme.my.salesforce.com"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "00DSF12345aaaa"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing instance_url")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"instance_url": "acme.my.salesforce.com"}, validSecrets()); err == nil {
		t.Error("missing scheme")
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
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{"totalSize":2,"done":false,"nextRecordsUrl":"/services/data/v59.0/query/0r80000000000ABC-2000","records":[{"Id":"u1","Name":"Alice","Email":"a@b.com","IsActive":true}]}`))
			return
		}
		if !strings.Contains(r.URL.Path, "0r80000000000ABC-2000") {
			t.Errorf("unexpected nextRecordsUrl path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"totalSize":2,"done":true,"records":[{"Id":"u2","Name":"Bob","Email":"b@b.com","IsActive":false}]}`))
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
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if page < 2 {
		t.Fatalf("expected pagination, calls = %d", page)
	}
	if got[1].Status != "inactive" {
		t.Errorf("expected u2 inactive, got %q", got[1].Status)
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
	if short == "" || strings.Contains(short, "SF12345") {
		t.Errorf("token_short = %q", short)
	}
}

func TestGetSSOMetadata(t *testing.T) {
	md, err := New().GetSSOMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md == nil || md.Protocol != "saml" {
		t.Fatalf("expected SAML, got %+v", md)
	}
	if !strings.HasSuffix(md.MetadataURL, "/identity/saml/metadata") {
		t.Errorf("metadata URL = %q", md.MetadataURL)
	}
}
