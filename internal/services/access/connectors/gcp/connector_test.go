package gcp

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

const fakeServiceAccountJSON = `{
  "type": "service_account",
  "project_id": "uney-prod",
  "private_key_id": "key-1",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
  "client_email": "ztna@uney-prod.iam.gserviceaccount.com",
  "client_id": "12345"
}`

func validConfig() map[string]interface{} { return map[string]interface{}{"project_id": "uney-prod"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"service_account_json": fakeServiceAccountJSON}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMalformedKey(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{"service_account_json": "{}"}); err == nil {
		t.Error("missing private_key marker: want error")
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
		_, _ = w.Write([]byte(`{"projectId":"uney-prod","name":"projects/uney-prod"}`))
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

func TestSync_FlattensIamPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, ":getIamPolicy") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"bindings":[
			{"role":"roles/owner","members":["user:alice@uney.com","serviceAccount:bot@uney.iam.gserviceaccount.com"]},
			{"role":"roles/viewer","members":["user:alice@uney.com","group:eng@uney.com","domain:partner.com"]}
		]}`))
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
	if len(got) != 3 {
		t.Fatalf("len = %d; want 3 (alice, bot, group eng); got = %+v", len(got), got)
	}
	types := map[access.IdentityType]int{}
	for _, id := range got {
		types[id.Type]++
	}
	if types[access.IdentityTypeServiceAccount] != 1 || types[access.IdentityTypeGroup] != 1 || types[access.IdentityTypeUser] != 1 {
		t.Errorf("type counts = %+v", types)
	}
}

func TestGetCredentialsMetadata_ExtractsClientEmail(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md["client_email"] != "ztna@uney-prod.iam.gserviceaccount.com" {
		t.Errorf("client_email = %v", md["client_email"])
	}
}
