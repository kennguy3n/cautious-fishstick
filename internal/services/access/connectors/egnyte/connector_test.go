package egnyte

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

func validConfig() map[string]interface{}  { return map[string]interface{}{"domain": "acme"} }
func validSecrets() map[string]interface{} { return map[string]interface{}{"access_token": "egnyAAAA1234bbbbCCCC"} }

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing domain")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

func TestValidate_RejectsInvalidDomain(t *testing.T) {
	c := New()
	for _, bad := range []string{"acme.example", "acme/evil", "acme egnyte", "-acme", "acme-"} {
		if err := c.Validate(context.Background(), map[string]interface{}{"domain": bad}, validSecrets()); err == nil {
			t.Errorf("expected error for domain %q", bad)
		}
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
		if r.URL.Path != "/pubapi/v2/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		startIndex := r.URL.Query().Get("startIndex")
		if calls == 1 && startIndex != "1" {
			t.Errorf("startIndex = %q", startIndex)
		}
		if calls == 2 && startIndex != fmt.Sprintf("%d", 1+pageSize) {
			t.Errorf("startIndex = %q", startIndex)
		}
		if calls == 1 {
			res := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				res = append(res, map[string]interface{}{
					"id":       i + 1,
					"userName": fmt.Sprintf("user%d", i+1),
					"active":   true,
					"name":     map[string]interface{}{"givenName": "User", "familyName": fmt.Sprintf("%d", i+1)},
					"emails":   []map[string]interface{}{{"value": fmt.Sprintf("u%d@x.com", i+1), "primary": true}},
				})
			}
			b, _ := json.Marshal(map[string]interface{}{
				"totalResults": pageSize + 1,
				"itemsPerPage": pageSize,
				"startIndex":   1,
				"resources":    res,
			})
			_, _ = w.Write(b)
			return
		}
		b, _ := json.Marshal(map[string]interface{}{
			"totalResults": pageSize + 1,
			"itemsPerPage": pageSize,
			"startIndex":   1 + pageSize,
			"resources": []map[string]interface{}{
				{"id": 999, "userName": "last", "active": false,
					"name":   map[string]interface{}{"givenName": "Last", "familyName": "User"},
					"emails": []map[string]interface{}{{"value": "last@x.com", "primary": true}}},
			},
		})
		_, _ = w.Write(b)
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
		t.Errorf("last status = %q; want inactive", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v; want 403", err)
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
