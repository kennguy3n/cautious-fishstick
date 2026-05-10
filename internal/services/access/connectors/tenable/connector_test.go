package tenable

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

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_key": "tnAAAA1234bbbbCCCC",
		"secret_key": "tnDDDD5678eeeeFFFF",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing keys")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"access_key": "ak"}); err == nil {
		t.Error("missing secret_key")
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
		if got := r.Header.Get("X-ApiKeys"); !strings.Contains(got, "accessKey=") || !strings.Contains(got, ";secretKey=") {
			t.Errorf("X-ApiKeys = %q", got)
		}
		offset := r.URL.Query().Get("offset")
		body := map[string]interface{}{}
		var arr []map[string]interface{}
		if calls == 1 {
			if offset != "0" {
				t.Errorf("offset = %q", offset)
			}
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"id":      i,
					"uuid":    fmt.Sprintf("u-%d", i),
					"name":    fmt.Sprintf("U%d", i),
					"email":   fmt.Sprintf("u%d@x.com", i),
					"enabled": i%2 == 0,
				})
			}
		} else {
			if offset != fmt.Sprintf("%d", pageSize) {
				t.Errorf("offset = %q", offset)
			}
			arr = []map[string]interface{}{{"id": 999, "uuid": "u-last", "name": "Last", "email": "last@x.com", "enabled": true}}
		}
		body["users"] = arr
		b, _ := json.Marshal(body)
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
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	disabled := 0
	for _, id := range got {
		if id.Status == "disabled" {
			disabled++
		}
	}
	if disabled == 0 {
		t.Errorf("expected at least one disabled user from enabled=false")
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	ak, _ := md["access_key_short"].(string)
	sk, _ := md["secret_key_short"].(string)
	if !strings.Contains(ak, "...") || strings.Contains(ak, "AAAA1234") {
		t.Errorf("ak redaction failed: %q", ak)
	}
	if !strings.Contains(sk, "...") || strings.Contains(sk, "DDDD5678") {
		t.Errorf("sk redaction failed: %q", sk)
	}
}
