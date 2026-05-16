package slack_enterprise

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func slackEntSSOConfig() map[string]interface{} { return map[string]interface{}{} }
func slackEntSSOSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "xoxp-token"}
}

func TestSlackEnterprise_CheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/team.info") {
			t.Errorf("path=%q; want suffix /api/team.info", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer xoxp-token" {
			t.Errorf("auth=%q; want Bearer xoxp-token", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"team":{"sso_provider":{"type":"saml"}},"enterprise":{"is_sso_enabled":true}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), slackEntSSOConfig(), slackEntSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Fatalf("enforced=false; want true (details=%q)", details)
	}
}

func TestSlackEnterprise_CheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"team":{"sso_provider":{"type":""}},"enterprise":{"is_sso_enabled":false}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), slackEntSSOConfig(), slackEntSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Fatal("enforced=true; want false")
	}
}

func TestSlackEnterprise_CheckSSOEnforcement_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"not_authed"}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), slackEntSSOConfig(), slackEntSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on api error")
	}
}

func TestSlackEnterprise_CheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), slackEntSSOConfig(), slackEntSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestSlackEnterprise_SatisfiesSSOEnforcementCheckerInterface(t *testing.T) {
	var _ interface {
		CheckSSOEnforcement(context.Context, map[string]interface{}, map[string]interface{}) (bool, string, error)
	} = New()
}
