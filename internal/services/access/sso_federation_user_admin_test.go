package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockUserAdminKeycloak embeds mockKeycloakClient and adds the
// Phase 11 user-admin capability. The embedded mock keeps every
// existing test working unchanged.
type mockUserAdminKeycloak struct {
	*mockKeycloakClient
	updateCalls []struct {
		realm  string
		userID string
		patch  map[string]interface{}
	}
	logoutCalls []struct {
		realm  string
		userID string
	}
	updateErr error
	logoutErr error
}

func (m *mockUserAdminKeycloak) UpdateUser(_ context.Context, realm, userID string, patch map[string]interface{}) error {
	m.updateCalls = append(m.updateCalls, struct {
		realm  string
		userID string
		patch  map[string]interface{}
	}{realm, userID, patch})
	return m.updateErr
}

func (m *mockUserAdminKeycloak) LogoutUser(_ context.Context, realm, userID string) error {
	m.logoutCalls = append(m.logoutCalls, struct {
		realm  string
		userID string
	}{realm, userID})
	return m.logoutErr
}

func TestDisableKeycloakUser_DisabledWhenServiceHasNoClient(t *testing.T) {
	svc := NewSSOFederationService(nil)
	if err := svc.DisableKeycloakUser(context.Background(), "acme", "u-1"); !errors.Is(err, ErrSSOFederationDisabled) {
		t.Fatalf("err=%v; want ErrSSOFederationDisabled", err)
	}
}

func TestDisableKeycloakUser_UnsupportedWhenClientLacksUserAdmin(t *testing.T) {
	svc := NewSSOFederationService(newMockKeycloak())
	if err := svc.DisableKeycloakUser(context.Background(), "acme", "u-1"); !errors.Is(err, ErrSSOFederationUnsupported) {
		t.Fatalf("err=%v; want ErrSSOFederationUnsupported", err)
	}
}

func TestDisableKeycloakUser_HappyPath(t *testing.T) {
	admin := &mockUserAdminKeycloak{mockKeycloakClient: newMockKeycloak()}
	svc := NewSSOFederationService(admin)
	if err := svc.DisableKeycloakUser(context.Background(), "acme", "u-1"); err != nil {
		t.Fatalf("DisableKeycloakUser: %v", err)
	}
	if len(admin.updateCalls) != 1 || admin.updateCalls[0].userID != "u-1" {
		t.Errorf("updateCalls=%+v", admin.updateCalls)
	}
	if disabled, _ := admin.updateCalls[0].patch["enabled"].(bool); disabled {
		t.Errorf("patch.enabled=true; want false")
	}
	if len(admin.logoutCalls) != 1 || admin.logoutCalls[0].userID != "u-1" {
		t.Errorf("logoutCalls=%+v", admin.logoutCalls)
	}
}

func TestDisableKeycloakUser_UpdateErrorSurfacesAndSkipsLogout(t *testing.T) {
	admin := &mockUserAdminKeycloak{
		mockKeycloakClient: newMockKeycloak(),
		updateErr:          errors.New("boom"),
	}
	svc := NewSSOFederationService(admin)
	if err := svc.DisableKeycloakUser(context.Background(), "acme", "u-1"); err == nil {
		t.Fatal("err=nil; want non-nil when UpdateUser fails")
	}
	if len(admin.logoutCalls) != 0 {
		t.Errorf("logoutCalls=%d; want 0 when update failed", len(admin.logoutCalls))
	}
}

func TestDisableKeycloakUser_ValidationEmpty(t *testing.T) {
	admin := &mockUserAdminKeycloak{mockKeycloakClient: newMockKeycloak()}
	svc := NewSSOFederationService(admin)
	if err := svc.DisableKeycloakUser(context.Background(), "", "u-1"); err == nil {
		t.Error("err=nil for empty realm")
	}
	if err := svc.DisableKeycloakUser(context.Background(), "acme", ""); err == nil {
		t.Error("err=nil for empty userID")
	}
}

// TestHTTPKeycloakClient_UpdateAndLogout exercises the real
// HTTPKeycloakClient against an httptest.Server: PUT /users/{id}
// then POST /users/{id}/logout. 404 must be treated as idempotent.
func TestHTTPKeycloakClient_UpdateAndLogout(t *testing.T) {
	var putCount, logoutCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/users/u-1"):
			putCount++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/users/u-1/logout"):
			logoutCount++
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/users/missing"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/users/missing/logout"):
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := NewHTTPKeycloakClient(srv.URL, func(_ context.Context) (string, error) { return "t", nil })
	if err := client.UpdateUser(context.Background(), "acme", "u-1", map[string]interface{}{"enabled": false}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if err := client.LogoutUser(context.Background(), "acme", "u-1"); err != nil {
		t.Fatalf("LogoutUser: %v", err)
	}
	if putCount != 1 || logoutCount != 1 {
		t.Errorf("putCount=%d logoutCount=%d", putCount, logoutCount)
	}
	if err := client.UpdateUser(context.Background(), "acme", "missing", map[string]interface{}{"enabled": false}); err != nil {
		t.Errorf("404 on UpdateUser should be idempotent: %v", err)
	}
	if err := client.LogoutUser(context.Background(), "acme", "missing"); err != nil {
		t.Errorf("404 on LogoutUser should be idempotent: %v", err)
	}
}
