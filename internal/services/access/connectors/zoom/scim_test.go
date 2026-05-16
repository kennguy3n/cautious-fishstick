package zoom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

type scimRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newZoomSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, scimRoundtrip{
			Method: r.Method,
			Path:   r.URL.Path,
			Auth:   r.Header.Get("Authorization"),
			Body:   string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func zoomSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"account_id": "acct-1"}
}

func zoomSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"client_id": "cid", "client_secret": "csec"}
}

func withZoomSCIMTestServer(t *testing.T, srv *httptest.Server) *ZoomAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	// short-circuit OAuth token minting so the SCIM tests don't need
	// to mock the /oauth/token endpoint as well.
	conn.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "zoom-access-token", nil
	}
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestZoomConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZoomSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withZoomSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), zoomSCIMConfig(), zoomSCIMSecrets(), access.SCIMUser{
		ExternalID:  "u1",
		UserName:    "alice@example.com",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	if !strings.HasSuffix(captured[0].Path, "/scim2/Users") {
		t.Errorf("path = %q; want suffix /scim2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer zoom-access-token" {
		t.Errorf("auth = %q; want Bearer zoom-access-token", captured[0].Auth)
	}
}

func TestZoomConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZoomSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withZoomSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), zoomSCIMConfig(), zoomSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"u1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim2/Groups") {
		t.Errorf("path = %q; want suffix /scim2/Groups", captured[0].Path)
	}
}

func TestZoomConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZoomSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withZoomSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), zoomSCIMConfig(), zoomSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestZoomConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZoomSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withZoomSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), zoomSCIMConfig(), zoomSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestZoomConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZoomSCIMTestServer(t, http.StatusBadGateway, &captured)
	conn := withZoomSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), zoomSCIMConfig(), zoomSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestZoomConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZoomSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withZoomSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), zoomSCIMConfig(), zoomSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestZoomConnector_PushSCIMUser_MissingAccountSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), map[string]interface{}{}, zoomSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-account error")
	}
}

func TestZoomConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
