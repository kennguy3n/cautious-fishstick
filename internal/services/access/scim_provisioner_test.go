package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scimMockServer wires an httptest.Server with a hand-rolled
// router that records inbound requests and returns programmable
// responses. The struct exposes the captured request fields so
// tests assert against them after the call.
type scimMockServer struct {
	t        *testing.T
	server   *httptest.Server
	handlers map[string]scimMockResponse
	captured []scimCapturedRequest
}

type scimMockResponse struct {
	status int
	body   string
}

type scimCapturedRequest struct {
	Method     string
	Path       string
	AuthHeader string
	Body       string
}

func newSCIMMockServer(t *testing.T) *scimMockServer {
	t.Helper()
	m := &scimMockServer{
		t:        t,
		handlers: map[string]scimMockResponse{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *scimMockServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.captured = append(m.captured, scimCapturedRequest{
		Method:     r.Method,
		Path:       r.URL.Path,
		AuthHeader: r.Header.Get("Authorization"),
		Body:       string(body),
	})
	key := r.Method + " " + r.URL.Path
	resp, ok := m.handlers[key]
	if !ok {
		// Default to a 2xx empty body so happy-path setup is one
		// line — tests register explicit handlers when they care
		// about the response shape.
		resp = scimMockResponse{status: http.StatusCreated, body: `{"id":"upstream-id"}`}
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(resp.status)
	_, _ = w.Write([]byte(resp.body))
}

func (m *scimMockServer) on(method, path string, status int, body string) {
	m.handlers[method+" "+path] = scimMockResponse{status: status, body: body}
}

func (m *scimMockServer) lastRequest() scimCapturedRequest {
	if len(m.captured) == 0 {
		m.t.Fatalf("no captured requests")
	}
	return m.captured[len(m.captured)-1]
}

// TestSCIMClient_PushSCIMUser_HappyPath asserts a 201 response
// with a JSON-shaped {"id": ...} body returns no error.
func TestSCIMClient_PushSCIMUser_HappyPath(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusCreated, `{"id":"upstream-001"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{scimProvisionerSecretKey: "Bearer alice"}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{
		ExternalID: "ext-001",
		UserName:   "alice@example.com",
		Email:      "alice@example.com",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	got := ms.lastRequest()
	if got.AuthHeader != "Bearer alice" {
		t.Errorf("AuthHeader = %q; want %q", got.AuthHeader, "Bearer alice")
	}
	if !strings.Contains(got.Body, `"externalId":"ext-001"`) {
		t.Errorf("body missing externalId: %s", got.Body)
	}
	if !strings.Contains(got.Body, `"userName":"alice@example.com"`) {
		t.Errorf("body missing userName: %s", got.Body)
	}
}

// TestSCIMClient_PushSCIMUser_Conflict asserts a 409 surfaces as
// ErrSCIMRemoteConflict. JML callers can errors.Is against the
// sentinel and treat it as an idempotent success.
func TestSCIMClient_PushSCIMUser_Conflict(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusConflict, `{"detail":"already exists"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{scimProvisionerSecretKey: "Bearer alice"}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{
		ExternalID: "ext-002",
		UserName:   "bob@example.com",
	})
	if !errors.Is(err, ErrSCIMRemoteConflict) {
		t.Errorf("err = %v; want errors.Is(err, ErrSCIMRemoteConflict)", err)
	}
}

// TestSCIMClient_PushSCIMGroup_HappyPath asserts the group push
// hits /Groups with the expected schema URN and member list.
func TestSCIMClient_PushSCIMGroup_HappyPath(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Groups", http.StatusCreated, `{"id":"grp-001"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	err := client.PushSCIMGroup(context.Background(), cfg, secrets, SCIMGroup{
		ExternalID:  "ext-grp-001",
		DisplayName: "platform-eng",
		MemberIDs:   []string{"u1", "u2"},
	})
	if err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	got := ms.lastRequest()
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(got.Body), &payload); err != nil {
		t.Fatalf("decode group payload: %v\nbody: %s", err, got.Body)
	}
	if payload["displayName"] != "platform-eng" {
		t.Errorf("displayName = %v; want platform-eng", payload["displayName"])
	}
	members, ok := payload["members"].([]interface{})
	if !ok || len(members) != 2 {
		t.Errorf("members = %v; want 2 entries", payload["members"])
	}
}

// TestSCIMClient_DeleteSCIMResource_HappyPath asserts a 204
// response is treated as success and routed to /Users/:id.
func TestSCIMClient_DeleteSCIMResource_HappyPath(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodDelete, "/scim/v2/Users/upstream-001", http.StatusNoContent, "")

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	if err := client.DeleteSCIMResource(context.Background(), cfg, secrets, "Users", "upstream-001"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if got, want := ms.lastRequest().Path, "/scim/v2/Users/upstream-001"; got != want {
		t.Errorf("Path = %q; want %q", got, want)
	}
}

// TestSCIMClient_DeleteSCIMResource_NotFoundIsIdempotent asserts
// that a 404 response is treated as a successful idempotent
// delete (no error returned).
func TestSCIMClient_DeleteSCIMResource_NotFoundIsIdempotent(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodDelete, "/scim/v2/Users/missing", http.StatusNotFound, `{"detail":"not found"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	err := client.DeleteSCIMResource(context.Background(), cfg, secrets, "Users", "missing")
	if err != nil {
		t.Errorf("DeleteSCIMResource(missing): %v; want nil (idempotent delete)", err)
	}
}

// TestSCIMClient_PushSCIMUser_Unauthorized asserts a 401 surfaces
// as ErrSCIMRemoteUnauthorized.
func TestSCIMClient_PushSCIMUser_Unauthorized(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusUnauthorized, `{"detail":"bad token"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{scimProvisionerSecretKey: "Bearer bogus"}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{
		UserName: "x@y.com",
	})
	if !errors.Is(err, ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want errors.Is(err, ErrSCIMRemoteUnauthorized)", err)
	}
}

// TestSCIMClient_PushSCIMUser_ServerError asserts 5xx surfaces as
// ErrSCIMRemoteServer.
func TestSCIMClient_PushSCIMUser_ServerError(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusInternalServerError, `{"detail":"boom"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{UserName: "x"})
	if !errors.Is(err, ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want errors.Is(err, ErrSCIMRemoteServer)", err)
	}
}

// TestSCIMClient_ConfigValidation asserts the (config, secrets)
// shape errors before any HTTP call.
func TestSCIMClient_ConfigValidation(t *testing.T) {
	t.Parallel()
	client := NewSCIMClient()

	cases := []struct {
		name    string
		config  map[string]interface{}
		secrets map[string]interface{}
		op      func(*SCIMClient, map[string]interface{}, map[string]interface{}) error
	}{
		{
			"missing base_url",
			map[string]interface{}{},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.PushSCIMUser(context.Background(), cfg, sec, SCIMUser{UserName: "x"})
			},
		},
		{
			"unparseable timeout",
			map[string]interface{}{
				scimProvisionerConfigKey:  "http://example",
				scimProvisionerTimeoutKey: "not-a-duration",
			},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.PushSCIMUser(context.Background(), cfg, sec, SCIMUser{UserName: "x"})
			},
		},
		{
			"unknown resource type",
			map[string]interface{}{scimProvisionerConfigKey: "http://example"},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.DeleteSCIMResource(context.Background(), cfg, sec, "Widgets", "x")
			},
		},
		{
			"empty external id on delete",
			map[string]interface{}{scimProvisionerConfigKey: "http://example"},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.DeleteSCIMResource(context.Background(), cfg, sec, "Users", "")
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.op(client, tc.config, tc.secrets)
			if !errors.Is(err, ErrSCIMConfigInvalid) {
				t.Errorf("err = %v; want errors.Is(err, ErrSCIMConfigInvalid)", err)
			}
		})
	}
}

// TestSCIMClient_TimeoutOverride asserts that the scim_timeout
// config key is respected (the request fails with deadline
// exceeded against a slow server).
func TestSCIMClient_TimeoutOverride(t *testing.T) {
	t.Parallel()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(slow.Close)

	client := NewSCIMClient().WithHTTPClient(slow.Client())
	cfg := map[string]interface{}{
		scimProvisionerConfigKey:  slow.URL,
		scimProvisionerTimeoutKey: "10ms",
	}
	err := client.PushSCIMUser(context.Background(), cfg, map[string]interface{}{}, SCIMUser{UserName: "x"})
	if err == nil {
		t.Fatalf("PushSCIMUser: want timeout error, got nil")
	}
}
