package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestK8sListener_EndToEnd_RecordsAndCapturesCommands wires the
// real K8sListener against an in-process fake K8s API server, then
// drives an exec session through it and asserts that:
//   - the recorded replay blob contains both directions of I/O,
//   - the command sink received one row per typed command, in order,
//   - the upstream request was made against the right URL with the
//     injected service-account token in the Authorization header,
//   - the gateway forwards the channel-prefixed framing untouched in
//     both directions (kubectl wire-compat).
func TestK8sListener_EndToEnd_RecordsAndCapturesCommands(t *testing.T) {
	t.Parallel()

	upstream := newFakeK8sAPI(t)
	defer upstream.Close()

	const (
		sessionID    = "01HXYE2EQR8K4PAMZJ4N7N9X7K"
		workspaceID  = "ws-1"
		connectToken = "k8s-connect-token"
		saToken      = "sa-token-xyz"
		namespace    = "payments"
		pod          = "payments-7d4c8f-abc"
		container    = "app"
	)

	authz := &fakeSessionAuthorizer{
		session: AuthorizedSession{
			SessionID:   sessionID,
			WorkspaceID: workspaceID,
			LeaseID:     "lease-k8s-1",
			AssetID:     "asset-cluster-1",
			AccountID:   "acct-k8s-1",
			Protocol:    "k8s",
		},
		expectedToken: connectToken,
	}
	injectedPayload, err := json.Marshal(map[string]any{
		"server":               upstream.URL(),
		"token":                saToken,
		"insecure_skip_verify": true,
	})
	if err != nil {
		t.Fatalf("marshal injected payload: %v", err)
	}
	injector := &fakeSecretInjector{secretType: "k8s_token", secret: injectedPayload}
	replayStore := NewMemoryReplayStore()
	commandSink := NewMemoryCommandSink()

	gw := startK8sListener(t, K8sListenerConfig{
		Authorizer:  authz,
		Injector:    injector,
		ReplayStore: replayStore,
		CommandSink: commandSink,
	})
	defer gw.cancel()

	// Dial the gateway as if we were kubectl.
	gwURL := gw.wsURL("/api/v1/namespaces/"+namespace+"/pods/"+pod+"/exec",
		url.Values{
			"command":   {"/bin/bash"},
			"container": {container},
			"stdin":     {"true"},
			"stdout":    {"true"},
			"stderr":    {"true"},
		},
	)
	hdr := http.Header{"Authorization": []string{"Bearer " + connectToken}}
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 5 * time.Second
	dialer.Subprotocols = []string{k8sSubprotocolV4Channel}
	conn, resp, err := dialer.Dial(gwURL, hdr)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial gateway: status=%d err=%v", resp.StatusCode, err)
		}
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	// Send two commands as stdin and interleave reads with writes.
	// Pipelining both stdin frames at once would let cmd2's
	// newline reach the parser before cmd1's output echo, so cmd1
	// would land in the sink with an empty OutputHash. That race
	// is a real CommandParser limitation we'll address in
	// Milestone 6+ for pty sessions; the happy-path test instead
	// exercises a properly-interleaved exchange (which is also
	// what a real kubectl invocation does — humans don't pipeline
	// commands without waiting for output).
	readStdoutContains := func(want string) string {
		t.Helper()
		var rx strings.Builder
		deadline := time.Now().Add(3 * time.Second)
		for rx.Len() < 1024 && time.Now().Before(deadline) {
			if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				t.Fatalf("set read deadline: %v", err)
			}
			_, payload, err := conn.ReadMessage()
			if err != nil {
				// Read deadline triggers a "i/o timeout" — that's
				// fine, we just loop and check the buffer.
				if strings.Contains(err.Error(), "timeout") {
					if strings.Contains(rx.String(), want) {
						return rx.String()
					}
					continue
				}
				t.Fatalf("read stdout while waiting for %q: rx=%q err=%v", want, rx.String(), err)
			}
			if len(payload) >= 1 && payload[0] == k8sChanStdout {
				rx.Write(payload[1:])
				if strings.Contains(rx.String(), want) {
					return rx.String()
				}
			}
		}
		t.Fatalf("timed out waiting for %q on stdout; rx=%q", want, rx.String())
		return rx.String()
	}

	cmds := []string{"uptime\n", "whoami\n"}
	for _, c := range cmds {
		frame := append([]byte{k8sChanStdin}, []byte(c)...)
		if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			t.Fatalf("write stdin frame %q: %v", c, err)
		}
		// Wait until the echo lands before sending the next command
		// so the parser sees each command's output before the next
		// newline closes it.
		readStdoutContains(strings.TrimRight(c, "\n"))
	}

	// Close cleanly so the gateway's proxy goroutines tear down
	// and Close() flushes the recorder + parser.
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
	_ = conn.Close()

	// Wait for the listener to finish flushing the replay + audit
	// rows. We poll instead of sleeping so the test stays fast on
	// fast machines.
	flushDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(flushDeadline) {
		if blob, ok := replayStore.Get(sessionID); ok && len(blob) > 0 {
			if len(commandSink.Commands()) >= 2 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Recorder assertions: blob is present under the canonical
	// key, decodes to a sequence of frames with both directions
	// represented, and the input frames carry the bytes we typed.
	blob, ok := replayStore.Get(sessionID)
	if !ok {
		t.Fatalf("replay blob not found under sessionID=%s; keys=%v", sessionID, replayStore.Keys())
	}
	if len(blob) == 0 {
		t.Fatalf("replay blob is empty")
	}
	frames, err := DecodeFrames(blob)
	if err != nil {
		t.Fatalf("DecodeFrames: %v", err)
	}
	var sawInput, sawOutput bool
	var inputCollected strings.Builder
	for _, f := range frames {
		switch f.Direction {
		case DirectionInput:
			sawInput = true
			inputCollected.Write(f.Payload)
		case DirectionOutput:
			sawOutput = true
		}
	}
	if !sawInput {
		t.Errorf("no DirectionInput frames in replay; frames=%d", len(frames))
	}
	if !sawOutput {
		t.Errorf("no DirectionOutput frames in replay; frames=%d", len(frames))
	}
	if !strings.Contains(inputCollected.String(), "uptime") || !strings.Contains(inputCollected.String(), "whoami") {
		t.Errorf("recorded input %q does not contain both commands", inputCollected.String())
	}

	// Command sink assertions: one row per typed command, in
	// order, with non-empty SHA-256 output hashes.
	rows := commandSink.Commands()
	if len(rows) < 2 {
		t.Fatalf("commandSink rows = %d, want >= 2", len(rows))
	}
	for i, want := range []string{"uptime", "whoami"} {
		if rows[i].Input != want {
			t.Errorf("rows[%d].Input = %q, want %q", i, rows[i].Input, want)
		}
		if rows[i].Sequence != i+1 {
			t.Errorf("rows[%d].Sequence = %d, want %d", i, rows[i].Sequence, i+1)
		}
		if rows[i].OutputHash == "" {
			t.Errorf("rows[%d].OutputHash empty — output bytes never fed to parser", i)
		}
		if rows[i].SessionID != sessionID {
			t.Errorf("rows[%d].SessionID = %q, want %q", i, rows[i].SessionID, sessionID)
		}
	}

	// Upstream-side assertions: the gateway hit the canonical
	// exec URL with the injected SA token in the Authorization
	// header. The namespace, pod, container, and command query
	// params all survived the proxy.
	gotReq := upstream.LastRequest()
	if gotReq == nil {
		t.Fatalf("fake upstream received no requests")
	}
	if gotReq.Authorization != "Bearer "+saToken {
		t.Errorf("upstream Authorization = %q, want %q", gotReq.Authorization, "Bearer "+saToken)
	}
	if gotReq.URL.Path != "/api/v1/namespaces/"+namespace+"/pods/"+pod+"/exec" {
		t.Errorf("upstream path = %q", gotReq.URL.Path)
	}
	if got, want := gotReq.URL.Query().Get("container"), container; got != want {
		t.Errorf("upstream container = %q, want %q", got, want)
	}
	if !equalSlices(gotReq.URL.Query()["command"], []string{"/bin/bash"}) {
		t.Errorf("upstream command = %v, want [/bin/bash]", gotReq.URL.Query()["command"])
	}
	if gotReq.Subprotocol != k8sSubprotocolV4Channel {
		t.Errorf("upstream subprotocol = %q, want %q", gotReq.Subprotocol, k8sSubprotocolV4Channel)
	}
}

// TestK8sListener_RejectsBadToken confirms the gateway returns 401
// when the operator presents a token the authorizer doesn't
// recognise. No upstream dial is attempted in this path — the
// fake K8s API server's request count must stay at zero.
func TestK8sListener_RejectsBadToken(t *testing.T) {
	t.Parallel()
	upstream := newFakeK8sAPI(t)
	defer upstream.Close()

	authz := &fakeSessionAuthorizer{expectedToken: "good-token"}
	injector := &fakeSecretInjector{}

	gw := startK8sListener(t, K8sListenerConfig{
		Authorizer: authz,
		Injector:   injector,
	})
	defer gw.cancel()

	gwURL := gw.wsURL("/api/v1/namespaces/default/pods/p/exec", url.Values{"command": {"sh"}})
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 2 * time.Second
	dialer.Subprotocols = []string{k8sSubprotocolV4Channel}
	hdr := http.Header{"Authorization": []string{"Bearer wrong-token"}}
	_, resp, err := dialer.Dial(gwURL, hdr)
	if err == nil {
		t.Fatalf("expected dial error for bad token")
	}
	if resp == nil {
		t.Fatalf("no HTTP response on rejection; err=%v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if upstream.RequestCount() != 0 {
		t.Errorf("upstream received %d requests, want 0 (auth failed → no upstream dial)", upstream.RequestCount())
	}
}

// TestK8sListener_RejectsMissingBearer covers the case where the
// operator's WebSocket request has no Authorization header at all.
func TestK8sListener_RejectsMissingBearer(t *testing.T) {
	t.Parallel()
	gw := startK8sListener(t, K8sListenerConfig{
		Authorizer: &fakeSessionAuthorizer{expectedToken: "any"},
		Injector:   &fakeSecretInjector{},
	})
	defer gw.cancel()

	gwURL := gw.wsURL("/api/v1/namespaces/default/pods/p/exec", url.Values{"command": {"sh"}})
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 2 * time.Second
	dialer.Subprotocols = []string{k8sSubprotocolV4Channel}
	_, resp, err := dialer.Dial(gwURL, nil)
	if err == nil {
		t.Fatalf("expected dial error for missing bearer")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status=%v err=%v, want 401", resp, err)
	}
}

// TestK8sListener_PathNot404 confirms unknown paths return 404
// before any auth work is attempted.
func TestK8sListener_PathNot404(t *testing.T) {
	t.Parallel()
	gw := startK8sListener(t, K8sListenerConfig{
		Authorizer: &fakeSessionAuthorizer{expectedToken: "any"},
		Injector:   &fakeSecretInjector{},
	})
	defer gw.cancel()

	resp, err := http.Get(gw.httpURL("/healthz", nil))
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestParseK8sExecPath spot-checks the path parser. Hand-rolled
// because a regex would be overkill and slow.
func TestParseK8sExecPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		path      string
		wantNS    string
		wantPod   string
		wantOK    bool
	}{
		{"happy", "/api/v1/namespaces/default/pods/nginx/exec", "default", "nginx", true},
		{"with dash", "/api/v1/namespaces/payments-prod/pods/api-7d4c8f-abc/exec", "payments-prod", "api-7d4c8f-abc", true},
		{"wrong prefix", "/api/v2/namespaces/default/pods/nginx/exec", "", "", false},
		{"too short", "/api/v1/namespaces/default/pods/nginx", "", "", false},
		{"missing exec", "/api/v1/namespaces/default/pods/nginx/foo", "", "", false},
		{"missing pods", "/api/v1/namespaces/default/podz/nginx/exec", "", "", false},
		{"empty ns", "/api/v1/namespaces//pods/nginx/exec", "", "", false},
		{"empty pod", "/api/v1/namespaces/default/pods//exec", "", "", false},
		{"unrelated", "/healthz", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, pod, ok := parseK8sExecPath(tc.path)
			if ns != tc.wantNS || pod != tc.wantPod || ok != tc.wantOK {
				t.Errorf("parseK8sExecPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.path, ns, pod, ok, tc.wantNS, tc.wantPod, tc.wantOK)
			}
		})
	}
}

// TestExtractBearerToken spot-checks the bearer-token helper. Both
// the standard `Authorization: Bearer X` header and the `?token=X`
// query param are accepted.
func TestExtractBearerToken(t *testing.T) {
	t.Parallel()
	mk := func(hdr string, q string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "http://x/?"+q, nil)
		if hdr != "" {
			r.Header.Set("Authorization", hdr)
		}
		return r
	}
	cases := []struct {
		name    string
		req     *http.Request
		wantTok string
		wantOK  bool
	}{
		{"header", mk("Bearer abc", ""), "abc", true},
		{"header lowercase", mk("bearer abc", ""), "abc", true},
		{"query", mk("", "token=qq"), "qq", true},
		{"header beats query", mk("Bearer hh", "token=qq"), "hh", true},
		{"missing", mk("", ""), "", false},
		{"empty bearer", mk("Bearer", ""), "", false},
		{"basic auth", mk("Basic xxx", ""), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, ok := extractBearerToken(tc.req)
			if tok != tc.wantTok || ok != tc.wantOK {
				t.Errorf("extractBearerToken = (%q, %v), want (%q, %v)", tok, ok, tc.wantTok, tc.wantOK)
			}
		})
	}
}

// TestBuildUpstreamExecURL verifies the gateway constructs a
// kubectl-equivalent wss:// URL for the upstream API server. The
// scheme is upgraded from https → wss, the path is canonical, and
// stdin/stdout/stderr are always asserted (the recorder needs all
// three regardless of what the operator asked for).
func TestBuildUpstreamExecURL(t *testing.T) {
	t.Parallel()
	got := buildUpstreamExecURL("https://api.cluster.example:6443", "payments", "api-pod", "app",
		[]string{"/bin/sh", "-c", "uptime"}, false, true, true, true)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if u.Scheme != "wss" {
		t.Errorf("scheme = %q, want wss", u.Scheme)
	}
	if u.Host != "api.cluster.example:6443" {
		t.Errorf("host = %q, want api.cluster.example:6443", u.Host)
	}
	if u.Path != "/api/v1/namespaces/payments/pods/api-pod/exec" {
		t.Errorf("path = %q", u.Path)
	}
	q := u.Query()
	if !equalSlices(q["command"], []string{"/bin/sh", "-c", "uptime"}) {
		t.Errorf("command = %v", q["command"])
	}
	if q.Get("container") != "app" {
		t.Errorf("container = %q", q.Get("container"))
	}
	for _, k := range []string{"stdin", "stdout", "stderr"} {
		if q.Get(k) != "true" {
			t.Errorf("%s = %q, want true", k, q.Get(k))
		}
	}
}

// ---------------------------------------------------------------------
// k8s gateway test scaffolding
// ---------------------------------------------------------------------

type k8sGatewayHandle struct {
	addr   string
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// wsURL builds the gateway's WebSocket URL for the supplied path +
// query — i.e. ws://127.0.0.1:NNNN/api/v1/namespaces/.../exec?...
// The gateway listens on plain HTTP for tests (no TLS material to
// fabricate), so the scheme is ws not wss.
func (h *k8sGatewayHandle) wsURL(path string, q url.Values) string {
	u := url.URL{Scheme: "ws", Host: h.addr, Path: path}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (h *k8sGatewayHandle) httpURL(path string, q url.Values) string {
	u := url.URL{Scheme: "http", Host: h.addr, Path: path}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// startK8sListener boots the gateway on a random localhost port and
// returns a handle the test uses to dial it. The listener is torn
// down when the test's cancel func is called or t.Cleanup fires.
func startK8sListener(t *testing.T, cfg K8sListenerConfig) *k8sGatewayHandle {
	t.Helper()
	listener, err := NewK8sListener(cfg)
	if err != nil {
		t.Fatalf("NewK8sListener: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := listener.serveListener(ctx, ln); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("serveListener: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return &k8sGatewayHandle{addr: ln.Addr().String(), cancel: cancel, wg: &wg}
}

// equalSlices is the trivial string-slice equality helper.
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------
// Fake K8s API server
// ---------------------------------------------------------------------

// fakeK8sAPI stands in for the upstream Kubernetes API server. It
// accepts a WebSocket upgrade at any /api/v1/namespaces/.../exec
// path, captures the request metadata for assertions, and echoes
// every stdin frame back as a stdout frame with the same payload.
type fakeK8sAPI struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []*fakeK8sAPIRequest
}

type fakeK8sAPIRequest struct {
	URL           *url.URL
	Authorization string
	Subprotocol   string
}

func newFakeK8sAPI(t *testing.T) *fakeK8sAPI {
	t.Helper()
	api := &fakeK8sAPI{}
	api.srv = httptest.NewServer(http.HandlerFunc(api.handle))
	return api
}

func (a *fakeK8sAPI) Close() {
	if a == nil || a.srv == nil {
		return
	}
	a.srv.Close()
}

func (a *fakeK8sAPI) URL() string {
	if a == nil || a.srv == nil {
		return ""
	}
	return a.srv.URL
}

func (a *fakeK8sAPI) LastRequest() *fakeK8sAPIRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.requests) == 0 {
		return nil
	}
	return a.requests[len(a.requests)-1]
}

func (a *fakeK8sAPI) RequestCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

func (a *fakeK8sAPI) handle(w http.ResponseWriter, r *http.Request) {
	// Capture the request shape so the test can assert on it.
	rec := &fakeK8sAPIRequest{
		URL:           cloneURL(r.URL),
		Authorization: r.Header.Get("Authorization"),
	}

	if !strings.HasSuffix(r.URL.Path, "/exec") {
		http.Error(w, "not exec", http.StatusNotFound)
		return
	}

	upgrader := websocket.Upgrader{
		Subprotocols: []string{k8sSubprotocolV4Channel},
		CheckOrigin:  func(*http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	rec.Subprotocol = conn.Subprotocol()

	a.mu.Lock()
	a.requests = append(a.requests, rec)
	a.mu.Unlock()

	defer conn.Close()
	// Echo loop: every stdin frame is mirrored back as stdout.
	// Stop on a close message or a read error.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if msgType == websocket.CloseMessage {
			return
		}
		if msgType != websocket.BinaryMessage || len(payload) == 0 {
			continue
		}
		if payload[0] != k8sChanStdin {
			continue
		}
		out := make([]byte, 1+len(payload)-1)
		out[0] = k8sChanStdout
		copy(out[1:], payload[1:])
		if err := conn.WriteMessage(websocket.BinaryMessage, out); err != nil {
			return
		}
	}
}

// cloneURL deep-copies r.URL so the captured snapshot isn't mutated
// by the http handler runtime once the goroutine exits.
func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	out := *u
	q := u.Query()
	rawQ := q.Encode()
	out.RawQuery = rawQ
	return &out
}

// ensure unused import warnings stay quiet on platforms with strict
// linting — the fmt import lives in the assert path below.
var _ = fmt.Sprintf
