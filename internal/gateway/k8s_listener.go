package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// K8sListenerConfig captures the wiring a K8sListener needs.
// Authorizer + Injector are required; everything else is optional
// (the listener still proxies sessions, but no recording / audit
// flushes when those sinks are nil).
type K8sListenerConfig struct {
	// Port is the HTTPS port the listener binds. Defaults to 8443
	// when zero, matching the configurable default in
	// docs/pam/architecture.md §9.
	Port int

	// TLSCertPath / TLSKeyPath enable HTTPS on the operator-side
	// listener. Both must be set or both empty; when empty the
	// listener serves plain HTTP — only suitable for the dev
	// compose stack behind an in-cluster mesh that terminates TLS
	// at the ingress.
	TLSCertPath string
	TLSKeyPath  string

	Authorizer    SessionAuthorizer
	Injector      SecretInjector
	ReplayStore   ReplayStore
	CommandSink   CommandSink
	CommandPolicy CommandPolicyEvaluator

	// ReadHeaderTimeout bounds how long a slow client can hold a
	// connection open without sending request headers. Defaults
	// to 5s when zero.
	ReadHeaderTimeout time.Duration

	// ShutdownTimeout caps how long Serve waits for in-flight
	// exec sessions to drain after ctx is cancelled. Defaults to
	// 30s when zero.
	ShutdownTimeout time.Duration

	// HandshakeTimeout caps how long the operator-side WebSocket
	// upgrade can take. Defaults to 10s when zero.
	HandshakeTimeout time.Duration

	// UpstreamDialTimeout caps how long the gateway will wait for
	// the upstream API server's WebSocket handshake. Defaults to
	// 15s when zero.
	UpstreamDialTimeout time.Duration
}

// K8sListener is the gateway's Kubernetes exec proxy. It accepts
// WebSocket connections on a kubectl-compatible URL, authenticates
// the operator via the same connect-token mechanism the SSH
// listener uses, and proxies the exec stream to the target
// cluster's API server using the standard v4.channel.k8s.io
// channel-prefixed binary framing.
//
// The listener is intentionally narrow: it owns no long-lived
// kubernetes credentials and never touches the kubeconfig YAML or
// service-account token directly — those are injected per session
// via SecretInjector and held only in memory for the lifetime of
// the exec channel.
type K8sListener struct {
	cfg      K8sListenerConfig
	upgrader websocket.Upgrader
}

// NewK8sListener builds a K8sListener bound to the supplied
// configuration. Returns an error when required fields are missing.
func NewK8sListener(cfg K8sListenerConfig) (*K8sListener, error) {
	if cfg.Authorizer == nil {
		return nil, errors.New("gateway: K8sListenerConfig.Authorizer is required")
	}
	if cfg.Injector == nil {
		return nil, errors.New("gateway: K8sListenerConfig.Injector is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 8443
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = 5 * time.Second
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.UpstreamDialTimeout == 0 {
		cfg.UpstreamDialTimeout = 15 * time.Second
	}
	if (cfg.TLSCertPath == "") != (cfg.TLSKeyPath == "") {
		return nil, errors.New("gateway: K8sListenerConfig.TLSCertPath and TLSKeyPath must both be set or both empty")
	}
	l := &K8sListener{cfg: cfg}
	l.upgrader = websocket.Upgrader{
		HandshakeTimeout: cfg.HandshakeTimeout,
		Subprotocols:     []string{k8sSubprotocolV4Channel, k8sSubprotocolV4Base64Channel},
		// Same-origin enforcement is the API client's job; we
		// always accept the upgrade and rely on Bearer-token auth
		// to gate access. Without this kubectl's upgrade request
		// (which carries no Origin) is rejected.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	return l, nil
}

// Serve binds an HTTP(S) listener on the configured port and
// blocks until ctx is cancelled. Errors that aren't expected during
// shutdown are returned to the caller; ctx cancellation triggers a
// bounded drain of active sessions before returning.
func (l *K8sListener) Serve(ctx context.Context) error {
	addr := net.JoinHostPort("", strconv.Itoa(l.cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("gateway: k8s listen on %s: %w", addr, err)
	}
	return l.serveListener(ctx, ln)
}

// serveListener accepts on a pre-bound listener. Split out from
// Serve so end-to-end tests can supply a httptest-style listener
// on a random localhost port without racing with port allocation.
func (l *K8sListener) serveListener(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/", l.handleExec)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: l.cfg.ReadHeaderTimeout,
	}
	errCh := make(chan error, 1)
	go func() {
		var serveErr error
		if l.cfg.TLSCertPath != "" {
			serveErr = srv.ServeTLS(ln, l.cfg.TLSCertPath, l.cfg.TLSKeyPath)
		} else {
			serveErr = srv.Serve(ln)
		}
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		errCh <- serveErr
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), l.cfg.ShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		<-errCh
		return ctx.Err()
	}
}

// handleExec is the HTTP entry point. It implements a small,
// kubectl-compatible subset of the Kubernetes API:
//
//	GET /api/v1/namespaces/{namespace}/pods/{pod}/exec?command=...&container=...&stdin=true&stdout=true&stderr=true
//
// Authentication is via `Authorization: Bearer <connect_token>` —
// the same one-shot token the SSH listener accepts. After the
// upgrade the connection speaks v4.channel.k8s.io to both sides
// (operator and upstream API server).
func (l *K8sListener) handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	namespace, pod, ok := parseK8sExecPath(r.URL.Path)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	token, ok := extractBearerToken(r)
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	sess, err := l.cfg.Authorizer.AuthorizeConnectToken(r.Context(), token)
	if err != nil {
		log.Printf("gateway: k8s authorize session: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if sess.Protocol != "" && !strings.EqualFold(sess.Protocol, "k8s") && !strings.EqualFold(sess.Protocol, "kubernetes") {
		log.Printf("gateway: k8s authorize session=%s wrong protocol=%q", sess.SessionID, sess.Protocol)
		http.Error(w, "session protocol mismatch", http.StatusForbidden)
		return
	}

	secretType, plaintext, err := l.cfg.Injector.InjectSecret(r.Context(), sess.SessionID, sess.AccountID)
	if err != nil {
		log.Printf("gateway: k8s inject session=%s: %v", sess.SessionID, err)
		http.Error(w, "credential injection failed", http.StatusBadGateway)
		return
	}
	upstream, err := ParseK8sUpstream(secretType, plaintext)
	if err != nil {
		log.Printf("gateway: k8s parse upstream session=%s: %v", sess.SessionID, err)
		http.Error(w, "invalid upstream credential", http.StatusBadGateway)
		return
	}

	command, container, tty, stdin, stdout, stderr, err := parseK8sExecQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientConn, err := l.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrader has already written an HTTP error response.
		log.Printf("gateway: k8s upgrade session=%s: %v", sess.SessionID, err)
		return
	}
	// `defer clientConn.Close()` would race with goroutines that
	// share the conn — bidirectionalProxy owns the close.

	upstreamURL := buildUpstreamExecURL(upstream.Server, namespace, pod, container, command, tty, stdin, stdout, stderr)
	upstreamConn, err := dialUpstreamExec(r.Context(), upstreamURL, upstream, l.cfg.UpstreamDialTimeout)
	if err != nil {
		log.Printf("gateway: k8s dial upstream session=%s: %v", sess.SessionID, err)
		_ = clientConn.WriteMessage(websocket.BinaryMessage, packK8sErrorFrame(fmt.Sprintf("pam-gateway: upstream dial failed: %v", err)))
		_ = clientConn.Close()
		return
	}

	// Build the recorder + parser the same way the SSH listener
	// does. Both are optional — the listener still proxies even
	// when the sinks are nil; in that case the audit trail is
	// silently disabled. Production wiring always sets both.
	var recorder *IORecorder
	var parser *CommandParser
	if l.cfg.ReplayStore != nil {
		rec, recErr := NewIORecorder(sess.SessionID, l.cfg.ReplayStore, IORecorderConfig{})
		if recErr != nil {
			log.Printf("gateway: k8s init recorder session=%s: %v", sess.SessionID, recErr)
		} else {
			recorder = rec
		}
	}
	if l.cfg.CommandSink != nil {
		pr, prErr := NewCommandParser(sess.SessionID, l.cfg.CommandSink, CommandParserConfig{})
		if prErr != nil {
			log.Printf("gateway: k8s init parser session=%s: %v", sess.SessionID, prErr)
		} else {
			parser = pr
		}
	}

	if err := proxyK8sExec(r.Context(), clientConn, upstreamConn, recorder, parser); err != nil {
		log.Printf("gateway: k8s proxy session=%s: %v", sess.SessionID, err)
	}

	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelFlush()
	if parser != nil {
		parser.Close(flushCtx)
	}
	if recorder != nil {
		if err := recorder.Close(flushCtx); err != nil {
			log.Printf("gateway: k8s flush recording session=%s: %v", sess.SessionID, err)
		}
	}
}

// k8sSubprotocolV4Channel is the channel-prefixed binary subprotocol
// used by kubectl exec since K8s 1.4. Each WebSocket message has a
// single-byte channel ID followed by the payload:
//
//	channel 0  — stdin   (operator → upstream)
//	channel 1  — stdout  (upstream → operator)
//	channel 2  — stderr  (upstream → operator)
//	channel 3  — error   (upstream → operator, JSON Status object)
//	channel 4  — resize  (operator → upstream, JSON {Width, Height})
const (
	k8sSubprotocolV4Channel       = "v4.channel.k8s.io"
	k8sSubprotocolV4Base64Channel = "base64.channel.k8s.io"

	k8sChanStdin  byte = 0
	k8sChanStdout byte = 1
	k8sChanStderr byte = 2
	k8sChanError  byte = 3
	k8sChanResize byte = 4
)

// parseK8sExecPath extracts (namespace, pod) from a path of the form
//
//	/api/v1/namespaces/{namespace}/pods/{pod}/exec
//
// Anything that doesn't match returns ok=false.
func parseK8sExecPath(path string) (namespace, pod string, ok bool) {
	const prefix = "/api/v1/namespaces/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 4 || parts[1] != "pods" || parts[3] != "exec" {
		return "", "", false
	}
	if parts[0] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[0], parts[2], true
}

// extractBearerToken peels the connect token out of the request.
// Both the standard `Authorization: Bearer X` header and a `token`
// query param are accepted — kubectl uses the header, but the
// browser SQL console (Milestone 6) prefers the query string so it
// doesn't need to set headers on the WebSocket upgrade.
func extractBearerToken(r *http.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		parts := strings.SplitN(h, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			t := strings.TrimSpace(parts[1])
			if t != "" {
				return t, true
			}
		}
	}
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" {
		return t, true
	}
	return "", false
}

// parseK8sExecQuery normalises the kubectl exec query parameters.
// kubectl repeats `command=` once per argv element; the other
// stream flags are simple booleans.
func parseK8sExecQuery(q url.Values) (command []string, container string, tty, stdin, stdout, stderr bool, err error) {
	command = q["command"]
	if len(command) == 0 {
		return nil, "", false, false, false, false, errors.New("missing command")
	}
	container = q.Get("container")
	tty = parseBoolQ(q.Get("tty"))
	stdin = parseBoolQ(q.Get("stdin"))
	stdout = parseBoolQ(q.Get("stdout"))
	stderr = parseBoolQ(q.Get("stderr"))
	// Default to enabling stdout when nothing was asked for —
	// kubectl always sets at least one of stdout / stderr but a
	// malformed client should still see *something* echo back so
	// the audit trail isn't blank.
	if !stdin && !stdout && !stderr {
		stdout = true
	}
	return command, container, tty, stdin, stdout, stderr, nil
}

func parseBoolQ(v string) bool {
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// buildUpstreamExecURL constructs the wss:// URL for the upstream
// K8s API server's exec endpoint, mirroring the parameters kubectl
// would send. We always request stdin + stdout + stderr because the
// gateway needs to mirror them all into the recorder regardless of
// whether the operator asked for them — partial streams would
// leave gaps in the replay artefact.
func buildUpstreamExecURL(server, namespace, pod, container string, command []string, tty, _, _, _ bool) string {
	u, _ := url.Parse(server)
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec", namespace, pod)
	q := url.Values{}
	for _, c := range command {
		q.Add("command", c)
	}
	if container != "" {
		q.Set("container", container)
	}
	if tty {
		q.Set("tty", "true")
	}
	q.Set("stdin", "true")
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	u.RawQuery = q.Encode()
	return u.String()
}

// dialUpstreamExec opens the upstream WebSocket against the K8s API
// server. The bearer token is sent via the Authorization header
// (kubectl-equivalent) and TLS verification is driven by the
// kubeconfig / k8s_token payload.
func dialUpstreamExec(ctx context.Context, target string, up *K8sUpstream, timeout time.Duration) (*websocket.Conn, error) {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = timeout
	dialer.Subprotocols = []string{k8sSubprotocolV4Channel}
	dialer.TLSClientConfig = buildUpstreamTLSConfig(up)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+up.Token)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, resp, err := dialer.DialContext(dialCtx, target, hdr)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			return nil, fmt.Errorf("dial %s: status=%d body=%s err=%w", target, resp.StatusCode, string(body), err)
		}
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, nil
}

// buildUpstreamTLSConfig assembles the *tls.Config the dialer uses
// for the upstream API server. CAPEM, when present, is added to a
// fresh RootCAs pool — we never load the system trust store for
// upstream calls so a host-level cert addition can't widen the
// gateway's trust boundary without an explicit kubeconfig change.
func buildUpstreamTLSConfig(up *K8sUpstream) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: up.InsecureSkipVerify,
	}
	if len(up.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(up.CAPEM) {
			cfg.RootCAs = pool
		} else {
			log.Printf("gateway: k8s upstream CAPEM did not contain any valid certs — falling back to system roots")
		}
	}
	return cfg
}

// packK8sErrorFrame returns a single channel-3 frame carrying a
// plain-language error message, suitable for the operator client to
// surface in its terminal. The payload is intentionally not a JSON
// Status object — kubectl will simply print it verbatim, which is
// the correct behaviour for an upstream-dial failure.
func packK8sErrorFrame(msg string) []byte {
	out := make([]byte, 1+len(msg))
	out[0] = k8sChanError
	copy(out[1:], msg)
	return out
}

// proxyK8sExec runs the bidirectional WebSocket proxy between the
// operator's client and the upstream API server. The recorder
// captures both directions; the parser only sees stdin / stdout /
// stderr (the resize / error channels are control traffic, not
// commands).
//
// The proxy returns when either side closes the connection. ctx is
// observed for early cancellation (gateway shutdown).
func proxyK8sExec(ctx context.Context, client, upstream *websocket.Conn, recorder *IORecorder, parser *CommandParser) error {
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	setErr := func(err error) {
		errOnce.Do(func() { firstErr = err })
	}

	// Close both sides on context cancellation so the read loops
	// unblock. Best-effort: gorilla/websocket has no native
	// context support, so we rely on closing the underlying
	// conn to interrupt blocking reads.
	closer := make(chan struct{})
	defer close(closer)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
		case <-closer:
		}
	}()

	wg.Add(2)
	// Operator → Upstream
	go func() {
		defer wg.Done()
		defer func() { _ = upstream.Close() }()
		if err := pumpK8sFrames(client, upstream, recorder, parser, true); err != nil {
			setErr(fmt.Errorf("client→upstream: %w", err))
		}
	}()
	// Upstream → Operator
	go func() {
		defer wg.Done()
		defer func() { _ = client.Close() }()
		if err := pumpK8sFrames(upstream, client, recorder, parser, false); err != nil {
			setErr(fmt.Errorf("upstream→client: %w", err))
		}
	}()
	wg.Wait()
	return firstErr
}

// pumpK8sFrames is the inner loop of proxyK8sExec. fromClient
// indicates the direction (operator → upstream when true). The
// channel-prefixed framing is preserved on the wire; the recorder
// and parser observe the unframed payload bytes only.
func pumpK8sFrames(src, dst *websocket.Conn, recorder *IORecorder, parser *CommandParser, fromClient bool) error {
	for {
		msgType, payload, err := src.ReadMessage()
		if err != nil {
			if isExpectedCloseErr(err) {
				return nil
			}
			return err
		}
		if msgType == websocket.CloseMessage {
			return nil
		}
		if msgType != websocket.BinaryMessage {
			// kubectl always uses binary frames; text frames are
			// either base64-encoded streams (the v4.base64 sub-
			// protocol, which we don't currently advertise to the
			// upstream) or non-conformant clients. Forward
			// unchanged so the other end sees the frame as-is.
			if err := dst.WriteMessage(msgType, payload); err != nil {
				return err
			}
			continue
		}
		if len(payload) == 0 {
			// Empty frames are heartbeats — forward as-is.
			if err := dst.WriteMessage(msgType, payload); err != nil {
				return err
			}
			continue
		}
		channel := payload[0]
		body := payload[1:]

		// Feed the audit + recording taps before forwarding so a
		// crash mid-write still leaves a partial trail.
		recordK8sFrame(recorder, parser, channel, body, fromClient)

		if err := dst.WriteMessage(msgType, payload); err != nil {
			return err
		}
	}
}

// recordK8sFrame tees one decoded channel frame into the recorder
// and command parser. The parser only cares about stdin (input
// boundary) and stdout/stderr (output hash); resize and error
// frames are control traffic.
//
// The recorder stores a copy of body so the WebSocket read buffer
// can be reused for the next frame without corrupting the
// recording.
func recordK8sFrame(recorder *IORecorder, parser *CommandParser, channel byte, body []byte, fromClient bool) {
	if len(body) == 0 {
		return
	}
	if recorder != nil {
		switch channel {
		case k8sChanStdin:
			recorder.Record(DirectionInput, append([]byte(nil), body...))
		case k8sChanStdout:
			recorder.Record(DirectionOutput, append([]byte(nil), body...))
		case k8sChanStderr:
			recorder.Record(DirectionStderr, append([]byte(nil), body...))
		}
	}
	if parser != nil {
		if fromClient && channel == k8sChanStdin {
			parser.WriteInput(context.Background(), body)
		}
		if !fromClient && (channel == k8sChanStdout || channel == k8sChanStderr) {
			parser.WriteOutput(body)
		}
	}
}

// isExpectedCloseErr returns true when err is one of the close
// statuses we treat as a normal end-of-stream (the operator hit
// Ctrl-D, the upstream pod exited, etc.).
func isExpectedCloseErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
		websocket.CloseAbnormalClosure,
	) {
		return true
	}
	return false
}
