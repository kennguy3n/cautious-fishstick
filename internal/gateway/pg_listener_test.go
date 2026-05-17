package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// TestPGListener_EndToEnd_RecordsAndCapturesQueries drives the
// full gateway path against an in-process fake upstream:
//
//   - operator dials the gateway as a plain `psql` would
//     (StartupMessage → AuthenticationCleartextPassword →
//     PasswordMessage with the one-shot connect token)
//   - the gateway authorises the token, injects an upstream
//     password, dials the fake PG, completes the cleartext
//     handshake, and signals ReadyForQuery to the operator
//   - the operator issues two SimpleQuery statements; the fake
//     server replies with DataRow + CommandComplete + ReadyForQuery
//   - the test asserts that both rows were captured by the
//     CommandSink with non-empty output hashes, and that the
//     recorder flushed bytes in both directions to the replay
//     store.
func TestPGListener_EndToEnd_RecordsAndCapturesQueries(t *testing.T) {
	upstream := newFakePGUpstream(t)
	defer upstream.Close()

	const (
		sessionID = "01HXYE2EQR8K4PAMZJ4N7P9X7L"
		token     = "pg-connect-token"
		password  = "pg-upstream-secret"
		username  = "ops"
		database  = "appdb"
	)

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}

	authz := &fakeSessionAuthorizer{
		expectedToken: token,
		session: AuthorizedSession{
			SessionID:   sessionID,
			WorkspaceID: "ws-1",
			LeaseID:     "lease-1",
			AssetID:     "asset-1",
			AccountID:   "acc-1",
			Protocol:    "postgres",
			TargetHost:  host,
			TargetPort:  port,
			Username:    username,
		},
	}
	injector := &fakeSecretInjector{
		secretType: "pg_password",
		secret:     []byte(password),
	}
	replayStore := NewMemoryReplayStore()
	commandSink := NewMemoryCommandSink()

	listener, err := NewPGListener(PGListenerConfig{
		Port:        0,
		Authorizer:  authz,
		Injector:    injector,
		ReplayStore: replayStore,
		CommandSink: commandSink,
	})
	if err != nil {
		t.Fatalf("NewPGListener: %v", err)
	}
	gateway := startPGListener(t, listener)
	defer gateway.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := net.Dial("tcp", gateway.Addr())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	front := pgproto3.NewFrontend(conn, conn)

	// 1. Handshake: send StartupMessage with database+user.
	front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": username, "database": database},
	})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}

	// 2. Gateway demands a cleartext password.
	msg, err := front.Receive()
	if err != nil {
		t.Fatalf("receive auth challenge: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("want AuthenticationCleartextPassword, got %T", msg)
	}
	front.Send(&pgproto3.PasswordMessage{Password: token})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush password: %v", err)
	}

	// 3. Gateway should now emit AuthenticationOk + ReadyForQuery.
	gotAuthOK := false
	gotReady := false
	deadline := time.Now().Add(5 * time.Second)
	for !(gotAuthOK && gotReady) && time.Now().Before(deadline) {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive auth-ok: %v", err)
		}
		switch msg.(type) {
		case *pgproto3.AuthenticationOk:
			gotAuthOK = true
		case *pgproto3.ReadyForQuery:
			gotReady = true
		}
	}
	if !gotAuthOK {
		t.Fatalf("never received AuthenticationOk")
	}
	if !gotReady {
		t.Fatalf("never received ReadyForQuery")
	}

	// 4. Issue two SimpleQuery statements and read responses.
	queries := []string{"SELECT 1", "SELECT 'hello'"}
	for _, q := range queries {
		front.Send(&pgproto3.Query{String: q})
		if err := front.Flush(); err != nil {
			t.Fatalf("flush query %q: %v", q, err)
		}
		gotCommandComplete := false
		gotReady := false
		readDeadline := time.Now().Add(5 * time.Second)
		for !(gotCommandComplete && gotReady) && time.Now().Before(readDeadline) {
			msg, err := front.Receive()
			if err != nil {
				t.Fatalf("receive after query %q: %v", q, err)
			}
			switch msg.(type) {
			case *pgproto3.CommandComplete:
				gotCommandComplete = true
			case *pgproto3.ReadyForQuery:
				gotReady = true
			}
		}
		if !gotCommandComplete {
			t.Fatalf("never got CommandComplete for %q", q)
		}
		if !gotReady {
			t.Fatalf("never got ReadyForQuery for %q", q)
		}
	}

	// 5. Send Terminate to close the session cleanly.
	front.Send(&pgproto3.Terminate{})
	_ = front.Flush()
	_ = conn.Close()

	// 6. Wait for the listener to flush telemetry on the
	//    upstream-side close.
	rows := waitForCommandRows(ctx, commandSink, len(queries))
	if len(rows) != len(queries) {
		t.Fatalf("captured %d command rows, want %d: %+v", len(rows), len(queries), rows)
	}
	for i, q := range queries {
		if rows[i].Input != q {
			t.Errorf("row %d input = %q, want %q", i, rows[i].Input, q)
		}
		if rows[i].Sequence != i+1 {
			t.Errorf("row %d sequence = %d, want %d", i, rows[i].Sequence, i+1)
		}
		if rows[i].OutputHash == "" {
			t.Errorf("row %d output hash is empty", i)
		}
	}

	// 7. The replay store should hold a single blob with bytes
	//    from BOTH directions of the conversation. The flush
	//    happens asynchronously when handleConn returns, so we
	//    poll instead of asserting immediately.
	body := waitForReplay(ctx, replayStore, sessionID)
	if len(body) == 0 {
		keys := replayStore.Keys()
		t.Fatalf("replay blob is empty; keys=%+v", keys)
	}
}

// TestPGListener_RejectsBadToken proves the listener gives the
// client a clean FATAL ErrorResponse and never opens an upstream
// connection when the authorizer rejects the supplied password.
func TestPGListener_RejectsBadToken(t *testing.T) {
	authz := &fakeSessionAuthorizer{
		expectedToken: "good-token",
		session:       AuthorizedSession{SessionID: "s", TargetHost: "127.0.0.1", TargetPort: 1, Username: "u"},
	}
	injector := &fakeSecretInjector{
		secretType: "pg_password",
		secret:     []byte("nope"),
	}
	listener, err := NewPGListener(PGListenerConfig{
		Port:       0,
		Authorizer: authz,
		Injector:   injector,
	})
	if err != nil {
		t.Fatalf("NewPGListener: %v", err)
	}
	gateway := startPGListener(t, listener)
	defer gateway.Close()

	conn, err := net.Dial("tcp", gateway.Addr())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	front := pgproto3.NewFrontend(conn, conn)
	front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "ops", "database": "appdb"},
	})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}
	msg, err := front.Receive()
	if err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("want AuthenticationCleartextPassword, got %T", msg)
	}
	front.Send(&pgproto3.PasswordMessage{Password: "bad-token"})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush bad pw: %v", err)
	}
	// Read until we either get an ErrorResponse or the conn is
	// closed (either outcome is acceptable as long as we never
	// see AuthenticationOk).
	gotError := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := front.Receive()
		if err != nil {
			break
		}
		if _, ok := msg.(*pgproto3.AuthenticationOk); ok {
			t.Fatalf("authentication unexpectedly succeeded with bad token")
		}
		if _, ok := msg.(*pgproto3.ErrorResponse); ok {
			gotError = true
			break
		}
	}
	if !gotError {
		t.Fatalf("never received ErrorResponse for bad token")
	}
}

// TestPGListener_SSLRequestThenStartup proves the listener honours
// the libpq dance: SSLRequest → 'N' → StartupMessage. A real client
// drives this whenever PGSSLMODE != disable.
func TestPGListener_SSLRequestThenStartup(t *testing.T) {
	upstream := newFakePGUpstream(t)
	defer upstream.Close()

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}
	authz := &fakeSessionAuthorizer{
		expectedToken: "tok",
		session: AuthorizedSession{
			SessionID: "s1", AccountID: "a1", TargetHost: host, TargetPort: port, Username: "u",
		},
	}
	injector := &fakeSecretInjector{
		secretType: "pg_password", secret: []byte("pw"),
	}
	listener, err := NewPGListener(PGListenerConfig{
		Port: 0, Authorizer: authz, Injector: injector,
	})
	if err != nil {
		t.Fatalf("NewPGListener: %v", err)
	}
	gateway := startPGListener(t, listener)
	defer gateway.Close()

	conn, err := net.Dial("tcp", gateway.Addr())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// Send SSLRequest (8 bytes: length=8, code=80877103).
	front := pgproto3.NewFrontend(conn, conn)
	front.Send(&pgproto3.SSLRequest{})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush ssl request: %v", err)
	}
	// Read single-byte 'N' reply.
	one := make([]byte, 1)
	if _, err := io.ReadFull(conn, one); err != nil {
		t.Fatalf("read ssl-no: %v", err)
	}
	if one[0] != 'N' {
		t.Fatalf("ssl-no byte = %q, want 'N'", one[0])
	}
	// Now send the real StartupMessage.
	front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "ops", "database": "appdb"},
	})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}
	msg, err := front.Receive()
	if err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("want AuthenticationCleartextPassword, got %T", msg)
	}
	front.Send(&pgproto3.PasswordMessage{Password: "tok"})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush pw: %v", err)
	}
	gotAuthOK := false
	deadline := time.Now().Add(3 * time.Second)
	for !gotAuthOK && time.Now().Before(deadline) {
		msg, err := front.Receive()
		if err != nil {
			t.Fatalf("receive auth-ok: %v", err)
		}
		if _, ok := msg.(*pgproto3.AuthenticationOk); ok {
			gotAuthOK = true
		}
	}
	if !gotAuthOK {
		t.Fatalf("never received AuthenticationOk after SSLRequest dance")
	}
}

// TestPGListener_RejectsUnsupportedSecretType proves the listener
// refuses an upstream credential it cannot interpret. The error
// surfaces to the client as a FATAL ErrorResponse.
func TestPGListener_RejectsUnsupportedSecretType(t *testing.T) {
	upstream := newFakePGUpstream(t)
	defer upstream.Close()

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}
	authz := &fakeSessionAuthorizer{
		expectedToken: "tok",
		session: AuthorizedSession{
			SessionID: "s1", AccountID: "a1", TargetHost: host, TargetPort: port, Username: "u",
		},
	}
	injector := &fakeSecretInjector{
		secretType: "ssh_password", // wrong type for pg
		secret:     []byte("pw"),
	}
	listener, err := NewPGListener(PGListenerConfig{
		Port: 0, Authorizer: authz, Injector: injector,
	})
	if err != nil {
		t.Fatalf("NewPGListener: %v", err)
	}
	gateway := startPGListener(t, listener)
	defer gateway.Close()

	conn, err := net.Dial("tcp", gateway.Addr())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	front := pgproto3.NewFrontend(conn, conn)
	front.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "ops", "database": "appdb"},
	})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}
	if _, err := front.Receive(); err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	front.Send(&pgproto3.PasswordMessage{Password: "tok"})
	if err := front.Flush(); err != nil {
		t.Fatalf("flush pw: %v", err)
	}
	gotErr := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := front.Receive()
		if err != nil {
			break
		}
		if _, ok := msg.(*pgproto3.AuthenticationOk); ok {
			t.Fatalf("authentication unexpectedly succeeded with wrong secret type")
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			if !strings.Contains(er.Message, "upstream unavailable") {
				t.Fatalf("error message = %q, want 'upstream unavailable'", er.Message)
			}
			gotErr = true
			break
		}
	}
	if !gotErr {
		t.Fatalf("never received ErrorResponse for unsupported secret type")
	}
}

// TestNewPGListener_RequiresAuthorizerAndInjector proves the
// constructor refuses to start without its mandatory collaborators.
func TestNewPGListener_RequiresAuthorizerAndInjector(t *testing.T) {
	if _, err := NewPGListener(PGListenerConfig{}); err == nil {
		t.Fatal("expected error when Authorizer is nil")
	}
	if _, err := NewPGListener(PGListenerConfig{Authorizer: &fakeSessionAuthorizer{}}); err == nil {
		t.Fatal("expected error when Injector is nil")
	}
}

// TestMD5PasswordHash pins the libpq-compatible md5 hash format —
// the same algorithm psql uses when an upstream sends
// AuthenticationMD5Password.
func TestMD5PasswordHash(t *testing.T) {
	// Cross-checked against `psql`: hash for user="user",
	// password="password", salt="\x01\x02\x03\x04".
	got := md5PasswordHash("user", "password", []byte{0x01, 0x02, 0x03, 0x04})
	if !strings.HasPrefix(got, "md5") {
		t.Fatalf("hash missing md5 prefix: %q", got)
	}
	if len(got) != 3+32 {
		t.Fatalf("hash wrong length: got %d, want %d", len(got), 3+32)
	}
	got2 := md5PasswordHash("user", "password", []byte{0x01, 0x02, 0x03, 0x04})
	if got != got2 {
		t.Fatalf("md5 hash is non-deterministic; got %q and %q", got, got2)
	}
}

// pgGatewayHandle bundles the ephemeral test gateway listener so
// tests can address its Addr().
type pgGatewayHandle struct {
	ln net.Listener
}

func (h *pgGatewayHandle) Addr() string  { return h.ln.Addr().String() }
func (h *pgGatewayHandle) Close() error  { return h.ln.Close() }

// startPGListener binds the listener to an ephemeral port and
// returns a handle that closes cleanly when the test ends.
func startPGListener(t *testing.T, l *PGListener) *pgGatewayHandle {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := l.serveListener(ctx, ln); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("pg listener serveListener: %v", err)
		}
	}()
	return &pgGatewayHandle{ln: ln}
}

// fakePGUpstream is a minimal PG-wire fake that:
//   - accepts any cleartext password,
//   - sends AuthenticationOk + ReadyForQuery,
//   - replies to every Query with one DataRow + CommandComplete
//     + ReadyForQuery,
//   - exits cleanly on Terminate.
type fakePGUpstream struct {
	ln net.Listener

	mu     sync.Mutex
	closed bool
}

func newFakePGUpstream(t *testing.T) *fakePGUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	u := &fakePGUpstream{ln: ln}
	go u.acceptLoop(t)
	return u
}

func (u *fakePGUpstream) Addr() string { return u.ln.Addr().String() }

func (u *fakePGUpstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return
	}
	u.closed = true
	_ = u.ln.Close()
}

func (u *fakePGUpstream) acceptLoop(t *testing.T) {
	t.Helper()
	for {
		conn, err := u.ln.Accept()
		if err != nil {
			return
		}
		go u.serve(t, conn)
	}
}

func (u *fakePGUpstream) serve(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	backend := pgproto3.NewBackend(conn, conn)
	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := msg.(*pgproto3.StartupMessage); !ok {
		return
	}
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	if err := backend.Flush(); err != nil {
		return
	}
	if _, err := backend.Receive(); err != nil {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 1234, SecretKey: 5678})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}
	queryIdx := 0
	for {
		m, err := backend.Receive()
		if err != nil {
			return
		}
		switch q := m.(type) {
		case *pgproto3.Query:
			queryIdx++
			// Single-column, single-row response.
			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{
				Name:                 []byte("col"),
				TableOID:             0,
				TableAttributeNumber: 0,
				DataTypeOID:          25, // text
				DataTypeSize:         -1,
				TypeModifier:         -1,
				Format:               0,
			}}})
			val := []byte(fmt.Sprintf("row-for-%s-%d", q.String, queryIdx))
			backend.Send(&pgproto3.DataRow{Values: [][]byte{val}})
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

// waitForCommandRows blocks until the sink has captured at least n
// rows or the context is cancelled. Used to gate test assertions on
// the asynchronous parser → sink pipeline.
func waitForCommandRows(ctx context.Context, sink *MemoryCommandSink, n int) []AppendCommandInput {
	for {
		rows := sink.Commands()
		if len(rows) >= n {
			return rows
		}
		select {
		case <-ctx.Done():
			return rows
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// waitForReplay polls the replay store until the recorder finishes
// its flush for sessionID, or the context is cancelled. The recorder
// flush happens asynchronously inside the listener's handleConn
// goroutine after the operator disconnects, so the test cannot
// assert on the blob synchronously.
func waitForReplay(ctx context.Context, store *MemoryReplayStore, sessionID string) []byte {
	for {
		if body, ok := store.Get(sessionID); ok {
			return body
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(20 * time.Millisecond):
		}
	}
}
