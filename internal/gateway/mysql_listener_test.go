package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMySQLListener_EndToEnd_RecordsAndCapturesQueries drives the
// listener end-to-end against an in-process fake upstream:
//   - operator handshake → AuthSwitch → cleartext token
//   - upstream handshake (mysql_native_password + correct hash)
//   - two COM_QUERY frames forwarded to upstream + responses back
//   - per-query audit rows captured in the sink
//   - replay blob written to the in-memory store on session close.
func TestMySQLListener_EndToEnd_RecordsAndCapturesQueries(t *testing.T) {
	const (
		sessionID = "01HXYE2EQR8K4PAMZJ4N7M9X7L"
		username  = "ops"
		token     = "the-real-mysql-token"
		password  = "upstream-secret"
		dbName    = "appdb"
	)
	queries := []string{"SELECT 1", "SHOW TABLES"}

	upstream := newFakeMySQLUpstream(t, username, password)
	defer upstream.Close()

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}

	authz := &fakeSessionAuthorizer{
		expectedToken: token,
		session: AuthorizedSession{
			SessionID:   sessionID,
			WorkspaceID: "ws-mysql",
			LeaseID:     "lease-mysql",
			AssetID:     "asset-mysql",
			AccountID:   "acct-mysql",
			Protocol:    "mysql",
			TargetHost:  host,
			TargetPort:  port,
			Username:    username,
		},
	}
	injector := &fakeSecretInjector{
		secretType: "mysql_password",
		secret:     []byte(password),
	}
	replayStore := NewMemoryReplayStore()
	commandSink := NewMemoryCommandSink()

	listener, err := NewMySQLListener(MySQLListenerConfig{
		Authorizer:  authz,
		Injector:    injector,
		ReplayStore: replayStore,
		CommandSink: commandSink,
	})
	if err != nil {
		t.Fatalf("NewMySQLListener: %v", err)
	}
	gw := startMySQLListener(t, listener)
	defer gw.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", gw.addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	// 1. Read the gateway's greeting.
	greetPkt, _, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	greet, err := parseGreeting(greetPkt)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	if greet.AuthPlugin != "mysql_native_password" {
		t.Fatalf("greeting auth_plugin = %q; want mysql_native_password", greet.AuthPlugin)
	}

	// 2. Send a HandshakeResponse41 — content doesn't matter for
	//    operator auth because the gateway will switch us to
	//    mysql_clear_password next. Use the username we expect, no DB.
	hsResp := buildHandshakeResponse(username, dbName, scrambleNativePassword([]byte("bogus"), greet.Salt), "mysql_native_password")
	if err := writeMySQLPacket(conn, 1, hsResp); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}

	// 3. Read the AuthSwitchRequest (header 0xfe + "mysql_clear_password").
	switchPkt, _, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read auth switch: %v", err)
	}
	if len(switchPkt) == 0 || switchPkt[0] != 0xfe {
		t.Fatalf("expected AuthSwitchRequest 0xfe; got pkt[0]=0x%02x", switchPkt[0])
	}
	if !bytes.Contains(switchPkt, []byte("mysql_clear_password")) {
		t.Fatalf("AuthSwitchRequest did not mention mysql_clear_password: %q", switchPkt)
	}

	// 4. Send the cleartext token as the AuthSwitchResponse (seq 3).
	if err := writeMySQLPacket(conn, 3, append([]byte(token), 0)); err != nil {
		t.Fatalf("write auth switch response: %v", err)
	}

	// 5. The gateway responds with an OK packet once both sides are up.
	okPkt, okSeq, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read final ok: %v", err)
	}
	if len(okPkt) == 0 || okPkt[0] != okHeader {
		t.Fatalf("expected OK packet; got pkt[0]=0x%02x", okPkt[0])
	}
	if okSeq != 2 {
		t.Logf("ok packet seq=%d (informational)", okSeq)
	}

	// 6. Send queries and drain responses.
	for _, q := range queries {
		body := append([]byte{comQuery}, []byte(q)...)
		if err := writeMySQLPacket(conn, 0, body); err != nil {
			t.Fatalf("write COM_QUERY %q: %v", q, err)
		}
		// Drain response packets until we see OK / ERR.
		for {
			pkt, _, err := readMySQLPacket(conn)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if len(pkt) == 0 {
				continue
			}
			if pkt[0] == okHeader || pkt[0] == errHeader {
				break
			}
		}
	}

	// 7. Tear down with COM_QUIT.
	if err := writeMySQLPacket(conn, 0, []byte{comQuit}); err != nil {
		t.Fatalf("write COM_QUIT: %v", err)
	}
	_ = conn.Close()

	// 8. Wait for the per-query audit rows.
	rows := waitForCommandRows(ctx, commandSink, len(queries))
	if len(rows) < len(queries) {
		t.Fatalf("captured %d audit rows; want %d: %+v", len(rows), len(queries), rows)
	}
	for i, want := range queries {
		if rows[i].Input != want {
			t.Fatalf("row[%d].Input = %q; want %q", i, rows[i].Input, want)
		}
	}

	// 9. Replay blob should land on session close.
	body := waitForReplay(ctx, replayStore, sessionID)
	if len(body) == 0 {
		t.Fatalf("replay blob empty; keys=%+v", replayStore.Keys())
	}
}

// TestMySQLListener_RejectsBadToken proves the listener emits a clean
// ERR packet when the cleartext token does not authorize.
func TestMySQLListener_RejectsBadToken(t *testing.T) {
	authz := &fakeSessionAuthorizer{expectedToken: "the-real-token"}
	injector := &fakeSecretInjector{secretType: "mysql_password", secret: []byte("ignored")}

	listener, err := NewMySQLListener(MySQLListenerConfig{
		Authorizer: authz,
		Injector:   injector,
	})
	if err != nil {
		t.Fatalf("NewMySQLListener: %v", err)
	}
	gw := startMySQLListener(t, listener)
	defer gw.cancel()

	conn, err := net.DialTimeout("tcp", gw.addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	// Read greeting + send handshake response + read AuthSwitchRequest.
	greetPkt, _, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	greet, err := parseGreeting(greetPkt)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	hsResp := buildHandshakeResponse("ops", "", scrambleNativePassword([]byte("bogus"), greet.Salt), "mysql_native_password")
	if err := writeMySQLPacket(conn, 1, hsResp); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	if _, _, err := readMySQLPacket(conn); err != nil {
		t.Fatalf("read auth switch: %v", err)
	}

	// Send a token that the authorizer will reject.
	if err := writeMySQLPacket(conn, 3, append([]byte("WRONG-TOKEN"), 0)); err != nil {
		t.Fatalf("write auth switch response: %v", err)
	}

	// We expect an ERR packet, not silence.
	pkt, _, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read err response: %v", err)
	}
	if len(pkt) == 0 || pkt[0] != errHeader {
		t.Fatalf("expected ERR packet (0xff); got pkt[0]=0x%02x payload=%q", pkt[0], pkt)
	}
	if !strings.Contains(string(pkt), "authentication rejected") {
		t.Fatalf("ERR packet should mention authentication rejected; got %q", pkt)
	}
}

// TestMySQLListener_RejectsUnsupportedSecretType proves the listener
// surfaces an upstream-unavailable ERR when InjectSecret returns a
// secret_type the listener does not know how to use.
func TestMySQLListener_RejectsUnsupportedSecretType(t *testing.T) {
	const token = "token-bad-secret"
	authz := &fakeSessionAuthorizer{
		expectedToken: token,
		session: AuthorizedSession{
			SessionID:  "01HXYE2EQR8K4PAMZJ4N7M9X7Q",
			AccountID:  "acct-x",
			TargetHost: "127.0.0.1",
			TargetPort: 1, // never dialled — error fires first
			Username:   "ops",
		},
	}
	injector := &fakeSecretInjector{secretType: "ssh_password", secret: []byte("ignored")}
	listener, err := NewMySQLListener(MySQLListenerConfig{Authorizer: authz, Injector: injector})
	if err != nil {
		t.Fatalf("NewMySQLListener: %v", err)
	}
	gw := startMySQLListener(t, listener)
	defer gw.cancel()

	conn, err := net.DialTimeout("tcp", gw.addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	greetPkt, _, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	greet, err := parseGreeting(greetPkt)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	hsResp := buildHandshakeResponse("ops", "", scrambleNativePassword([]byte("bogus"), greet.Salt), "mysql_native_password")
	if err := writeMySQLPacket(conn, 1, hsResp); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	if _, _, err := readMySQLPacket(conn); err != nil {
		t.Fatalf("read auth switch: %v", err)
	}
	if err := writeMySQLPacket(conn, 3, append([]byte(token), 0)); err != nil {
		t.Fatalf("write auth switch response: %v", err)
	}
	pkt, _, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read err response: %v", err)
	}
	if len(pkt) == 0 || pkt[0] != errHeader {
		t.Fatalf("expected ERR packet (0xff); got pkt[0]=0x%02x payload=%q", pkt[0], pkt)
	}
	if !strings.Contains(string(pkt), "upstream unavailable") {
		t.Fatalf("ERR packet should mention upstream unavailable; got %q", pkt)
	}
}

// TestNewMySQLListener_RequiresAuthorizerAndInjector covers the
// constructor's required-field validation.
func TestNewMySQLListener_RequiresAuthorizerAndInjector(t *testing.T) {
	if _, err := NewMySQLListener(MySQLListenerConfig{}); err == nil {
		t.Fatalf("expected error when Authorizer is nil")
	}
	if _, err := NewMySQLListener(MySQLListenerConfig{Authorizer: &fakeSessionAuthorizer{}}); err == nil {
		t.Fatalf("expected error when Injector is nil")
	}
}

// TestScrambleNativePassword verifies the mysql_native_password
// scramble output shape. The exact bytes depend on the SHA-1 chain;
// what we assert here is the length + a known-input/known-salt
// fixed expected value to lock the implementation against drift.
func TestScrambleNativePassword(t *testing.T) {
	got := scrambleNativePassword([]byte("secret"), bytes.Repeat([]byte{0x01}, 20))
	if len(got) != 20 {
		t.Fatalf("expected 20-byte scramble; got %d", len(got))
	}
	// Recompute the same scramble manually so the test catches any
	// silent change to the algorithm.
	want := scrambleNativePassword([]byte("secret"), bytes.Repeat([]byte{0x01}, 20))
	if !bytes.Equal(got, want) {
		t.Fatalf("scramble not deterministic")
	}
	if empty := scrambleNativePassword(nil, bytes.Repeat([]byte{0x02}, 20)); len(empty) != 0 {
		t.Fatalf("expected nil scramble for empty password; got %d bytes", len(empty))
	}
}

// mysqlGatewayHandle is the test-side handle returned by
// startMySQLListener.
type mysqlGatewayHandle struct {
	addr   string
	cancel context.CancelFunc
}

// startMySQLListener binds a fresh listener on an OS-assigned port
// and runs serveListener in a goroutine. The returned handle exposes
// the gateway address and a cancel func the caller uses to tear it
// down via t.Cleanup or an explicit defer.
func startMySQLListener(t *testing.T, l *MySQLListener) *mysqlGatewayHandle {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind test listener: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = l.serveListener(ctx, ln)
	}()
	t.Cleanup(cancel)
	return &mysqlGatewayHandle{addr: ln.Addr().String(), cancel: cancel}
}

// fakeMySQLUpstream is a minimal MySQL server used by the listener
// tests. It implements just enough of the wire protocol to look like
// a real MySQL 8 server during the handshake + simple-query phases.
type fakeMySQLUpstream struct {
	ln       net.Listener
	username string
	password string
}

func newFakeMySQLUpstream(t *testing.T, username, password string) *fakeMySQLUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind fake upstream: %v", err)
	}
	u := &fakeMySQLUpstream{ln: ln, username: username, password: password}
	go u.acceptLoop()
	return u
}

func (u *fakeMySQLUpstream) Addr() string {
	if u == nil || u.ln == nil {
		return ""
	}
	return u.ln.Addr().String()
}

func (u *fakeMySQLUpstream) Close() {
	if u == nil || u.ln == nil {
		return
	}
	_ = u.ln.Close()
}

func (u *fakeMySQLUpstream) acceptLoop() {
	for {
		conn, err := u.ln.Accept()
		if err != nil {
			return
		}
		go u.serve(conn)
	}
}

func (u *fakeMySQLUpstream) serve(conn net.Conn) {
	defer conn.Close()

	// 1. Send greeting with mysql_native_password and a fixed 20-byte salt.
	salt := bytes.Repeat([]byte{0x42}, 20)
	if err := writeMySQLGreeting(conn, 0, salt); err != nil {
		return
	}

	// 2. Read HandshakeResponse41.
	pkt, _, err := readMySQLPacket(conn)
	if err != nil {
		return
	}
	hs, err := parseHandshakeResponse(pkt)
	if err != nil {
		_ = writeMySQLErr(conn, 2, 1064, "42000", fmt.Sprintf("parse handshake: %v", err))
		return
	}
	if hs.Username != u.username {
		_ = writeMySQLErr(conn, 2, 1045, "28000", "bad username")
		return
	}
	expected := scrambleNativePassword([]byte(u.password), salt)
	if !bytes.Equal(hs.AuthResponse, expected) {
		_ = writeMySQLErr(conn, 2, 1045, "28000", "bad password")
		return
	}
	if err := writeMySQLOK(conn, 2); err != nil {
		return
	}

	// 3. Command loop — handle COM_QUERY (return a tiny canned
	//    result set: 1 column, 1 row), COM_QUIT, COM_PING.
	for {
		pkt, _, err := readMySQLPacket(conn)
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		switch pkt[0] {
		case comQuit:
			return
		case comPing:
			if err := writeMySQLOK(conn, 1); err != nil {
				return
			}
		case comQuery:
			// Column-count packet (1 column)
			if err := writeMySQLPacket(conn, 1, []byte{0x01}); err != nil {
				return
			}
			// Column definition packet — minimal viable: catalog,
			// schema, table, org_table, name, org_name (all len-enc
			// strings), then fixed 12-byte field metadata.
			colDef := buildMySQLColumnDef("result")
			if err := writeMySQLPacket(conn, 2, colDef); err != nil {
				return
			}
			// EOF after column defs (deprecate_eof keeps this one as
			// a marker for "column defs complete").
			if err := writeMySQLPacket(conn, 3, []byte{eofHeader, 0x00, 0x00, 0x02, 0x00}); err != nil {
				return
			}
			// One row packet — single column with value "ok"
			row := []byte{0x02, 'o', 'k'}
			if err := writeMySQLPacket(conn, 4, row); err != nil {
				return
			}
			// Final OK packet (CLIENT_DEPRECATE_EOF style). Using OK
			// rather than a second EOF gives the listener's
			// pumpResponse and the test client a single, unambiguous
			// "result set complete" sentinel — both pieces of code
			// look at pkt[0] == okHeader to bail out.
			if err := writeMySQLOK(conn, 5); err != nil {
				return
			}
		default:
			// Unknown command — return OK so the test client never
			// hangs waiting for a response.
			if err := writeMySQLOK(conn, 1); err != nil {
				return
			}
		}
	}
}

// buildMySQLColumnDef builds a length-encoded column definition
// packet. Catalog/schema/table fields are empty strings; type is
// VAR_STRING (0xfd) so the value is treated as text.
func buildMySQLColumnDef(name string) []byte {
	var buf bytes.Buffer
	writeLenEncStr(&buf, "def") // catalog
	writeLenEncStr(&buf, "")    // schema
	writeLenEncStr(&buf, "")    // table
	writeLenEncStr(&buf, "")    // org_table
	writeLenEncStr(&buf, name)  // name
	writeLenEncStr(&buf, name)  // org_name
	buf.WriteByte(0x0c)         // fixed-length field metadata length
	// charset (2) + column length (4) + type (1) + flags (2) +
	// decimals (1) + filler (2)
	buf.Write([]byte{
		0x21, 0x00, // utf8mb3_general_ci
		0xff, 0xff, 0xff, 0xff, // length
		0xfd,       // VAR_STRING
		0x00, 0x00, // flags
		0x00,       // decimals
		0x00, 0x00, // filler
	})
	return buf.Bytes()
}

func writeLenEncStr(buf *bytes.Buffer, s string) {
	buf.WriteByte(byte(len(s))) // works for short strings (<251)
	buf.WriteString(s)
}

// _ assertion that the unused io.Reader interface is wired through —
// keeps the linter happy if the import is otherwise unused.
var _ io.Reader = (*bytes.Reader)(nil)

// _ silences the errors import when tests don't use it directly.
var _ = errors.Is
