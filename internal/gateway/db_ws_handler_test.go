package gateway

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

// stubSQLConsoleAuthorizer implements SessionAuthorizer for the
// WebSocket SQL console tests. It returns the canned session
// pinned by the test, or an error when wantErr is set.
type stubSQLConsoleAuthorizer struct {
	session *AuthorizedSession
	wantErr error
	calls   int
}

func (s *stubSQLConsoleAuthorizer) AuthorizeConnectToken(_ context.Context, _ string) (*AuthorizedSession, error) {
	s.calls++
	if s.wantErr != nil {
		return nil, s.wantErr
	}
	return s.session, nil
}

// stubSQLConsoleInjector implements SecretInjector for the
// WebSocket SQL console tests. It returns the canned credential, or
// an error when wantErr is set.
type stubSQLConsoleInjector struct {
	secretType string
	plaintext  []byte
	wantErr    error
	calls      int
}

func (s *stubSQLConsoleInjector) InjectSecret(_ context.Context, _, _ string) (string, []byte, error) {
	s.calls++
	if s.wantErr != nil {
		return "", nil, s.wantErr
	}
	// Return a fresh copy so the handler's defer-zeroBytes cannot
	// scribble over the test's expected plaintext on subsequent
	// assertions.
	buf := make([]byte, len(s.plaintext))
	copy(buf, s.plaintext)
	return s.secretType, buf, nil
}

// stubSQLConsoleSink implements CommandSink for the WebSocket SQL
// console tests. It records every AppendCommandInput it sees so
// assertions can introspect the audit row shape (input text, output
// hash, risk flag, sequence ordering).
type stubSQLConsoleSink struct {
	mu       sync.Mutex
	captured []AppendCommandInput
	wantErr  error
}

func (s *stubSQLConsoleSink) AppendCommand(_ context.Context, in AppendCommandInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captured = append(s.captured, in)
	return s.wantErr
}

func (s *stubSQLConsoleSink) snapshot() []AppendCommandInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AppendCommandInput, len(s.captured))
	copy(out, s.captured)
	return out
}

// stubSQLConsolePolicy implements CommandPolicyEvaluator for the
// WebSocket SQL console tests. The decide callback lets a test
// return arbitrary (action, reason, err) tuples per query so the
// allow / deny / step_up / fail-open paths can each be covered.
type stubSQLConsolePolicy struct {
	mu     sync.Mutex
	calls  []string
	decide func(input string) (string, string, error)
}

func (s *stubSQLConsolePolicy) EvaluateCommand(_ context.Context, _, _, input string) (string, string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, input)
	s.mu.Unlock()
	if s.decide == nil {
		return "allow", "", nil
	}
	return s.decide(input)
}

// newSQLConsoleFixture stands up a complete WebSocket SQL console
// test rig:
//
//   - in-memory SQLite database (via modernc.org/sqlite, no CGO)
//     that the dialer hands back to the handler
//   - stub authorizer that pins an AuthorizedSession with protocol
//     "postgres" (so isDBProtocol passes)
//   - stub injector returning canned credential bytes
//   - stub command sink so each query's audit row can be inspected
//   - optional stub policy evaluator (off by default)
//   - httptest.Server that serves the WebSocket upgrade at "/"
//
// The fixture returns the dial URL the test client should use,
// along with handles to all the stubs so the tests can mutate them
// (e.g. swap the policy decide function) and assert on them.
type sqlConsoleFixture struct {
	t          *testing.T
	server     *httptest.Server
	dialURL    string
	auth       *stubSQLConsoleAuthorizer
	injector   *stubSQLConsoleInjector
	sink       *stubSQLConsoleSink
	policy     *stubSQLConsolePolicy
	handler    *DBSQLConsoleHandler
	db         *sql.DB
	now        time.Time
	dialerCall int
}

func newSQLConsoleFixture(t *testing.T) *sqlConsoleFixture {
	t.Helper()
	// Use a temp-file SQLite database (not :memory:) so the handler
	// can close its dialer-returned *sql.DB without invalidating the
	// fixture's seed data. Every dialer invocation re-opens the same
	// file path and sees the seeded rows.
	dbPath := t.TempDir() + "/console.sqlite"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name) VALUES (1, 'alice'), (2, 'bob'), (3, NULL)`); err != nil {
		t.Fatalf("seed rows: %v", err)
	}

	f := &sqlConsoleFixture{
		t: t,
		auth: &stubSQLConsoleAuthorizer{
			session: &AuthorizedSession{
				SessionID:   "ses-01",
				WorkspaceID: "ws-01",
				LeaseID:     "lease-01",
				AssetID:     "asset-01",
				AccountID:   "acct-01",
				Protocol:    "postgres",
				TargetHost:  "10.0.0.5",
				TargetPort:  5432,
				Username:    "app",
			},
		},
		injector: &stubSQLConsoleInjector{
			secretType: "password",
			plaintext:  []byte("hunter2"),
		},
		sink: &stubSQLConsoleSink{},
		policy: &stubSQLConsolePolicy{
			decide: func(string) (string, string, error) { return "allow", "", nil },
		},
		db:  db,
		now: time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
	}

	h, err := NewDBSQLConsoleHandler(DBSQLConsoleConfig{
		Authorizer:    f.auth,
		Injector:      f.injector,
		CommandSink:   f.sink,
		CommandPolicy: f.policy,
		Dialer: func(_ context.Context, _ *AuthorizedSession, _ string, _ []byte) (*sql.DB, error) {
			f.dialerCall++
			// Return a fresh handle backed by the same temp-file
			// SQLite database. The handler's deferred Close() then
			// only closes this handle, not the fixture's seed DB.
			wrapped, werr := sql.Open("sqlite", dbPath)
			if werr != nil {
				return nil, werr
			}
			return wrapped, nil
		},
		QueryTimeout:  5 * time.Second,
		ReadDeadline:  2 * time.Second,
		WriteDeadline: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewDBSQLConsoleHandler: %v", err)
	}
	h.now = func() time.Time { return f.now }
	f.handler = h

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	f.server = srv
	f.dialURL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/?token=t1"
	return f
}

// dial returns a connected gorilla/websocket client for the
// fixture, with sensible read/write deadlines so a misbehaving
// handler does not wedge the test.
func (f *sqlConsoleFixture) dial(t *testing.T) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(f.dialURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// send marshals payload as JSON and writes a single text-frame
// WebSocket message.
func (f *sqlConsoleFixture) send(t *testing.T, conn *websocket.Conn, payload any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal client message: %v", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
		t.Fatalf("write client message: %v", err)
	}
}

// readMessage reads exactly one server-side JSON message off the
// socket and unmarshals it. Failures surface as test fatals so the
// caller does not have to repeat boilerplate.
func (f *sqlConsoleFixture) readMessage(t *testing.T, conn *websocket.Conn) sqlConsoleServerMessage {
	t.Helper()
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var msg sqlConsoleServerMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("unmarshal %q: %v", string(raw), err)
	}
	return msg
}

// TestSQLConsole_AllowQuery_StreamsRows is the happy-path smoke
// test: an allow-by-default policy lets a SELECT through; the
// handler emits columns + rows + end frames, and the audit sink
// receives a row carrying the output hash + an empty risk flag.
func TestSQLConsole_AllowQuery_StreamsRows(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "SELECT id, name FROM users ORDER BY id"})

	cols := f.readMessage(t, conn)
	if cols.Type != "columns" {
		t.Fatalf("first frame type = %q; want columns", cols.Type)
	}
	if len(cols.Columns) != 2 || cols.Columns[0] != "id" || cols.Columns[1] != "name" {
		t.Fatalf("columns = %v; want [id name]", cols.Columns)
	}

	wantRows := [][]string{
		{"1", "alice"},
		{"2", "bob"},
		{"3", ""}, // NULL serialises to empty string
	}
	for _, want := range wantRows {
		got := f.readMessage(t, conn)
		if got.Type != "row" {
			t.Fatalf("expected row frame, got type=%q", got.Type)
		}
		if len(got.Values) != len(want) {
			t.Fatalf("row arity = %d; want %d", len(got.Values), len(want))
		}
		for i, v := range want {
			if got.Values[i] != v {
				t.Errorf("row[%d] = %q; want %q", i, got.Values[i], v)
			}
		}
	}

	end := f.readMessage(t, conn)
	if end.Type != "end" {
		t.Fatalf("final frame type = %q; want end", end.Type)
	}
	if end.RowCount != 3 {
		t.Errorf("end.row_count = %d; want 3", end.RowCount)
	}

	// The audit sink should have one row matching the query, with
	// an output hash that is the SHA-256 of the canonical
	// columns/rows stream.
	captured := f.sink.snapshot()
	if len(captured) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(captured))
	}
	row := captured[0]
	if row.SessionID != "ses-01" {
		t.Errorf("audit session_id = %q; want ses-01", row.SessionID)
	}
	if row.Sequence != 1 {
		t.Errorf("audit sequence = %d; want 1", row.Sequence)
	}
	if row.Input != "SELECT id, name FROM users ORDER BY id" {
		t.Errorf("audit input = %q; want SQL text", row.Input)
	}
	if row.RiskFlag != nil {
		t.Errorf("audit risk_flag = %v; want nil for allow path", row.RiskFlag)
	}
	if row.OutputHash == "" {
		t.Errorf("audit output_hash empty; want SHA-256 hex")
	}

	// And it must equal the deterministic hash of the streamed
	// data (columns + rows separators + NUL separator + NL).
	if want := expectedSQLConsoleOutputHash([]string{"id", "name"}, wantRows); row.OutputHash != want {
		t.Errorf("audit output_hash = %q; want %q", row.OutputHash, want)
	}
}

// TestSQLConsole_DenyQuery_ReturnsErrorAndAuditsRisk verifies the
// deny path: policy returns deny, the operator receives a structured
// policy_deny error, and the audit row carries the "policy:deny"
// risk flag.
func TestSQLConsole_DenyQuery_ReturnsErrorAndAuditsRisk(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.policy.decide = func(input string) (string, string, error) {
		if strings.Contains(strings.ToLower(input), "delete") {
			return "deny", "destructive DML is not permitted on prod assets", nil
		}
		return "allow", "", nil
	}
	conn := f.dial(t)
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "DELETE FROM users"})

	msg := f.readMessage(t, conn)
	if msg.Type != "error" {
		t.Fatalf("frame type = %q; want error", msg.Type)
	}
	if msg.Code != "policy_deny" {
		t.Errorf("error.code = %q; want policy_deny", msg.Code)
	}
	if !strings.Contains(msg.Message, "destructive DML") {
		t.Errorf("error.message = %q; want policy reason", msg.Message)
	}

	captured := f.sink.snapshot()
	if len(captured) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(captured))
	}
	row := captured[0]
	if row.Input != "DELETE FROM users" {
		t.Errorf("audit input = %q; want DELETE statement", row.Input)
	}
	if row.RiskFlag == nil || *row.RiskFlag != "policy:deny" {
		t.Errorf("audit risk_flag = %v; want policy:deny", row.RiskFlag)
	}
	if row.OutputHash != "" {
		t.Errorf("audit output_hash = %q; want empty (denied query never ran)", row.OutputHash)
	}
}

// TestSQLConsole_StepUpQuery_FlagsAuditButStillRuns verifies the
// step_up path: policy returns step_up; the query still proceeds
// (Phase 1 surfaces step_up as a risk flag, the mobile MFA loop
// gates the next request). The audit row carries "policy:step_up".
func TestSQLConsole_StepUpQuery_FlagsAuditButStillRuns(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.policy.decide = func(_ string) (string, string, error) {
		return "step_up", "sudo-equivalent requires mobile MFA", nil
	}
	conn := f.dial(t)
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "SELECT 1"})

	cols := f.readMessage(t, conn)
	if cols.Type != "columns" {
		t.Fatalf("expected columns frame; got %q", cols.Type)
	}
	row := f.readMessage(t, conn)
	if row.Type != "row" {
		t.Fatalf("expected row frame; got %q", row.Type)
	}
	end := f.readMessage(t, conn)
	if end.Type != "end" {
		t.Fatalf("expected end frame; got %q", end.Type)
	}

	captured := f.sink.snapshot()
	if len(captured) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(captured))
	}
	if captured[0].RiskFlag == nil || *captured[0].RiskFlag != "policy:step_up" {
		t.Errorf("audit risk_flag = %v; want policy:step_up", captured[0].RiskFlag)
	}
}

// TestSQLConsole_PolicyErrorFailsOpen verifies the fail-open
// semantics: a policy evaluator that errors out is treated as
// "allow", so the operator's session is not broken by a transient
// backend issue. This mirrors the PG / MySQL listeners.
func TestSQLConsole_PolicyErrorFailsOpen(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.policy.decide = func(_ string) (string, string, error) {
		return "", "", errors.New("ztna-api transient")
	}
	conn := f.dial(t)
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "SELECT 1"})

	if msg := f.readMessage(t, conn); msg.Type != "columns" {
		t.Fatalf("first frame type = %q; want columns (fail-open)", msg.Type)
	}
	_ = f.readMessage(t, conn) // row
	if end := f.readMessage(t, conn); end.Type != "end" {
		t.Fatalf("final frame type = %q; want end", end.Type)
	}
	captured := f.sink.snapshot()
	if len(captured) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(captured))
	}
	if captured[0].RiskFlag != nil {
		t.Errorf("audit risk_flag = %v; want nil (fail-open)", captured[0].RiskFlag)
	}
}

// TestSQLConsole_SequenceIncrements verifies sequence numbering
// across multiple queries on the same WebSocket session.
func TestSQLConsole_SequenceIncrements(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)
	for i := 0; i < 3; i++ {
		f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "SELECT 1"})
		// columns + row + end
		_ = f.readMessage(t, conn)
		_ = f.readMessage(t, conn)
		end := f.readMessage(t, conn)
		if end.Type != "end" {
			t.Fatalf("query %d: end frame type = %q", i, end.Type)
		}
	}
	captured := f.sink.snapshot()
	if len(captured) != 3 {
		t.Fatalf("audit rows = %d; want 3", len(captured))
	}
	for i, row := range captured {
		if row.Sequence != i+1 {
			t.Errorf("audit[%d].sequence = %d; want %d", i, row.Sequence, i+1)
		}
	}
}

// TestSQLConsole_BadMessageType returns a structured error but does
// not close the socket, so the operator can retry without losing
// session state.
func TestSQLConsole_BadMessageType(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)
	f.send(t, conn, map[string]string{"type": "ping"})
	msg := f.readMessage(t, conn)
	if msg.Type != "error" || msg.Code != "bad_request" {
		t.Fatalf("got %+v; want bad_request error", msg)
	}
	if len(f.sink.snapshot()) != 0 {
		t.Errorf("audit rows = %d; want 0 for rejected non-query frame", len(f.sink.snapshot()))
	}

	// Socket still usable.
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "SELECT 1"})
	if c := f.readMessage(t, conn); c.Type != "columns" {
		t.Fatalf("after bad frame: type = %q; want columns", c.Type)
	}
}

// TestSQLConsole_EmptySQL is a guardrail: empty SQL bodies return an
// error frame instead of being sent to the database.
func TestSQLConsole_EmptySQL(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "   \t\n  "})
	msg := f.readMessage(t, conn)
	if msg.Type != "error" || msg.Code != "bad_request" {
		t.Fatalf("got %+v; want bad_request error for empty SQL", msg)
	}
	if len(f.sink.snapshot()) != 0 {
		t.Errorf("audit rows = %d; want 0 for empty SQL", len(f.sink.snapshot()))
	}
}

// TestSQLConsole_BadJSON tolerates malformed JSON without closing
// the socket; the operator gets an error frame.
func TestSQLConsole_BadJSON(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)
	if err := conn.WriteMessage(websocket.TextMessage, []byte("not-json")); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	msg := f.readMessage(t, conn)
	if msg.Type != "error" || msg.Code != "bad_request" {
		t.Fatalf("got %+v; want bad_request error", msg)
	}
}

// TestSQLConsole_SQLExecError surfaces upstream errors as a
// structured exec error frame and captures the failed query in the
// audit row.
func TestSQLConsole_SQLExecError(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)
	f.send(t, conn, sqlConsoleClientMessage{Type: "query", SQL: "SELECT * FROM nonexistent_table"})
	msg := f.readMessage(t, conn)
	if msg.Type != "error" || msg.Code != "exec" {
		t.Fatalf("got %+v; want exec error", msg)
	}
	captured := f.sink.snapshot()
	if len(captured) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(captured))
	}
	if captured[0].Input != "SELECT * FROM nonexistent_table" {
		t.Errorf("audit input = %q", captured[0].Input)
	}
	if captured[0].RiskFlag == nil || *captured[0].RiskFlag != "exec:error" {
		t.Errorf("audit risk_flag = %v; want exec:error", captured[0].RiskFlag)
	}
}

// TestSQLConsole_MissingToken returns 401 without upgrading.
func TestSQLConsole_MissingToken(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	url := strings.TrimSuffix(f.dialURL, "/?token=t1") + "/"
	url = strings.Replace(url, "ws://", "http://", 1)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", resp.StatusCode)
	}
	if f.auth.calls != 0 {
		t.Errorf("authorizer.calls = %d; want 0 (missing token short-circuits)", f.auth.calls)
	}
}

// TestSQLConsole_BadToken returns 401 when the authorizer rejects.
func TestSQLConsole_BadToken(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.auth.wantErr = errors.New("invalid token")
	url := strings.Replace(f.dialURL, "ws://", "http://", 1)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", resp.StatusCode)
	}
}

// TestSQLConsole_NonDBProtocol returns 400 for SSH / K8s sessions
// so an operator cannot accidentally route a non-DB session through
// the SQL console.
func TestSQLConsole_NonDBProtocol(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.auth.session.Protocol = "ssh"
	url := strings.Replace(f.dialURL, "ws://", "http://", 1)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 for non-db protocol", resp.StatusCode)
	}
}

// TestSQLConsole_InjectFailure returns 502 when the secret injector
// is unavailable.
func TestSQLConsole_InjectFailure(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.injector.wantErr = errors.New("vault unreachable")
	url := strings.Replace(f.dialURL, "ws://", "http://", 1)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d; want 502 for inject failure", resp.StatusCode)
	}
}

// TestSQLConsole_DialFailure returns 502 when the database dialer
// can't establish a connection to the asset.
func TestSQLConsole_DialFailure(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	f.handler.dialDB = func(_ context.Context, _ *AuthorizedSession, _ string, _ []byte) (*sql.DB, error) {
		return nil, errors.New("connection refused")
	}
	url := strings.Replace(f.dialURL, "ws://", "http://", 1)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d; want 502 for dial failure", resp.StatusCode)
	}
}

// TestSQLConsole_NewHandlerValidation covers the constructor's
// nil-receiver guards.
func TestSQLConsole_NewHandlerValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewDBSQLConsoleHandler(DBSQLConsoleConfig{}); err == nil {
		t.Fatal("expected error for empty config")
	}
	if _, err := NewDBSQLConsoleHandler(DBSQLConsoleConfig{
		Authorizer: &stubSQLConsoleAuthorizer{},
	}); err == nil {
		t.Fatal("expected error when Injector missing")
	}
	if _, err := NewDBSQLConsoleHandler(DBSQLConsoleConfig{
		Authorizer: &stubSQLConsoleAuthorizer{},
		Injector:   &stubSQLConsoleInjector{},
	}); err != nil {
		t.Fatalf("minimal config should succeed: %v", err)
	}
}

// TestSQLConsole_IsDBProtocol covers the protocol whitelist used to
// reject non-DB sessions before the upgrade.
func TestSQLConsole_IsDBProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"postgres", true},
		{"POSTGRES", true},
		{"postgresql", true},
		{"mysql", true},
		{"MariaDB", true},
		{"ssh", false},
		{"kubernetes", false},
		{"", false},
		{"http", false},
	}
	for _, tc := range tests {
		if got := isDBProtocol(tc.in); got != tc.want {
			t.Errorf("isDBProtocol(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

// TestSQLConsole_SequenceDoesNotAdvanceOnRejectedMessages verifies
// the audit-trail sequence number is only consumed by queries that
// reached handleQuery, not by rejected control-frame messages
// (bad JSON, unsupported message type, empty SQL). A dense
// per-query sequence is the only way reviewers can tell whether
// the audit log is complete; if rejected messages bumped the
// counter the gap would be indistinguishable from a lost row.
func TestSQLConsole_SequenceDoesNotAdvanceOnRejectedMessages(t *testing.T) {
	t.Parallel()
	f := newSQLConsoleFixture(t)
	conn := f.dial(t)

	// Interleave rejects + successes — each reject must NOT consume
	// a sequence number.
	send := func(msg interface{}) { f.send(t, conn, msg) }
	drainErr := func() {
		if got := f.readMessage(t, conn); got.Type != "error" {
			t.Fatalf("expected error frame, got %+v", got)
		}
	}
	drainQuery := func() {
		// columns + row + end (canned single-row result)
		_ = f.readMessage(t, conn)
		_ = f.readMessage(t, conn)
		if end := f.readMessage(t, conn); end.Type != "end" {
			t.Fatalf("expected end frame, got %+v", end)
		}
	}

	send(map[string]string{"type": "ping"}) // bad type
	drainErr()
	send(sqlConsoleClientMessage{Type: "query", SQL: "   \n  "}) // empty
	drainErr()
	send(sqlConsoleClientMessage{Type: "query", SQL: "SELECT 1"})
	drainQuery()
	send(map[string]string{"type": "ping"}) // another bad type
	drainErr()
	send(sqlConsoleClientMessage{Type: "query", SQL: "SELECT 1"})
	drainQuery()

	captured := f.sink.snapshot()
	if len(captured) != 2 {
		t.Fatalf("audit rows = %d; want exactly 2 (one per successful query)", len(captured))
	}
	if captured[0].Sequence != 1 {
		t.Errorf("audit[0].sequence = %d; want 1", captured[0].Sequence)
	}
	if captured[1].Sequence != 2 {
		t.Errorf("audit[1].sequence = %d; want 2 (must not skip on rejected frames)", captured[1].Sequence)
	}
}

// TestQuoteDSNValue locks in the set of characters that force
// quoting of a libpq key=value DSN token. The set must include any
// whitespace (space / tab / newline / CR) and `=` because libpq
// uses both as token boundaries, plus `'` and `\\` because those
// are the quote and escape characters themselves. Missing any of
// these in the set lets a credential containing that byte either
// (a) silently truncate to whatever appears before the byte or
// (b) inject arbitrary DSN parameters like `sslmode=disable`,
// `host=attacker.example`, etc.
func TestQuoteDSNValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		// Bare values (no special bytes) pass through verbatim.
		{"plain", "alice", "alice"},
		{"empty", "", ""},
		{"digits", "12345", "12345"},
		// Whitespace forces quoting.
		{"space", "alice bob", "'alice bob'"},
		{"tab", "a\tb", "'a\tb'"},
		{"newline", "alice\nbob", "'alice\nbob'"},
		{"carriage_return", "alice\rbob", "'alice\rbob'"},
		{"crlf", "alice\r\nbob", "'alice\r\nbob'"},
		// `=` forces quoting — otherwise libpq would interpret the
		// right-hand side as another DSN parameter.
		{"equals", "abc=def", "'abc=def'"},
		{"injection_attempt", "abc=sslmode=disable", "'abc=sslmode=disable'"},
		// Quote/backslash are escaped per libpq rules.
		{"single_quote", "o'brien", `'o\'brien'`},
		{"backslash", `a\b`, `'a\\b'`},
		{"quote_and_backslash", `o'br\ian`, `'o\'br\\ian'`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := quoteDSNValue(tc.in); got != tc.want {
				t.Errorf("quoteDSNValue(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// expectedSQLConsoleOutputHash recomputes the SHA-256 hash the
// handler produces over a result-set, mirroring the in-handler
// hashing logic. Used so the audit-row assertion in the happy-path
// test does not have to hardcode a hex digest.
func expectedSQLConsoleOutputHash(columns []string, rows [][]string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(columns, "|")))
	h.Write([]byte{'\n'})
	for _, row := range rows {
		for _, v := range row {
			if v == "" {
				h.Write([]byte{0})
				continue
			}
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
