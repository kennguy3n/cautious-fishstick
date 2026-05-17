package gateway

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	gomysql "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver used by the SQL console for postgres assets
)

// DBSQLConsoleHandler is the browser-facing SQL console — a
// WebSocket endpoint that accepts SQL statements from an operator
// browser session, evaluates them against the same command policy
// engine the PG / MySQL listeners use, executes the statement
// against the target database (using credentials injected for the
// session), captures the statement + result-set hash as an audit
// row, and streams structured rows back over the same WebSocket.
//
// Wire format (JSON, newline-free per WebSocket message):
//
// client → server:
//
//	{"type":"query","sql":"SELECT 1"}
//
// server → client (one or more of):
//
//	{"type":"columns","columns":["col1","col2"]}
//	{"type":"row","values":["foo","bar"]}            // repeated, one per row
//	{"type":"end","row_count":42,"duration_ms":15}
//	{"type":"error","code":"policy_deny","message":"..."}
//	{"type":"error","code":"exec","message":"..."}
//
// One WebSocket = one session = one database/sql connection. The
// handler intentionally holds a single *sql.Conn for the lifetime
// of the socket so transaction state survives across messages.
//
// Auth: the connect token comes in as ?token=<one-shot> on the
// upgrade request — same one-shot semantics the SSH listener
// expects, validated through the same SessionAuthorizer.
type DBSQLConsoleHandler struct {
	authorizer    SessionAuthorizer
	injector      SecretInjector
	commandSink   CommandSink
	commandPolicy CommandPolicyEvaluator
	upgrader      websocket.Upgrader
	now           func() time.Time

	// dialDB is the dependency-injection seam for tests. Production
	// resolves a (*sql.DB, *sql.Conn) via the protocol-specific
	// driver (pgx, mysql). The function returns the open conn the
	// handler reads through, the *sql.DB so the handler can close
	// the pool, and a logical name (e.g., "postgres@10.0.0.5:5432
	// db=app") used in the audit row's host metadata.
	dialDB DBSQLConsoleDialer

	// readDeadline and writeDeadline bound how long the handler
	// will wait for a single message before tearing the socket
	// down. Defaults: 5 min read, 30 s write.
	readDeadline  time.Duration
	writeDeadline time.Duration

	// maxRowsPerQuery caps the rows streamed for a single
	// statement to avoid wedging a browser with an unbounded
	// SELECT. Default 10_000.
	maxRowsPerQuery int

	// queryTimeout bounds each query's execution against the
	// target. Default 60 s.
	queryTimeout time.Duration
}

// DBSQLConsoleDialer abstracts the protocol-specific
// connection-establishment step so tests can substitute an in-memory
// stand-in. Implementations must return a *sql.DB rooted on a
// connection that uses the supplied credential.
type DBSQLConsoleDialer func(
	ctx context.Context,
	session *AuthorizedSession,
	credentialType string,
	credential []byte,
) (*sql.DB, error)

// DBSQLConsoleConfig wires the handler. Authorizer + Injector
// are required (the handler refuses to start without them); the
// remaining fields are optional and default to sensible production
// values.
type DBSQLConsoleConfig struct {
	Authorizer    SessionAuthorizer
	Injector      SecretInjector
	CommandSink   CommandSink
	CommandPolicy CommandPolicyEvaluator

	// Dialer overrides the production database/sql dialer. Tests
	// pass an in-memory stand-in; leave nil in production to use
	// the default pgx / mysql dialers.
	Dialer DBSQLConsoleDialer

	// Upgrader can override the WebSocket upgrader (for, e.g., a
	// stricter CheckOrigin). When nil the handler installs a
	// permissive upgrader suitable for same-origin frontends.
	Upgrader *websocket.Upgrader

	// MaxRowsPerQuery, QueryTimeout, ReadDeadline, and
	// WriteDeadline override the defaults documented on
	// DBSQLConsoleHandler.
	MaxRowsPerQuery int
	QueryTimeout    time.Duration
	ReadDeadline    time.Duration
	WriteDeadline   time.Duration
}

// NewDBSQLConsoleHandler wires a handler bound to the supplied
// config. The handler is safe for concurrent use across many
// simultaneous browser sessions; each session owns its own goroutine
// and *sql.DB instance.
func NewDBSQLConsoleHandler(cfg DBSQLConsoleConfig) (*DBSQLConsoleHandler, error) {
	if cfg.Authorizer == nil {
		return nil, errors.New("gateway: DBSQLConsoleConfig.Authorizer is required")
	}
	if cfg.Injector == nil {
		return nil, errors.New("gateway: DBSQLConsoleConfig.Injector is required")
	}
	h := &DBSQLConsoleHandler{
		authorizer:      cfg.Authorizer,
		injector:        cfg.Injector,
		commandSink:     cfg.CommandSink,
		commandPolicy:   cfg.CommandPolicy,
		now:             time.Now,
		dialDB:          cfg.Dialer,
		readDeadline:    cfg.ReadDeadline,
		writeDeadline:   cfg.WriteDeadline,
		maxRowsPerQuery: cfg.MaxRowsPerQuery,
		queryTimeout:    cfg.QueryTimeout,
	}
	if h.dialDB == nil {
		h.dialDB = defaultDBSQLConsoleDialer
	}
	if h.readDeadline <= 0 {
		h.readDeadline = 5 * time.Minute
	}
	if h.writeDeadline <= 0 {
		h.writeDeadline = 30 * time.Second
	}
	if h.maxRowsPerQuery <= 0 {
		h.maxRowsPerQuery = 10_000
	}
	if h.queryTimeout <= 0 {
		h.queryTimeout = 60 * time.Second
	}
	if cfg.Upgrader != nil {
		h.upgrader = *cfg.Upgrader
	} else {
		h.upgrader = websocket.Upgrader{
			ReadBufferSize:  4 << 10,
			WriteBufferSize: 4 << 10,
			// CheckOrigin is permissive by default because the
			// expected deployment topology is a same-origin Next.js
			// app proxying through ztna-api → pam-gateway. A
			// reverse-proxy stack (ingress, oauth2-proxy) gates the
			// origin upstream; the handler relies on the connect
			// token for trust, not the origin header.
			CheckOrigin: func(*http.Request) bool { return true },
		}
	}
	return h, nil
}

// SetNow overrides the time source. Tests pin time so command-row
// timestamps are deterministic. nil resets to time.Now.
func (h *DBSQLConsoleHandler) SetNow(now func() time.Time) {
	if h == nil {
		return
	}
	if now == nil {
		h.now = time.Now
		return
	}
	h.now = now
}

// ServeHTTP upgrades the connection, validates the connect token,
// fetches the session's credential, opens a database/sql connection
// to the asset, and pumps query messages until the client
// disconnects or a fatal error occurs.
func (h *DBSQLConsoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		http.Error(w, "sql console not configured", http.StatusServiceUnavailable)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, "missing connect token", http.StatusUnauthorized)
		return
	}
	// We deliberately authorise BEFORE upgrading so a bad token
	// returns a 401 the browser can surface. After upgrade the only
	// signalling channel is the WebSocket itself.
	session, err := h.authorizer.AuthorizeConnectToken(r.Context(), token)
	if err != nil {
		log.Printf("gateway: sql-console: authorize: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !isDBProtocol(session.Protocol) {
		http.Error(w, "session is not a database session", http.StatusBadRequest)
		return
	}

	secretType, credential, err := h.injector.InjectSecret(r.Context(), session.SessionID, session.AccountID)
	if err != nil {
		log.Printf("gateway: sql-console: inject: %v", err)
		http.Error(w, "credential unavailable", http.StatusBadGateway)
		return
	}
	// Defensive: clear the credential bytes after the database/sql
	// pool is up (the bytes were copied into the DSN inside the
	// dialer; holding them past that point only widens the
	// in-memory window). We zero on every return path below.
	defer zeroBytes(credential)

	dialCtx, dialCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dialCancel()
	db, err := h.dialDB(dialCtx, session, secretType, credential)
	if err != nil {
		log.Printf("gateway: sql-console: dial: %v", err)
		http.Error(w, "database connection failed", http.StatusBadGateway)
		return
	}
	defer db.Close()

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("gateway: sql-console: upgrade: %v", err)
		return
	}
	defer conn.Close()

	if err := h.pump(r.Context(), conn, db, session); err != nil && !isPeerClose(err) {
		log.Printf("gateway: sql-console: pump: session=%s err=%v", session.SessionID, err)
	}
}

// pump is the per-session message loop. It reads a query message,
// evaluates policy, captures the audit row, executes the statement,
// and streams rows back. The loop continues until the peer closes
// or an unrecoverable error occurs.
func (h *DBSQLConsoleHandler) pump(
	ctx context.Context,
	conn *websocket.Conn,
	db *sql.DB,
	session *AuthorizedSession,
) error {
	for sequence := 1; ; sequence++ {
		// SetReadDeadline must use the real wall clock — h.now is
		// overridden in tests to pin audit-row timestamps, but the
		// underlying net.Conn always compares against time.Now().
		_ = conn.SetReadDeadline(time.Now().Add(h.readDeadline))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var msg sqlConsoleClientMessage
		if jerr := json.Unmarshal(raw, &msg); jerr != nil {
			if werr := h.writeError(conn, "bad_request", "malformed message: "+jerr.Error()); werr != nil {
				return werr
			}
			continue
		}
		if msg.Type != "query" {
			if werr := h.writeError(conn, "bad_request", fmt.Sprintf("unsupported message type %q", msg.Type)); werr != nil {
				return werr
			}
			continue
		}
		sql := strings.TrimSpace(msg.SQL)
		if sql == "" {
			if werr := h.writeError(conn, "bad_request", "empty sql"); werr != nil {
				return werr
			}
			continue
		}
		if err := h.handleQuery(ctx, conn, db, session, sequence, sql); err != nil {
			return err
		}
	}
}

// handleQuery is the per-query path. It is extracted so tests can
// exercise a single statement without driving a full WebSocket
// session.
func (h *DBSQLConsoleHandler) handleQuery(
	ctx context.Context,
	conn *websocket.Conn,
	db *sql.DB,
	session *AuthorizedSession,
	sequence int,
	sqlText string,
) error {
	start := h.now()
	policyAction, policyReason := h.evaluatePolicy(ctx, session, sqlText)

	if policyAction == "deny" {
		// Surface a structured error to the operator AND capture
		// the denied query as an audit row with risk_flag set so
		// the audit pipeline can highlight blocked attempts.
		h.appendAudit(ctx, session.SessionID, sequence, sqlText, "", "policy:deny", start)
		return h.writeError(conn, "policy_deny", policyReason)
	}

	riskFlag := ""
	if policyAction == "step_up" {
		// Phase 1 surfaces step_up as an audit risk flag; the
		// mobile MFA loop lives in Milestone 10. The query still
		// proceeds — the gating is downstream.
		riskFlag = "policy:step_up"
	}

	queryCtx, queryCancel := context.WithTimeout(ctx, h.queryTimeout)
	defer queryCancel()
	rows, err := db.QueryContext(queryCtx, sqlText)
	if err != nil {
		execErr := err
		h.appendAudit(ctx, session.SessionID, sequence, sqlText, "", "exec:error", start)
		return h.writeError(conn, "exec", execErr.Error())
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		h.appendAudit(ctx, session.SessionID, sequence, sqlText, "", "exec:error", start)
		return h.writeError(conn, "exec", err.Error())
	}
	if werr := h.writeJSON(conn, sqlConsoleServerMessage{Type: "columns", Columns: columns}); werr != nil {
		return werr
	}

	hasher := sha256.New()
	hasher.Write([]byte(strings.Join(columns, "|")))
	hasher.Write([]byte{'\n'})
	rowCount := 0
	for rows.Next() {
		if rowCount >= h.maxRowsPerQuery {
			// Drain remaining rows from the server-side cursor
			// but stop streaming to the operator.
			break
		}
		raw := make([]sql.RawBytes, len(columns))
		ptrs := make([]any, len(columns))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if scanErr := rows.Scan(ptrs...); scanErr != nil {
			h.appendAudit(ctx, session.SessionID, sequence, sqlText, hex.EncodeToString(hasher.Sum(nil)), "exec:error", start)
			return h.writeError(conn, "exec", scanErr.Error())
		}
		values := make([]string, len(raw))
		for i, b := range raw {
			if b == nil {
				values[i] = ""
				hasher.Write([]byte{0})
				continue
			}
			values[i] = string(b)
			hasher.Write(b)
			hasher.Write([]byte{0})
		}
		hasher.Write([]byte{'\n'})
		if werr := h.writeJSON(conn, sqlConsoleServerMessage{Type: "row", Values: values}); werr != nil {
			return werr
		}
		rowCount++
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		h.appendAudit(ctx, session.SessionID, sequence, sqlText, hex.EncodeToString(hasher.Sum(nil)), "exec:error", start)
		return h.writeError(conn, "exec", rowsErr.Error())
	}
	duration := h.now().Sub(start)
	finalHash := hex.EncodeToString(hasher.Sum(nil))
	if werr := h.writeJSON(conn, sqlConsoleServerMessage{
		Type:       "end",
		RowCount:   rowCount,
		DurationMS: duration.Milliseconds(),
	}); werr != nil {
		return werr
	}
	h.appendAudit(ctx, session.SessionID, sequence, sqlText, finalHash, riskFlag, start)
	return nil
}

// evaluatePolicy mirrors the fail-open semantics used by the PG /
// MySQL listeners: on any policy-side error the handler logs and
// allows the query. Tests assert on the (action, reason) tuple
// separately.
func (h *DBSQLConsoleHandler) evaluatePolicy(
	ctx context.Context,
	session *AuthorizedSession,
	sqlText string,
) (action, reason string) {
	if h.commandPolicy == nil {
		return "allow", ""
	}
	a, r, err := h.commandPolicy.EvaluateCommand(ctx, session.WorkspaceID, session.SessionID, sqlText)
	if err != nil {
		log.Printf("gateway: sql-console: policy evaluate: session=%s err=%v", session.SessionID, err)
		return "allow", ""
	}
	return a, r
}

// appendAudit fires-and-forgets a pam_session_commands row append
// to ztna-api. Failures are logged but do not break the operator's
// SQL session — the gateway's job is to serve queries; the audit
// pipeline retries via the control plane.
func (h *DBSQLConsoleHandler) appendAudit(
	ctx context.Context,
	sessionID string,
	sequence int,
	sqlText, outputHash, riskFlag string,
	start time.Time,
) {
	if h.commandSink == nil {
		return
	}
	in := AppendCommandInput{
		SessionID:  sessionID,
		Sequence:   sequence,
		Input:      sqlText,
		OutputHash: outputHash,
		Timestamp:  start.UTC(),
	}
	if riskFlag != "" {
		rf := riskFlag
		in.RiskFlag = &rf
	}
	if err := h.commandSink.AppendCommand(ctx, in); err != nil {
		log.Printf("gateway: sql-console: append-command: session=%s seq=%d err=%v", sessionID, sequence, err)
	}
}

// writeJSON marshals payload and writes it as a single text-frame
// WebSocket message, applying the configured write deadline so a
// hung peer cannot wedge the goroutine.
func (h *DBSQLConsoleHandler) writeJSON(conn *websocket.Conn, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("gateway: sql-console: marshal: %w", err)
	}
	// Same rationale as the read deadline: net.Conn's clock is the
	// real one, h.now is only for deterministic audit timestamps.
	_ = conn.SetWriteDeadline(time.Now().Add(h.writeDeadline))
	return conn.WriteMessage(websocket.TextMessage, body)
}

// writeError is a thin convenience that emits an error message in
// the canonical wire shape.
func (h *DBSQLConsoleHandler) writeError(conn *websocket.Conn, code, message string) error {
	return h.writeJSON(conn, sqlConsoleServerMessage{Type: "error", Code: code, Message: message})
}

// sqlConsoleClientMessage models a single inbound JSON frame.
type sqlConsoleClientMessage struct {
	Type string `json:"type"`
	SQL  string `json:"sql"`
}

// sqlConsoleServerMessage is the union of outbound message shapes.
// Fields not relevant to a particular Type omit cleanly via
// omitempty so clients can rely on JSON discriminator tags.
type sqlConsoleServerMessage struct {
	Type       string   `json:"type"`
	Columns    []string `json:"columns,omitempty"`
	Values     []string `json:"values,omitempty"`
	RowCount   int      `json:"row_count,omitempty"`
	DurationMS int64    `json:"duration_ms,omitempty"`
	Code       string   `json:"code,omitempty"`
	Message    string   `json:"message,omitempty"`
}

// isDBProtocol returns true for the protocol identifiers the SQL
// console knows how to dial. The SSH / K8s protocols stay on their
// dedicated listeners.
func isDBProtocol(p string) bool {
	switch strings.ToLower(p) {
	case "postgres", "postgresql", "mysql", "mariadb":
		return true
	}
	return false
}

// isPeerClose folds normal WebSocket close codes into a "no log"
// case so the operator's clean exit does not spam the server log.
func isPeerClose(err error) bool {
	if err == nil {
		return true
	}
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
	) {
		return true
	}
	return false
}

// zeroBytes overwrites the supplied slice in place. Used to clear
// credential plaintext from the handler's stack frame after the
// dialer has consumed it.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// defaultDBSQLConsoleDialer is the production dialer. It opens a
// database/sql pool against the target asset using the credential
// type injected by ztna-api. Tests substitute a custom dialer.
func defaultDBSQLConsoleDialer(
	ctx context.Context,
	session *AuthorizedSession,
	credentialType string,
	credential []byte,
) (*sql.DB, error) {
	switch strings.ToLower(session.Protocol) {
	case "postgres", "postgresql":
		dsn := buildPostgresDSN(session, credentialType, credential)
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("gateway: sql-console: open postgres: %w", err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, fmt.Errorf("gateway: sql-console: ping postgres: %w", err)
		}
		return db, nil
	case "mysql", "mariadb":
		cfg := gomysql.NewConfig()
		cfg.Net = "tcp"
		cfg.Addr = fmt.Sprintf("%s:%d", session.TargetHost, session.TargetPort)
		cfg.User = session.Username
		cfg.Passwd = string(credential)
		cfg.AllowNativePasswords = true
		// We deliberately do NOT pin a DB name — the operator may
		// USE <db> from the console.
		db, err := sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			return nil, fmt.Errorf("gateway: sql-console: open mysql: %w", err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, fmt.Errorf("gateway: sql-console: ping mysql: %w", err)
		}
		return db, nil
	}
	return nil, fmt.Errorf("gateway: sql-console: unsupported protocol %q", session.Protocol)
}

// buildPostgresDSN constructs a libpq key=value DSN with the
// credential interpolated as the password. We use key=value form
// rather than URL form because it tolerates passwords with special
// characters without manual escaping.
func buildPostgresDSN(session *AuthorizedSession, _ string, credential []byte) string {
	// pgx/stdlib accepts key=value style DSNs as well as
	// postgres:// URIs.
	var b strings.Builder
	fmt.Fprintf(&b, "host=%s ", session.TargetHost)
	fmt.Fprintf(&b, "port=%d ", session.TargetPort)
	fmt.Fprintf(&b, "user=%s ", quoteDSNValue(session.Username))
	fmt.Fprintf(&b, "password=%s ", quoteDSNValue(string(credential)))
	// sslmode=prefer matches the libpq default. Operators that
	// require TLS can install a stricter mode via the workspace's
	// connector config (out of scope for the console handler).
	fmt.Fprintf(&b, "sslmode=prefer")
	return b.String()
}

// quoteDSNValue wraps v in single quotes (DSN convention) when it
// contains characters that would terminate a bare DSN token.
func quoteDSNValue(v string) string {
	needsQuote := strings.ContainsAny(v, " \t'\\")
	if !needsQuote {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return "'" + v + "'"
}
