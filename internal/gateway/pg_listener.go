package gateway

import (
	"context"
	"crypto/md5" //nolint:gosec // PostgreSQL wire protocol requires MD5 for the AuthenticationMD5Password handshake
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// PGListenerConfig wires the PostgreSQL wire-protocol proxy into
// the gateway's standard authorize → inject → record → audit
// pipeline. The contract intentionally mirrors SSHListenerConfig so
// router code can compose listeners uniformly.
//
// Authorize semantics: the operator's `psql` client supplies its
// one-shot connect token in the password field of the startup
// handshake (typically via PGPASSWORD). The listener responds with
// AuthenticationCleartextPassword, reads the PasswordMessage, and
// validates the token through Authorizer before talking to any
// upstream cluster.
type PGListenerConfig struct {
	Port            int
	Authorizer      SessionAuthorizer
	Injector        SecretInjector
	ReplayStore     ReplayStore
	CommandSink     CommandSink
	ShutdownTimeout time.Duration

	// CommandPolicy evaluates each Simple-Query against the
	// pam_command_policies rule set. Optional — when nil the
	// listener forwards every query unchanged. When set, "deny"
	// rules short-circuit the query before it reaches the
	// upstream cluster (the operator sees a synthesised
	// ErrorResponse + ReadyForQuery so libpq stays happy) and
	// "step_up" rules raise a risk flag on the audit row.
	CommandPolicy CommandPolicyEvaluator
}

// PGListener is the production PostgreSQL gateway.
type PGListener struct {
	cfg PGListenerConfig
}

// NewPGListener validates the supplied configuration and returns a
// listener that is ready to Serve. Errors carry the field that was
// missing so a misconfiguration is obvious from the boot log.
func NewPGListener(cfg PGListenerConfig) (*PGListener, error) {
	if cfg.Authorizer == nil {
		return nil, errors.New("gateway: PGListenerConfig.Authorizer is required")
	}
	if cfg.Injector == nil {
		return nil, errors.New("gateway: PGListenerConfig.Injector is required")
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	return &PGListener{cfg: cfg}, nil
}

// Serve binds a TCP listener on cfg.Port and accepts connections
// until ctx is cancelled. The actual listener bookkeeping lives in
// serveListener so tests can drive a pre-bound listener.
func (l *PGListener) Serve(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", l.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("gateway: pg listen %s: %w", addr, err)
	}
	log.Printf("gateway: pg listener bound on %s", ln.Addr().String())
	return l.serveListener(ctx, ln)
}

// serveListener accepts connections on ln until ctx is cancelled or
// the underlying listener errors. Each connection is handled in a
// fresh goroutine that owns the operator + upstream conns.
func (l *PGListener) serveListener(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("gateway: pg accept: %w", err)
		}
		go l.handleConn(ctx, conn)
	}
}

// handleConn owns the lifetime of a single operator connection.
// The function is intentionally tall — the PG protocol is stateful
// enough that splitting it across helpers without sharing several
// hidden references is less readable than keeping the linear flow.
func (l *PGListener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// The recorder taps raw operator-side bytes in both
	// directions so the replay blob captures the full wire
	// transcript — including any prepared statements, parameter
	// values, and result rows. We tee at the conn level (before
	// pgproto3 decodes) so a future replay tool can re-parse the
	// stream exactly as it was on the wire.
	var recorderInputTap, recorderOutputTap *recorderTeeSink
	var recorder *IORecorder

	authCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// First, complete the operator handshake. Until we have a
	// validated AuthorizedSession we don't know the session ID to
	// open a recorder with, so we buffer the early bytes in an
	// in-memory sink that we replay into the real recorder once we
	// know the session ID.
	earlyIn := &bytesSink{}
	earlyOut := &bytesSink{}
	teeIn := io.TeeReader(conn, earlyIn)
	teeOut := io.MultiWriter(conn, earlyOut)
	backend := pgproto3.NewBackend(teeIn, teeOut)

	session, database, err := l.authenticateOperator(authCtx, backend, teeOut)
	if err != nil {
		log.Printf("gateway: pg authenticate operator: %v", err)
		sendFatalError(backend, "28000", "authentication rejected")
		return
	}

	// Now stand up the real recorder + parser bound to the
	// session id and seed them with the bytes we already saw.
	if l.cfg.ReplayStore != nil {
		r, rerr := NewIORecorder(session.SessionID, l.cfg.ReplayStore, IORecorderConfig{})
		if rerr != nil {
			log.Printf("gateway: pg new recorder session=%s: %v", session.SessionID, rerr)
		} else {
			recorder = r
			if earlyIn.Len() > 0 {
				recorder.Record(DirectionInput, earlyIn.Bytes())
			}
			if earlyOut.Len() > 0 {
				recorder.Record(DirectionOutput, earlyOut.Bytes())
			}
		}
	}
	var parser *CommandParser
	if l.cfg.CommandSink != nil {
		p, perr := NewCommandParser(session.SessionID, l.cfg.CommandSink, CommandParserConfig{})
		if perr != nil {
			log.Printf("gateway: pg new parser session=%s: %v", session.SessionID, perr)
		} else {
			parser = p
		}
	}

	// Rebind the backend to taps that route into the recorder.
	if recorder != nil {
		recorderInputTap = newRecorderTeeSink(recorder, DirectionInput)
		recorderOutputTap = newRecorderTeeSink(recorder, DirectionOutput)
		backend = pgproto3.NewBackend(io.TeeReader(conn, recorderInputTap), io.MultiWriter(conn, recorderOutputTap))
	}

	// Dial the upstream and complete its handshake using the
	// injected credentials.
	upstreamConn, frontend, err := l.connectUpstream(authCtx, session, database)
	if err != nil {
		log.Printf("gateway: pg connect upstream session=%s: %v", session.SessionID, err)
		sendFatalError(backend, "08001", fmt.Sprintf("upstream unavailable: %v", err))
		l.flushTelemetry(ctx, recorder, parser)
		return
	}
	defer upstreamConn.Close()

	// At this point both sides are happy — tell the operator the
	// session is open.
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		log.Printf("gateway: pg flush ready-for-query session=%s: %v", session.SessionID, err)
		l.flushTelemetry(ctx, recorder, parser)
		return
	}

	// Run the proxy phase. proxyQueries is the single-goroutine
	// request/response loop — see its doc-comment for the design
	// rationale.
	if err := l.proxyQueries(ctx, session, backend, frontend, parser); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("gateway: pg proxy loop session=%s: %v", session.SessionID, err)
	}

	l.flushTelemetry(ctx, recorder, parser)
}

// authenticateOperator runs the SSL gate + startup + cleartext
// password handshake on the operator side. The password field is
// the one-shot connect token; it is validated against the control
// plane before any upstream traffic is allowed.
//
// rawWriter is the same writer the backend wraps — we need it
// directly so we can send the single-byte 'N' reply that PG
// expects after SSLRequest / GSSEncRequest. pgproto3.Backend
// intentionally hides its writer; rather than fight the abstraction
// we just capture our copy at the call site.
func (l *PGListener) authenticateOperator(ctx context.Context, backend *pgproto3.Backend, rawWriter io.Writer) (*AuthorizedSession, string, error) {
	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return nil, "", fmt.Errorf("read startup: %w", err)
	}
	// Some clients (libpq, pgx) send SSLRequest first. We do not
	// terminate TLS at the listener (yet); refuse and wait for
	// the real StartupMessage. A future milestone can add TLS.
	if _, ok := msg.(*pgproto3.SSLRequest); ok {
		// 'N' = SSL not supported. The client should retry with
		// a plain StartupMessage.
		if _, err := rawWriter.Write([]byte{'N'}); err != nil {
			return nil, "", fmt.Errorf("write ssl-no: %w", err)
		}
		msg, err = backend.ReceiveStartupMessage()
		if err != nil {
			return nil, "", fmt.Errorf("read startup after ssl-no: %w", err)
		}
	}
	// GSSAPIRequest is also legal; reject the same way. We
	// surface it as a "not supported" message rather than EOF so
	// the client gets a clear failure.
	if _, ok := msg.(*pgproto3.GSSEncRequest); ok {
		if _, err := rawWriter.Write([]byte{'N'}); err != nil {
			return nil, "", fmt.Errorf("write gss-no: %w", err)
		}
		msg, err = backend.ReceiveStartupMessage()
		if err != nil {
			return nil, "", fmt.Errorf("read startup after gss-no: %w", err)
		}
	}

	startup, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return nil, "", fmt.Errorf("expected StartupMessage, got %T", msg)
	}
	database := startup.Parameters["database"]
	if database == "" {
		database = startup.Parameters["user"] // PG default
	}

	// Ask the client for a cleartext password.
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return nil, "", fmt.Errorf("set auth type: %w", err)
	}
	if err := backend.Flush(); err != nil {
		return nil, "", fmt.Errorf("flush auth challenge: %w", err)
	}

	resp, err := backend.Receive()
	if err != nil {
		return nil, "", fmt.Errorf("read password message: %w", err)
	}
	pwMsg, ok := resp.(*pgproto3.PasswordMessage)
	if !ok {
		return nil, "", fmt.Errorf("expected PasswordMessage, got %T", resp)
	}
	if l.cfg.Authorizer == nil {
		return nil, "", errors.New("authorizer not configured")
	}
	session, err := l.cfg.Authorizer.AuthorizeConnectToken(ctx, pwMsg.Password)
	if err != nil {
		return nil, "", fmt.Errorf("authorize connect token: %w", err)
	}
	return session, database, nil
}

// connectUpstream dials the upstream PG instance, runs the startup
// + auth handshake with the injected credential, and reads through
// the trailing ParameterStatus / BackendKeyData / ReadyForQuery
// messages. The connection is returned in a "ready for query"
// state, paired with the pgproto3.Frontend bound to it.
func (l *PGListener) connectUpstream(ctx context.Context, session *AuthorizedSession, database string) (net.Conn, *pgproto3.Frontend, error) {
	if l.cfg.Injector == nil {
		return nil, nil, errors.New("injector not configured")
	}
	secretType, plaintext, err := l.cfg.Injector.InjectSecret(ctx, session.SessionID, session.AccountID)
	if err != nil {
		return nil, nil, fmt.Errorf("inject secret: %w", err)
	}
	switch secretType {
	case "pg_password", "password", "":
		// ok — plaintext is the upstream password
	default:
		return nil, nil, fmt.Errorf("unsupported secret_type %q for pg listener", secretType)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addr := fmt.Sprintf("%s:%d", session.TargetHost, session.TargetPort)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream %s: %w", addr, err)
	}

	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     session.Username,
			"database": database,
		},
	})
	if err := frontend.Flush(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("flush upstream startup: %w", err)
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("read upstream startup response: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			// keep reading until ReadyForQuery
		case *pgproto3.AuthenticationCleartextPassword:
			frontend.Send(&pgproto3.PasswordMessage{Password: string(plaintext)})
			if err := frontend.Flush(); err != nil {
				conn.Close()
				return nil, nil, fmt.Errorf("flush cleartext password: %w", err)
			}
		case *pgproto3.AuthenticationMD5Password:
			frontend.Send(&pgproto3.PasswordMessage{Password: md5PasswordHash(session.Username, string(plaintext), m.Salt[:])})
			if err := frontend.Flush(); err != nil {
				conn.Close()
				return nil, nil, fmt.Errorf("flush md5 password: %w", err)
			}
		case *pgproto3.AuthenticationSASL, *pgproto3.AuthenticationSASLContinue, *pgproto3.AuthenticationSASLFinal:
			conn.Close()
			return nil, nil, errors.New("upstream requires SASL; not supported by pam-gateway yet")
		case *pgproto3.ParameterStatus, *pgproto3.BackendKeyData, *pgproto3.NoticeResponse:
			// swallow during handshake
		case *pgproto3.ErrorResponse:
			conn.Close()
			return nil, nil, fmt.Errorf("upstream rejected handshake: %s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			return conn, frontend, nil
		default:
			// Other messages during handshake are unexpected but
			// non-fatal — keep reading. The loop bails out either
			// via ReadyForQuery or ErrorResponse above.
		}
	}
}

// proxyQueries is the request/response loop for the established
// session. We run it single-threaded on purpose: PostgreSQL's
// simple-query and extended-query protocols are both strictly
// request-driven (the server doesn't push unsolicited rows), so a
// single goroutine that reads one operator message and pumps the
// matching server messages back is easier to reason about than two
// async pumps with a shared queue. The same goroutine captures the
// per-query audit row when the upstream signals ReadyForQuery.
//
// Returning io.EOF (or net.ErrClosed wrapped in an EOF) is normal
// — it just means the operator hung up.
func (l *PGListener) proxyQueries(ctx context.Context, session *AuthorizedSession, backend *pgproto3.Backend, frontend *pgproto3.Frontend, parser *CommandParser) error {
	for {
		clientMsg, err := backend.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return io.EOF
			}
			return fmt.Errorf("operator receive: %w", err)
		}
		switch m := clientMsg.(type) {
		case *pgproto3.Terminate:
			// best-effort forward + return
			frontend.Send(m)
			_ = frontend.Flush()
			return io.EOF
		case *pgproto3.Query:
			// Evaluate the policy engine before forwarding. On
			// "deny" we short-circuit by synthesising an
			// ErrorResponse + ReadyForQuery so libpq stays in
			// the expected protocol state, and we record the
			// command as denied (with the policy reason as the
			// hashed output payload so audit reviewers see the
			// rule that blocked it). On any policy error we
			// fail-open and forward the query — matching the
			// SSH listener's existing semantics.
			if l.cfg.CommandPolicy != nil {
				action, reason, err := l.cfg.CommandPolicy.EvaluateCommand(ctx, session.WorkspaceID, session.SessionID, m.String)
				if err != nil {
					log.Printf("gateway: pg evaluate policy session=%s err=%v", session.SessionID, err)
				} else {
					switch action {
					case "deny":
						denialMsg := reason
						if denialMsg == "" {
							denialMsg = "command blocked by PAM policy"
						}
						if parser != nil {
							parser.WriteInput(ctx, []byte(m.String+"\n"))
							parser.WriteOutput([]byte(denialMsg))
							parser.SetRiskFlag("pg:policy:deny")
							parser.WriteInput(ctx, []byte("\n"))
						}
						backend.Send(&pgproto3.ErrorResponse{
							Severity: "ERROR",
							Code:     "42501", // insufficient_privilege
							Message:  denialMsg,
						})
						backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
						if err := backend.Flush(); err != nil {
							return fmt.Errorf("flush policy deny: %w", err)
						}
						continue
					case "step_up":
						if parser != nil {
							parser.SetRiskFlag("pg:policy:step_up")
						}
						// step_up rules don't block the query in
						// the Phase 1 wire — mobile MFA prompt is
						// out-of-band. We just flag the row.
					}
				}
			}
			if parser != nil {
				parser.WriteInput(ctx, []byte(m.String+"\n"))
			}
			frontend.Send(m)
			if err := frontend.Flush(); err != nil {
				return fmt.Errorf("flush query upstream: %w", err)
			}
			if err := l.pumpUntilReady(ctx, session, backend, frontend, parser); err != nil {
				return err
			}
		default:
			// Pass other client messages straight through (Parse,
			// Bind, Execute, Sync, CopyData, …). We don't capture
			// these as commands, but they still need to be
			// forwarded for the session to function. Whenever the
			// client sends a Sync, the upstream will respond with
			// ReadyForQuery — pumpUntilReady handles that too.
			frontend.Send(m)
			if err := frontend.Flush(); err != nil {
				return fmt.Errorf("flush passthrough upstream: %w", err)
			}
			if _, isSync := m.(*pgproto3.Sync); isSync {
				if err := l.pumpUntilReady(ctx, session, backend, frontend, parser); err != nil {
					return err
				}
			}
		}
	}
}

// pumpUntilReady drains server messages from the upstream into the
// operator until a ReadyForQuery boundary, hashing row data along
// the way and emitting one audit row per command boundary.
func (l *PGListener) pumpUntilReady(ctx context.Context, session *AuthorizedSession, backend *pgproto3.Backend, frontend *pgproto3.Frontend, parser *CommandParser) error {
	for {
		serverMsg, err := frontend.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return io.EOF
			}
			return fmt.Errorf("upstream receive: %w", err)
		}
		switch sm := serverMsg.(type) {
		case *pgproto3.DataRow:
			if parser != nil {
				for _, col := range sm.Values {
					parser.WriteOutput(col)
				}
			}
		case *pgproto3.CommandComplete:
			if parser != nil {
				parser.WriteOutput([]byte(sm.CommandTag))
			}
		case *pgproto3.ErrorResponse:
			if parser != nil {
				parser.WriteOutput([]byte(sm.Message))
				parser.SetRiskFlag("pg:error:" + sm.Code)
			}
		}
		backend.Send(serverMsg)
		if err := backend.Flush(); err != nil {
			return fmt.Errorf("flush operator: %w", err)
		}
		if _, ok := serverMsg.(*pgproto3.ReadyForQuery); ok {
			// Force the parser to flush the just-completed
			// command by feeding a newline. WriteInput("\n")
			// closes the pending command with its accumulated
			// output hash. session is currently unused inside
			// the pump but is kept on the signature so future
			// per-session log enrichment (asset id, account id,
			// risk score) does not need a wider refactor.
			_ = session
			if parser != nil {
				parser.WriteInput(ctx, []byte("\n"))
			}
			return nil
		}
	}
}

// flushTelemetry drains the command parser and recorder. The flush
// context is intentionally detached from the request ctx — on
// SIGTERM the parent is already cancelled, so a derived context
// would be born cancelled and parser.Close / recorder.Close would
// immediately hit their <-ctx.Done() branches and abandon queued
// audit rows + the replay blob. Detaching from context.Background
// lets the bounded ShutdownTimeout actually elapse even mid-SIGTERM
// (matches the SSH + K8s listener behaviour — see SSHListener.handleChannel
// for the original comment on this invariant).
func (l *PGListener) flushTelemetry(_ context.Context, recorder *IORecorder, parser *CommandParser) {
	flushCtx, cancel := context.WithTimeout(context.Background(), l.cfg.ShutdownTimeout)
	defer cancel()
	if parser != nil {
		parser.Close(flushCtx)
	}
	if recorder != nil {
		if err := recorder.Close(flushCtx); err != nil {
			log.Printf("gateway: pg flush recorder: %v", err)
		}
	}
}

// sendFatalError writes a fatal ErrorResponse + Terminate so the
// operator's client sees a clean error message instead of a torn
// connection. Best-effort: any I/O error here is logged elsewhere.
func sendFatalError(backend *pgproto3.Backend, sqlState, msg string) {
	backend.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     sqlState,
		Message:  msg,
	})
	_ = backend.Flush()
}

// bytesSink is an io.Writer that records every byte written to it.
// We use it to buffer the operator-side handshake bytes before we
// know the session id (and therefore before we can open the real
// recorder).
type bytesSink struct {
	buf []byte
}

func (b *bytesSink) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// Bytes returns a defensive copy.
func (b *bytesSink) Bytes() []byte {
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

// Len returns the number of buffered bytes.
func (b *bytesSink) Len() int { return len(b.buf) }

// recorderTeeSink adapts an IORecorder into an io.Writer so it can
// be used with io.TeeReader / io.MultiWriter at the conn level.
type recorderTeeSink struct {
	rec *IORecorder
	dir RecordDirection
}

func newRecorderTeeSink(rec *IORecorder, dir RecordDirection) *recorderTeeSink {
	return &recorderTeeSink{rec: rec, dir: dir}
}

func (s *recorderTeeSink) Write(p []byte) (int, error) {
	if s.rec != nil && len(p) > 0 {
		s.rec.Record(s.dir, append([]byte(nil), p...))
	}
	return len(p), nil
}

// md5PasswordHash returns the libpq-compatible md5 wire encoding:
//
//	"md5" + md5( md5(password + username) + salt )
//
// The result is the cleartext payload of the PasswordMessage when
// the upstream responds with AuthenticationMD5Password.
func md5PasswordHash(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user)) //nolint:gosec
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...)) //nolint:gosec
	return "md5" + hex.EncodeToString(outer[:])
}
