// Package gateway: MySQL wire-protocol proxy (Milestone 6 Task 11).
//
// The listener mirrors the SSH / PG listener contract — accept on
// :3306, validate the operator's one-shot connect token, dial the
// upstream MySQL with the injected credential, then frame-proxy
// COM_QUERY traffic while capturing each statement as a per-command
// audit row.
//
// Wire protocol choices
//
//   - We hand-roll the minimum subset of the MySQL Client/Server
//     protocol because there is no jackc/pgproto3-equivalent for
//     MySQL in the Go ecosystem. Cap at:
//   - Protocol 10 initial handshake
//   - mysql_native_password (advertised in the greeting,
//     universally supported)
//   - AuthSwitchRequest to mysql_clear_password so the
//     operator-supplied token reaches us in clear text and we
//     can validate it against the control plane. Modern MySQL
//     clients accept this with --enable-cleartext-plugin (or
//     the equivalent driver flag).
//   - HandshakeResponse41
//   - COM_QUERY / COM_QUIT / COM_PING for the steady-state proxy
//   - No COMPRESS, no SSL, no caching_sha2_password (operator side).
//     Upstream connection negotiates whatever the upstream server
//     advertises so long as it supports mysql_native_password.
//
//   - Compression and TLS are deferred to a follow-up milestone —
//     this listener focuses on getting the audit + injection
//     pipeline wired through MySQL traffic. The PROGRESS.md note
//     calls out the constraint so operators know to use cleartext
//     plugins on the client side.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by the mysql_native_password handshake
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// MySQLListenerConfig wires the MySQL gateway into the same
// authorize → inject → record → audit pipeline the SSH / PG
// listeners use.
type MySQLListenerConfig struct {
	Port            int
	Authorizer      SessionAuthorizer
	Injector        SecretInjector
	ReplayStore     ReplayStore
	CommandSink     CommandSink
	ShutdownTimeout time.Duration

	// CommandPolicy evaluates each COM_QUERY against the
	// pam_command_policies rule set. Optional — when nil the
	// listener forwards every query unchanged. When set, "deny"
	// rules short-circuit the query before it reaches the
	// upstream MySQL server (the operator sees a synthesised ERR
	// packet so the client driver returns a normal SQL error)
	// and "step_up" rules raise a risk flag on the audit row.
	CommandPolicy CommandPolicyEvaluator
}

// MySQLListener is the production MySQL gateway.
type MySQLListener struct {
	cfg MySQLListenerConfig
}

// NewMySQLListener validates the supplied configuration and returns
// a listener that is ready to Serve.
func NewMySQLListener(cfg MySQLListenerConfig) (*MySQLListener, error) {
	if cfg.Authorizer == nil {
		return nil, errors.New("gateway: MySQLListenerConfig.Authorizer is required")
	}
	if cfg.Injector == nil {
		return nil, errors.New("gateway: MySQLListenerConfig.Injector is required")
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	return &MySQLListener{cfg: cfg}, nil
}

// Serve binds a TCP listener on cfg.Port and accepts connections
// until ctx is cancelled.
func (l *MySQLListener) Serve(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", l.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("gateway: mysql listen %s: %w", addr, err)
	}
	log.Printf("gateway: mysql listener bound on %s", ln.Addr().String())
	return l.serveListener(ctx, ln)
}

func (l *MySQLListener) serveListener(ctx context.Context, ln net.Listener) error {
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
			return fmt.Errorf("gateway: mysql accept: %w", err)
		}
		go l.handleConn(ctx, conn)
	}
}

// MySQL client capability flags we care about. The protocol defines
// many more — these are the ones we either set in our greeting or
// inspect in the handshake response.
const (
	clientLongPassword               uint32 = 0x00000001
	clientFoundRows                  uint32 = 0x00000002
	clientLongFlag                   uint32 = 0x00000004
	clientConnectWithDB              uint32 = 0x00000008
	clientNoSchema                   uint32 = 0x00000010
	clientCompress                   uint32 = 0x00000020
	clientODBC                       uint32 = 0x00000040
	clientLocalFiles                 uint32 = 0x00000080
	clientIgnoreSpace                uint32 = 0x00000100
	clientProtocol41                 uint32 = 0x00000200
	clientInteractive                uint32 = 0x00000400
	clientSSL                        uint32 = 0x00000800
	clientIgnoreSIGPIPE              uint32 = 0x00001000
	clientTransactions               uint32 = 0x00002000
	clientReserved                   uint32 = 0x00004000
	clientSecureConnection           uint32 = 0x00008000
	clientMultiStatements            uint32 = 0x00010000
	clientMultiResults               uint32 = 0x00020000
	clientPSMultiResults             uint32 = 0x00040000
	clientPluginAuth                 uint32 = 0x00080000
	clientConnectAttrs               uint32 = 0x00100000
	clientPluginAuthLenEncClientData uint32 = 0x00200000
	clientDeprecateEOF               uint32 = 0x01000000
)

// MySQL command bytes. Only COM_QUERY and COM_QUIT are special-cased
// in the proxy loop; the rest are forwarded transparently and the
// upstream's reply is pumped back until we see EOF / OK / ERR.
const (
	comQuit       byte = 0x01
	comInitDB     byte = 0x02
	comQuery      byte = 0x03
	comFieldList  byte = 0x04
	comPing       byte = 0x0e
	comStmtPrep   byte = 0x16
	comStmtExec   byte = 0x17
	comStmtClose  byte = 0x19
	comStmtReset  byte = 0x1a
	comSetOption  byte = 0x1b
	comStmtFetch  byte = 0x1c
)

// MySQL response packet headers used in proxyQueries to know when
// a multi-frame response has finished.
const (
	okHeader  byte = 0x00
	errHeader byte = 0xff
	eofHeader byte = 0xfe
)

// handleConn owns the lifetime of a single operator connection. It
// runs the operator handshake, dials the upstream + handshake there,
// then frame-proxies COM_QUERY traffic with audit + recording taps.
func (l *MySQLListener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// The recorder taps raw operator-side bytes in both directions
	// so the replay blob captures the full wire transcript. The
	// recorder is bound to session.SessionID, so we have to defer
	// creating it until after the handshake validates the token.
	earlyIn := &bytesSink{}
	earlyOut := &bytesSink{}
	opReader := io.TeeReader(conn, earlyIn)
	opWriter := io.MultiWriter(conn, earlyOut)

	authCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	session, database, err := l.authenticateOperator(authCtx, opReader, opWriter)
	if err != nil {
		log.Printf("gateway: mysql authenticate operator: %v", err)
		// Best effort — write an ERR packet so the client sees a
		// clean rejection rather than a half-closed socket.
		_ = writeMySQLErr(opWriter, 0, 1045, "28000", "authentication rejected")
		return
	}

	// Stand up the recorder + parser bound to the validated session
	// id and seed them with the bytes captured during handshake.
	var recorder *IORecorder
	if l.cfg.ReplayStore != nil {
		r, rerr := NewIORecorder(session.SessionID, l.cfg.ReplayStore, IORecorderConfig{})
		if rerr != nil {
			log.Printf("gateway: mysql new recorder session=%s: %v", session.SessionID, rerr)
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
			log.Printf("gateway: mysql new parser session=%s: %v", session.SessionID, perr)
		} else {
			parser = p
		}
	}

	// Rebind the operator-side reader/writer to taps that route into
	// the recorder for the post-handshake phase. Any bytes that may
	// have arrived between the handshake reads and this point are
	// already in earlyIn (replayed into the recorder above).
	if recorder != nil {
		opReader = io.TeeReader(conn, newRecorderTeeSink(recorder, DirectionInput))
		opWriter = io.MultiWriter(conn, newRecorderTeeSink(recorder, DirectionOutput))
	}

	// Dial the upstream and complete its handshake with the injected
	// credential.
	upstreamConn, err := l.connectUpstream(authCtx, session, database)
	if err != nil {
		log.Printf("gateway: mysql connect upstream session=%s: %v", session.SessionID, err)
		_ = writeMySQLErr(opWriter, 0, 1045, "08001", fmt.Sprintf("upstream unavailable: %v", err))
		l.flushTelemetry(ctx, recorder, parser)
		return
	}
	defer upstreamConn.Close()

	// Announce the session is live to the operator with an OK
	// packet. Sequence id starts at 2 because we sent the
	// AuthSwitchRequest (seq 1) and read its response in the
	// handshake.
	if err := writeMySQLOK(opWriter, 2); err != nil {
		log.Printf("gateway: mysql write final ok session=%s: %v", session.SessionID, err)
		l.flushTelemetry(ctx, recorder, parser)
		return
	}

	if err := l.proxyQueries(ctx, session, opReader, opWriter, upstreamConn, parser); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("gateway: mysql proxy loop session=%s: %v", session.SessionID, err)
	}

	l.flushTelemetry(ctx, recorder, parser)
}

// authenticateOperator runs the MySQL handshake on the operator side
// and validates the supplied cleartext token against the authorizer.
//
// Sequence:
//  1. Server greeting (protocol 10, mysql_native_password, salt)
//  2. Read HandshakeResponse41 from the client
//  3. Send AuthSwitchRequest to mysql_clear_password (so the next
//     payload from the client is the raw token, no hashing)
//  4. Read the AuthSwitchResponse payload — that is the token
//  5. Validate the token; return the AuthorizedSession on success.
func (l *MySQLListener) authenticateOperator(ctx context.Context, r io.Reader, w io.Writer) (*AuthorizedSession, string, error) {
	salt := make([]byte, 20)
	if _, err := rand.Read(salt); err != nil {
		return nil, "", fmt.Errorf("gen salt: %w", err)
	}
	if err := writeMySQLGreeting(w, 0, salt); err != nil {
		return nil, "", fmt.Errorf("write greeting: %w", err)
	}

	pkt, _, err := readMySQLPacket(r)
	if err != nil {
		return nil, "", fmt.Errorf("read handshake response: %w", err)
	}
	hsResp, err := parseHandshakeResponse(pkt)
	if err != nil {
		return nil, "", fmt.Errorf("parse handshake response: %w", err)
	}

	// AuthSwitchRequest — sequence id of the next server packet is
	// always client-seq + 1. The client's HandshakeResponse41 was
	// seq 1, so our AuthSwitchRequest is seq 2.
	if err := writeAuthSwitchRequest(w, 2, "mysql_clear_password", []byte{0}); err != nil {
		return nil, "", fmt.Errorf("write auth-switch: %w", err)
	}

	// Client's AuthSwitchResponse comes back at seq 3; the payload
	// is the cleartext password followed by a 0x00 terminator.
	switchPkt, _, err := readMySQLPacket(r)
	if err != nil {
		return nil, "", fmt.Errorf("read auth-switch response: %w", err)
	}
	token := string(bytes.TrimRight(switchPkt, "\x00"))
	if token == "" {
		return nil, "", errors.New("empty connect token")
	}
	if l.cfg.Authorizer == nil {
		return nil, "", errors.New("authorizer not configured")
	}
	session, err := l.cfg.Authorizer.AuthorizeConnectToken(ctx, token)
	if err != nil {
		return nil, "", fmt.Errorf("authorize connect token: %w", err)
	}
	return session, hsResp.Database, nil
}

// connectUpstream dials the upstream MySQL, runs the
// mysql_native_password handshake using the injected credential, and
// returns the connection in a ready-for-query state.
func (l *MySQLListener) connectUpstream(ctx context.Context, session *AuthorizedSession, database string) (net.Conn, error) {
	secretType, plaintext, err := l.cfg.Injector.InjectSecret(ctx, session.SessionID, session.AccountID)
	if err != nil {
		return nil, fmt.Errorf("inject secret: %w", err)
	}
	switch secretType {
	case "mysql_password", "password", "":
		// ok — plaintext is the upstream password
	default:
		return nil, fmt.Errorf("unsupported secret_type %q for mysql listener", secretType)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addr := fmt.Sprintf("%s:%d", session.TargetHost, session.TargetPort)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", addr, err)
	}

	// Read upstream greeting; extract salt + auth plugin.
	greetPkt, _, err := readMySQLPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upstream greeting: %w", err)
	}
	greet, err := parseGreeting(greetPkt)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse upstream greeting: %w", err)
	}
	if greet.AuthPlugin != "" && greet.AuthPlugin != "mysql_native_password" {
		conn.Close()
		return nil, fmt.Errorf("upstream advertises auth plugin %q; only mysql_native_password is supported", greet.AuthPlugin)
	}

	// Build HandshakeResponse41 with native_password hash of the
	// injected secret.
	authResponse := scrambleNativePassword(plaintext, greet.Salt)
	resp := buildHandshakeResponse(session.Username, database, authResponse, "mysql_native_password")
	if err := writeMySQLPacket(conn, 1, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upstream handshake response: %w", err)
	}

	// The upstream may reply with OK, AuthSwitchRequest (to switch
	// to native_password again with a new salt), or ERR.
	for {
		respPkt, _, err := readMySQLPacket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read upstream auth reply: %w", err)
		}
		if len(respPkt) == 0 {
			continue
		}
		switch respPkt[0] {
		case okHeader:
			return conn, nil
		case errHeader:
			conn.Close()
			return nil, fmt.Errorf("upstream rejected handshake: %s", parseErrPacket(respPkt))
		case eofHeader:
			// AuthSwitchRequest — body is plugin name (null-term)
			// + new salt (null-term).
			parts := bytes.SplitN(respPkt[1:], []byte{0}, 3)
			if len(parts) < 2 {
				conn.Close()
				return nil, errors.New("malformed auth-switch from upstream")
			}
			plugin := string(parts[0])
			newSalt := parts[1]
			// strip trailing 0x00 if present
			newSalt = bytes.TrimRight(newSalt, "\x00")
			if plugin != "mysql_native_password" {
				conn.Close()
				return nil, fmt.Errorf("upstream demands auth plugin %q; only mysql_native_password is supported", plugin)
			}
			rehash := scrambleNativePassword(plaintext, newSalt)
			if err := writeMySQLPacket(conn, 3, rehash); err != nil {
				conn.Close()
				return nil, fmt.Errorf("write auth-switch response: %w", err)
			}
		default:
			conn.Close()
			return nil, fmt.Errorf("unexpected upstream packet header 0x%02x", respPkt[0])
		}
	}
}

// proxyQueries is the steady-state pump. It reads packets from the
// operator, special-cases COM_QUERY for audit capture, forwards
// everything to the upstream, and pumps the matching response
// frames back.
func (l *MySQLListener) proxyQueries(ctx context.Context, session *AuthorizedSession, opR io.Reader, opW io.Writer, upstream net.Conn, parser *CommandParser) error {
	for {
		pkt, seq, err := readMySQLPacket(opR)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return io.EOF
			}
			return fmt.Errorf("operator receive: %w", err)
		}
		if len(pkt) == 0 {
			continue
		}
		cmd := pkt[0]
		switch cmd {
		case comQuit:
			_ = writeMySQLPacket(upstream, seq, pkt)
			return io.EOF
		case comQuery:
			sqlText := string(pkt[1:])
			// Evaluate the policy engine before forwarding. On
			// "deny" we short-circuit by synthesising an ERR
			// packet so the MySQL client driver surfaces a normal
			// SQL error to the operator. On any policy error we
			// fail-open and forward the query — matching the SSH
			// listener's existing semantics.
			if l.cfg.CommandPolicy != nil {
				action, reason, err := l.cfg.CommandPolicy.EvaluateCommand(ctx, session.WorkspaceID, session.SessionID, sqlText)
				if err != nil {
					log.Printf("gateway: mysql evaluate policy session=%s err=%v", session.SessionID, err)
				} else {
					switch action {
					case "deny":
						denialMsg := reason
						if denialMsg == "" {
							denialMsg = "command blocked by PAM policy"
						}
						if parser != nil {
							parser.WriteInput(ctx, append(append([]byte{}, pkt[1:]...), '\n'))
							parser.WriteOutput([]byte(denialMsg))
							parser.SetRiskFlag("mysql:policy:deny")
							parser.WriteInput(ctx, []byte("\n"))
						}
						// 1227 = ER_SPECIFIC_ACCESS_DENIED_ERROR — a
						// privilege-related error that MySQL clients
						// already render in plain English. Sequence id
						// of an ERR packet is the next id after the
						// COM_QUERY — i.e. seq+1.
						if err := writeMySQLErr(opW, seq+1, 1227, "42000", denialMsg); err != nil {
							return fmt.Errorf("write policy deny err: %w", err)
						}
						continue
					case "step_up":
						if parser != nil {
							parser.SetRiskFlag("mysql:policy:step_up")
						}
						// step_up rules don't block the query in
						// the Phase 1 wire — mobile MFA prompt is
						// out-of-band. We just flag the row.
					}
				}
			}
			if parser != nil {
				// CommandParser keys command boundaries off newlines
				// in its input stream. Wrap the SQL text in a trailing
				// "\n" so each COM_QUERY produces exactly one audit row.
				parser.WriteInput(ctx, append(append([]byte{}, pkt[1:]...), '\n'))
			}
			if err := writeMySQLPacket(upstream, seq, pkt); err != nil {
				return fmt.Errorf("forward com_query: %w", err)
			}
			if err := pumpResponse(opW, upstream, parser); err != nil {
				return err
			}
		default:
			if err := writeMySQLPacket(upstream, seq, pkt); err != nil {
				return fmt.Errorf("forward upstream: %w", err)
			}
			if err := pumpResponse(opW, upstream, parser); err != nil {
				return err
			}
		}
	}
}

// pumpResponse forwards upstream packets to the operator until the
// upstream signals end-of-response (OK / ERR / final EOF). The MySQL
// protocol does not put a single sentinel at the end of a result set
// — instead the server sends: column-count packet, N column-def
// packets, intermediate EOF, M row packets, final EOF (or OK with
// CLIENT_DEPRECATE_EOF). To stay lightweight we just count: OK/ERR
// = done after one packet; otherwise wait for the second EOF/OK.
//
// parser.WriteOutput is fed every byte we forward so the per-command
// SHA-256 hash captures the full server response.
func pumpResponse(opW io.Writer, upstream net.Conn, parser *CommandParser) error {
	eofSeen := 0
	for {
		pkt, seq, err := readMySQLPacket(upstream)
		if err != nil {
			return fmt.Errorf("upstream receive: %w", err)
		}
		// Write to operator first; if that fails we still want to
		// surface the error and bail.
		if err := writeMySQLPacket(opW, seq, pkt); err != nil {
			return fmt.Errorf("forward to operator: %w", err)
		}
		if parser != nil {
			parser.WriteOutput(pkt)
		}
		if len(pkt) == 0 {
			continue
		}
		switch pkt[0] {
		case okHeader:
			// Plain OK packet — only valid as end-of-response on the
			// first packet OR after a result set when
			// CLIENT_DEPRECATE_EOF is set. Either way we are done.
			if parser != nil {
				// Flush the pending COM_QUERY into the sink. WriteInput
				// previously appended "\n" so the parser's pending
				// command exists; emit one more "\n" here so it gets
				// flushed even on follow-on queries.
				parser.WriteInput(context.Background(), []byte("\n"))
			}
			return nil
		case errHeader:
			if parser != nil {
				parser.WriteInput(context.Background(), []byte("\n"))
			}
			return nil
		case eofHeader:
			if len(pkt) < 9 {
				eofSeen++
				if eofSeen >= 2 {
					if parser != nil {
						parser.WriteInput(context.Background(), []byte("\n"))
					}
					return nil
				}
			}
		}
	}
}

// flushTelemetry closes the parser + recorder so the audit row and
// replay blob land in their stores before handleConn returns. The
// flush context is intentionally detached from the request ctx —
// on SIGTERM the parent is already cancelled, so a derived context
// would be born cancelled and parser.Close / recorder.Close would
// immediately hit their <-ctx.Done() branches and abandon queued
// audit rows + the replay blob. Detaching from context.Background
// lets the bounded ShutdownTimeout actually elapse even mid-SIGTERM
// (matches the SSH + K8s + PG listener behaviour).
func (l *MySQLListener) flushTelemetry(_ context.Context, recorder *IORecorder, parser *CommandParser) {
	flushCtx, cancel := context.WithTimeout(context.Background(), l.cfg.ShutdownTimeout)
	defer cancel()
	if parser != nil {
		parser.Close(flushCtx)
	}
	if recorder != nil {
		if err := recorder.Close(flushCtx); err != nil {
			log.Printf("gateway: mysql flush recording: %v", err)
		}
	}
}

// readMySQLPacket reads one MySQL packet — 3-byte length LE, 1-byte
// sequence, payload — from r.
func readMySQLPacket(r io.Reader) ([]byte, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, err
	}
	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
	seq := header[3]
	if length == 0 {
		return nil, seq, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, seq, err
	}
	return body, seq, nil
}

// writeMySQLPacket writes one MySQL packet with the given sequence
// id. For payloads >= 16 MiB the MySQL protocol requires splitting
// across multiple chunks; this implementation does not — single
// queries up to 16 MiB are supported, larger queries will be
// rejected by the upstream with a packet-too-large error.
func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	if len(payload) >= 1<<24 {
		return fmt.Errorf("gateway: mysql payload too large (%d bytes)", len(payload))
	}
	var header [4]byte
	header[0] = byte(len(payload))
	header[1] = byte(len(payload) >> 8)
	header[2] = byte(len(payload) >> 16)
	header[3] = seq
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// writeMySQLGreeting emits a Protocol::Handshake v10 packet
// advertising mysql_native_password as the default auth plugin. The
// salt must be 20 bytes — 8 bytes go before the filler, the remaining
// 12+1 (including null terminator) go in the optional-auth-data slot.
func writeMySQLGreeting(w io.Writer, seq byte, salt []byte) error {
	if len(salt) != 20 {
		return fmt.Errorf("gateway: mysql greeting salt must be 20 bytes, got %d", len(salt))
	}
	caps := clientLongPassword | clientLongFlag | clientProtocol41 | clientTransactions |
		clientSecureConnection | clientPluginAuth | clientConnectWithDB
	statusFlags := uint16(0x0002) // SERVER_STATUS_AUTOCOMMIT

	var buf bytes.Buffer
	buf.WriteByte(10)                            // protocol version
	buf.WriteString("8.0.0-pam-gateway")         // server version
	buf.WriteByte(0)                             // null terminator
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1)) // connection id
	buf.Write(salt[:8])                          // salt part 1
	buf.WriteByte(0)                             // filler
	_ = binary.Write(&buf, binary.LittleEndian, uint16(caps&0xffff))
	buf.WriteByte(0x21) // utf8mb3_general_ci character set
	_ = binary.Write(&buf, binary.LittleEndian, statusFlags)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(caps>>16))
	buf.WriteByte(byte(len(salt) + 1)) // auth-data length (salt + null)
	buf.Write(make([]byte, 10))        // reserved
	buf.Write(salt[8:])                // salt part 2 (12 bytes)
	buf.WriteByte(0)                   // salt part 2 null terminator
	buf.WriteString("mysql_native_password")
	buf.WriteByte(0)
	return writeMySQLPacket(w, seq, buf.Bytes())
}

// writeMySQLOK emits an OK packet (header 0x00 + affected_rows=0 +
// insert_id=0 + status_flags=AUTOCOMMIT + warnings=0).
func writeMySQLOK(w io.Writer, seq byte) error {
	var buf bytes.Buffer
	buf.WriteByte(okHeader)
	buf.WriteByte(0) // affected_rows length-encoded int 0
	buf.WriteByte(0) // insert_id length-encoded int 0
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0002))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	return writeMySQLPacket(w, seq, buf.Bytes())
}

// writeMySQLErr emits an ERR packet with a SQLSTATE marker.
func writeMySQLErr(w io.Writer, seq byte, code uint16, sqlState, msg string) error {
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	var buf bytes.Buffer
	buf.WriteByte(errHeader)
	_ = binary.Write(&buf, binary.LittleEndian, code)
	buf.WriteByte('#')
	buf.WriteString(sqlState)
	buf.WriteString(msg)
	return writeMySQLPacket(w, seq, buf.Bytes())
}

// writeAuthSwitchRequest emits a 0xfe-prefixed AuthSwitchRequest
// with the named plugin and the given (possibly empty) plugin data.
func writeAuthSwitchRequest(w io.Writer, seq byte, plugin string, data []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(eofHeader) // 0xfe
	buf.WriteString(plugin)
	buf.WriteByte(0)
	buf.Write(data)
	return writeMySQLPacket(w, seq, buf.Bytes())
}

// handshakeResponse41 is the parsed view of the client's
// HandshakeResponse41 packet (subset used by the gateway).
type handshakeResponse41 struct {
	Capabilities uint32
	Username     string
	Database     string
	AuthPlugin   string
	AuthResponse []byte
}

// parseHandshakeResponse decodes the minimum fields the gateway
// needs from a HandshakeResponse41 packet. Tolerant of optional
// fields — missing CLIENT_CONNECT_WITH_DB / CLIENT_PLUGIN_AUTH just
// leave the relevant fields empty.
func parseHandshakeResponse(pkt []byte) (*handshakeResponse41, error) {
	if len(pkt) < 32 {
		return nil, fmt.Errorf("handshake response too short (%d bytes)", len(pkt))
	}
	caps := binary.LittleEndian.Uint32(pkt[0:4])
	// skip max_packet_size (4), charset (1), reserved (23) -> 28 bytes total before username
	pos := 32
	usernameEnd := bytes.IndexByte(pkt[pos:], 0)
	if usernameEnd < 0 {
		return nil, errors.New("malformed username in handshake response")
	}
	username := string(pkt[pos : pos+usernameEnd])
	pos += usernameEnd + 1

	var authResponse []byte
	if caps&clientPluginAuthLenEncClientData != 0 {
		length, n := readLenEncInt(pkt[pos:])
		pos += n
		if pos+int(length) > len(pkt) {
			return nil, errors.New("auth response overflows packet")
		}
		authResponse = pkt[pos : pos+int(length)]
		pos += int(length)
	} else if caps&clientSecureConnection != 0 {
		if pos >= len(pkt) {
			return nil, errors.New("missing auth-response length byte")
		}
		length := int(pkt[pos])
		pos++
		if pos+length > len(pkt) {
			return nil, errors.New("auth response overflows packet")
		}
		authResponse = pkt[pos : pos+length]
		pos += length
	} else {
		end := bytes.IndexByte(pkt[pos:], 0)
		if end < 0 {
			return nil, errors.New("malformed auth response (no null term)")
		}
		authResponse = pkt[pos : pos+end]
		pos += end + 1
	}

	var database string
	if caps&clientConnectWithDB != 0 && pos < len(pkt) {
		end := bytes.IndexByte(pkt[pos:], 0)
		if end >= 0 {
			database = string(pkt[pos : pos+end])
			pos += end + 1
		}
	}

	var plugin string
	if caps&clientPluginAuth != 0 && pos < len(pkt) {
		end := bytes.IndexByte(pkt[pos:], 0)
		if end >= 0 {
			plugin = string(pkt[pos : pos+end])
		}
	}
	return &handshakeResponse41{
		Capabilities: caps,
		Username:     username,
		Database:     database,
		AuthPlugin:   plugin,
		AuthResponse: authResponse,
	}, nil
}

// mysqlGreeting is the parsed view of the upstream's initial
// handshake packet.
type mysqlGreeting struct {
	Capabilities uint32
	Salt         []byte
	AuthPlugin   string
}

// parseGreeting decodes the fields we need from the upstream's
// initial Protocol::Handshake v10 packet.
func parseGreeting(pkt []byte) (*mysqlGreeting, error) {
	if len(pkt) < 1 || pkt[0] != 10 {
		return nil, errors.New("not a protocol 10 greeting")
	}
	pos := 1
	verEnd := bytes.IndexByte(pkt[pos:], 0)
	if verEnd < 0 {
		return nil, errors.New("malformed server version")
	}
	pos += verEnd + 1
	// connection id (4)
	if pos+4 > len(pkt) {
		return nil, errors.New("greeting truncated at connection id")
	}
	pos += 4
	// auth-plugin-data part 1 (8 bytes)
	if pos+8 > len(pkt) {
		return nil, errors.New("greeting truncated at salt part 1")
	}
	salt1 := pkt[pos : pos+8]
	pos += 8
	// filler (1)
	pos++
	if pos+2 > len(pkt) {
		return nil, errors.New("greeting truncated at caps low")
	}
	capsLow := binary.LittleEndian.Uint16(pkt[pos : pos+2])
	pos += 2
	if pos >= len(pkt) {
		// Pre-4.1 protocol — we don't support it.
		return nil, errors.New("upstream announces pre-4.1 protocol")
	}
	// charset (1)
	pos++
	// status flags (2)
	pos += 2
	if pos+2 > len(pkt) {
		return nil, errors.New("greeting truncated at caps high")
	}
	capsHigh := binary.LittleEndian.Uint16(pkt[pos : pos+2])
	pos += 2
	caps := uint32(capsLow) | uint32(capsHigh)<<16
	authDataLen := 0
	if pos < len(pkt) {
		authDataLen = int(pkt[pos])
	}
	pos++
	// reserved (10)
	pos += 10
	salt2Len := authDataLen - 8 - 1 // strip null terminator from accounting
	if salt2Len < 0 {
		salt2Len = 12
	}
	if pos+salt2Len > len(pkt) {
		return nil, errors.New("greeting truncated at salt part 2")
	}
	salt2 := pkt[pos : pos+salt2Len]
	pos += salt2Len
	if pos < len(pkt) && pkt[pos] == 0 {
		pos++
	}
	var plugin string
	if caps&clientPluginAuth != 0 && pos < len(pkt) {
		end := bytes.IndexByte(pkt[pos:], 0)
		if end < 0 {
			plugin = string(pkt[pos:])
		} else {
			plugin = string(pkt[pos : pos+end])
		}
	}
	salt := append(append([]byte{}, salt1...), salt2...)
	return &mysqlGreeting{Capabilities: caps, Salt: salt, AuthPlugin: plugin}, nil
}

// buildHandshakeResponse constructs a HandshakeResponse41 payload.
func buildHandshakeResponse(username, database string, authResponse []byte, plugin string) []byte {
	caps := clientLongPassword | clientLongFlag | clientProtocol41 | clientTransactions |
		clientSecureConnection | clientPluginAuth
	if database != "" {
		caps |= clientConnectWithDB
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, caps)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1<<24)) // max packet size 16 MiB
	buf.WriteByte(0x21)                                        // charset utf8mb3_general_ci
	buf.Write(make([]byte, 23))                                // reserved
	buf.WriteString(username)
	buf.WriteByte(0)
	buf.WriteByte(byte(len(authResponse)))
	buf.Write(authResponse)
	if database != "" {
		buf.WriteString(database)
		buf.WriteByte(0)
	}
	buf.WriteString(plugin)
	buf.WriteByte(0)
	return buf.Bytes()
}

// scrambleNativePassword computes the mysql_native_password
// authentication response:
//
//	SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
//
// The result is 20 bytes. Empty password short-circuits to an empty
// response (the protocol treats len=0 as "no password").
func scrambleNativePassword(password, salt []byte) []byte {
	if len(password) == 0 {
		return nil
	}
	h1 := sha1.Sum(password) //nolint:gosec // required by mysql_native_password
	h2 := sha1.Sum(h1[:])    //nolint:gosec
	h3 := sha1.New()         //nolint:gosec
	h3.Write(salt)
	h3.Write(h2[:])
	h3sum := h3.Sum(nil)
	out := make([]byte, 20)
	for i := 0; i < 20; i++ {
		out[i] = h1[i] ^ h3sum[i]
	}
	return out
}

// readLenEncInt decodes a MySQL length-encoded integer and returns
// the value plus how many bytes it consumed.
func readLenEncInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch {
	case b[0] < 0xfb:
		return uint64(b[0]), 1
	case b[0] == 0xfc:
		if len(b) < 3 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3
	case b[0] == 0xfd:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case b[0] == 0xfe:
		if len(b) < 9 {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9
	}
	return 0, 0
}

// parseErrPacket extracts the human-readable portion of an ERR
// packet so handshake failures bubble up with a sensible message.
func parseErrPacket(pkt []byte) string {
	if len(pkt) < 3 {
		return "unknown error"
	}
	pos := 3
	if len(pkt) > pos && pkt[pos] == '#' {
		pos += 6 // skip '#' + 5-byte SQLSTATE
	}
	if pos > len(pkt) {
		return "unknown error"
	}
	return string(pkt[pos:])
}
