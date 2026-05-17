package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHListenerConfig captures the wiring an SSHListener needs.
// HostKey must be set; Authorizer must be set; CA and Injector are
// optional but at least one must be provided so the gateway can
// authenticate to the upstream target.
type SSHListenerConfig struct {
	Port       int
	HostKey    ssh.Signer
	Authorizer SessionAuthorizer
	Injector   SecretInjector
	CA         *SSHCertificateAuthority

	// ReplayStore receives the bidirectional session blob via
	// IORecorder. Optional — when nil, sessions still proxy but
	// no recording is flushed (dev binaries without S3
	// credentials stay healthy). The canonical key shape is
	// sessions/{session_id}/replay.bin (see ReplayKey).
	ReplayStore ReplayStore

	// CommandSink receives one row per newline-delimited command
	// the operator types. Optional — when nil, no per-command
	// audit rows are emitted. In production both ReplayStore and
	// CommandSink are wired so the audit trail matches the
	// docs/pam/architecture.md acceptance criteria.
	CommandSink CommandSink

	// CommandPolicy evaluates each typed command against the
	// pam_command_policies rule set. Optional — when nil the
	// listener forwards every command unchanged. When set, "deny"
	// rules abort the line before it reaches the upstream shell
	// and "step_up" rules are flagged on the audit row.
	CommandPolicy CommandPolicyEvaluator

	// AcceptTimeout caps how long an inbound TCP socket can sit
	// before the SSH handshake completes. Defaults to 10s when
	// zero.
	AcceptTimeout time.Duration

	// ShutdownTimeout caps how long Serve will wait for in-flight
	// SSH sessions to drain after ctx is cancelled before returning.
	// Defaults to 30s when zero. Active sessions are first asked to
	// drain by closing their SSH server-side connection (which
	// unblocks the chans loop in handleConn and the io.Copy goroutines
	// in handleChannel); if some refuse to terminate within the
	// timeout, Serve returns anyway so the process can exit.
	ShutdownTimeout time.Duration
}

// CommandPolicyEvaluator is the narrow contract the listener uses
// to query the command-policy engine. Production wiring binds this
// to pam.PAMCommandPolicyService; tests substitute a stub.
type CommandPolicyEvaluator interface {
	// EvaluateCommand returns the action ("allow" / "deny" /
	// "step_up") and a human-readable reason for the supplied
	// command. The reason is surfaced to the operator on deny.
	EvaluateCommand(ctx context.Context, workspaceID, sessionID, input string) (action string, reason string, err error)
}

// SSHListener is the gateway's SSH server. It accepts inbound SSH
// connections from operator clients, validates the supplied connect
// token against the control plane, and proxies the channel to the
// resolved target host.
//
// The listener is intentionally narrow: it owns no long-lived
// secrets (the SSH host key is the only private material it keeps)
// and never touches the recording store directly — the recorder
// hooks land in a follow-up milestone.
type SSHListener struct {
	cfg       SSHListenerConfig
	srvConfig *ssh.ServerConfig
}

// NewSSHListener builds an SSHListener bound to the supplied
// configuration. Returns an error when required fields are missing.
func NewSSHListener(cfg SSHListenerConfig) (*SSHListener, error) {
	if cfg.HostKey == nil {
		return nil, errors.New("gateway: SSHListenerConfig.HostKey is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("gateway: SSHListenerConfig.Authorizer is required")
	}
	if cfg.CA == nil && cfg.Injector == nil {
		return nil, errors.New("gateway: SSHListenerConfig requires either CA or Injector")
	}
	if cfg.AcceptTimeout <= 0 {
		cfg.AcceptTimeout = 10 * time.Second
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	l := &SSHListener{cfg: cfg}
	l.srvConfig = &ssh.ServerConfig{
		// Operators authenticate to the gateway with a one-shot
		// connect token issued by ztna-api. The token is supplied
		// as the SSH password — using publickey auth here would
		// force every operator to register a key, which violates
		// the "identity is the perimeter" design (their identity
		// is already proven by the upstream session-request
		// approval).
		PasswordCallback: l.passwordCallback,
	}
	l.srvConfig.AddHostKey(cfg.HostKey)
	return l, nil
}

// passwordCallback validates the password (which the operator
// supplies as their one-shot connect token) against the control
// plane. The resolved AuthorizedSession is stashed in
// conn.Permissions.Extensions so the channel handler can look it
// up without a second round trip.
func (l *SSHListener) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	token := string(password)
	if token == "" {
		return nil, fmt.Errorf("gateway: empty connect token from %s", conn.RemoteAddr())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := l.cfg.Authorizer.AuthorizeConnectToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("gateway: authorize token: %w", err)
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"pam-session-id":   sess.SessionID,
			"pam-lease-id":     sess.LeaseID,
			"pam-asset-id":     sess.AssetID,
			"pam-account-id":   sess.AccountID,
			"pam-workspace-id": sess.WorkspaceID,
			"pam-target-host":  sess.TargetHost,
			"pam-target-port":  strconv.Itoa(sess.TargetPort),
			"pam-username":     sess.Username,
		},
	}, nil
}

// Serve binds to cfg.Port and accepts incoming connections until
// ctx is cancelled. Each accepted connection is handled in its own
// goroutine. Returns the listener-bind error (or context.Canceled
// on graceful shutdown). On shutdown Serve closes the TCP listener
// (stopping new Accepts), waits up to cfg.ShutdownTimeout for
// in-flight sessions to drain, and then returns even if some
// goroutines have not yet exited so the process can shut down.
// Active SSH sessions observe ctx.Done() via handleConn closing
// their server-side SSH connection.
func (l *SSHListener) Serve(ctx context.Context) error {
	addr := net.JoinHostPort("", strconv.Itoa(l.cfg.Port))
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("gateway: bind ssh listener %s: %w", addr, err)
	}
	log.Printf("gateway: ssh listener bound on %s", addr)
	return l.serveListener(ctx, tcp)
}

// serveListener is the inner accept loop split out so tests can
// drive it with a pre-bound net.Listener (and thus discover the
// random port the OS chose for "127.0.0.1:0"). Serve is the
// production wrapper that binds the listener itself.
//
// On ctx cancellation the listener is closed (unblocking Accept)
// and in-flight sessions are given cfg.ShutdownTimeout to drain.
func (l *SSHListener) serveListener(ctx context.Context, tcp net.Listener) error {
	defer tcp.Close()
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = tcp.Close()
	}()

	for {
		conn, err := tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				done := make(chan struct{})
				go func() {
					wg.Wait()
					close(done)
				}()
				select {
				case <-done:
				case <-time.After(l.cfg.ShutdownTimeout):
					log.Printf("gateway: ssh listener drain exceeded %s — returning anyway", l.cfg.ShutdownTimeout)
				}
				return ctx.Err()
			}
			log.Printf("gateway: ssh accept: %v", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.handleConn(ctx, conn)
		}()
	}
}

// handleConn completes the SSH handshake, validates the inbound
// token, fans out channels to handleChannel, and tears the
// connection down on the first error.
//
// When ctx is cancelled (e.g., process shutdown) the server-side
// SSH connection is closed eagerly so the `for newCh := range chans`
// loop below exits and the goroutine returns. Without this, the
// outer wg.Wait in Serve would block indefinitely on long-lived
// SSH sessions that hold their channel open past SIGTERM.
func (l *SSHListener) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	if d := l.cfg.AcceptTimeout; d > 0 {
		_ = raw.SetDeadline(time.Now().Add(d))
	}
	sconn, chans, reqs, err := ssh.NewServerConn(raw, l.srvConfig)
	if err != nil {
		log.Printf("gateway: ssh handshake from %s: %v", raw.RemoteAddr(), err)
		return
	}
	defer sconn.Close()
	// Clear the deadline now that the handshake is done — sessions
	// can be long-lived.
	_ = raw.SetDeadline(time.Time{})
	go ssh.DiscardRequests(reqs)

	// Drain hook: on context cancellation, close the SSH server
	// connection so the chans range below unblocks. The goroutine
	// also exits naturally when sconn closes via the deferred Close
	// above, so it does not leak on the happy path.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = sconn.Close()
		case <-connDone:
		}
	}()

	sessID := sconn.Permissions.Extensions["pam-session-id"]
	log.Printf("gateway: ssh session %s opened from %s", sessID, sconn.RemoteAddr())

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		go l.handleChannel(ctx, sconn, newCh)
	}
	log.Printf("gateway: ssh session %s closed", sessID)
}

// handleChannel accepts the session channel and proxies it to the
// target host. The proxy is bi-directional; either side closing
// the channel tears down the proxy goroutines.
func (l *SSHListener) handleChannel(ctx context.Context, sconn *ssh.ServerConn, newCh ssh.NewChannel) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		log.Printf("gateway: ssh accept channel: %v", err)
		return
	}
	defer ch.Close()

	sessionID := sconn.Permissions.Extensions["pam-session-id"]
	accountID := sconn.Permissions.Extensions["pam-account-id"]
	workspaceID := sconn.Permissions.Extensions["pam-workspace-id"]
	host := sconn.Permissions.Extensions["pam-target-host"]
	portStr := sconn.Permissions.Extensions["pam-target-port"]
	username := sconn.Permissions.Extensions["pam-username"]
	port, _ := strconv.Atoi(portStr)
	target := net.JoinHostPort(host, strconv.Itoa(port))

	clientCfg, err := l.buildTargetClientConfig(ctx, sessionID, accountID, username)
	if err != nil {
		log.Printf("gateway: build target client config for %s: %v", target, err)
		_, _ = io.WriteString(ch, fmt.Sprintf("\r\npam-gateway: failed to authenticate to target: %v\r\n", err))
		return
	}

	upstream, err := ssh.Dial("tcp", target, clientCfg)
	if err != nil {
		log.Printf("gateway: dial target %s: %v", target, err)
		_, _ = io.WriteString(ch, fmt.Sprintf("\r\npam-gateway: failed to dial target %s: %v\r\n", target, err))
		return
	}
	defer upstream.Close()

	upstreamSession, err := upstream.NewSession()
	if err != nil {
		log.Printf("gateway: upstream new session: %v", err)
		return
	}
	defer upstreamSession.Close()

	stdin, err := upstreamSession.StdinPipe()
	if err != nil {
		log.Printf("gateway: upstream stdin pipe: %v", err)
		return
	}
	stdout, err := upstreamSession.StdoutPipe()
	if err != nil {
		log.Printf("gateway: upstream stdout pipe: %v", err)
		return
	}
	stderr, err := upstreamSession.StderrPipe()
	if err != nil {
		log.Printf("gateway: upstream stderr pipe: %v", err)
		return
	}

	if err := upstreamSession.Shell(); err != nil {
		log.Printf("gateway: upstream shell start: %v", err)
		return
	}

	// Service operator-side channel requests inline. The gateway
	// pre-starts a shell on the upstream so it can wire the
	// recorder + parser before any operator bytes arrive — this
	// goroutine therefore just acknowledges shell-style requests
	// without re-starting anything. exec / subsystem are rejected
	// so every captured session goes through the same audit
	// pipeline.
	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell", "pty-req", "env", "window-change":
				// Best-effort terminal plumbing — failures are
				// logged but never block the proxy. window-change
				// in particular is fire-and-forget per RFC 4254.
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	// Wire the recorder and command parser. Both are optional; the
	// proxy continues to run when either is unwired (dev binaries
	// without S3 credentials or an audit sink stay healthy).
	var (
		recorder *IORecorder
		parser   *CommandParser
	)
	if l.cfg.ReplayStore != nil {
		if rec, recErr := NewIORecorder(sessionID, l.cfg.ReplayStore, IORecorderConfig{}); recErr == nil {
			recorder = rec
		} else {
			log.Printf("gateway: build recorder session=%s: %v", sessionID, recErr)
		}
	}
	if l.cfg.CommandSink != nil {
		if p, pErr := NewCommandParser(sessionID, l.cfg.CommandSink, CommandParserConfig{}); pErr == nil {
			parser = p
		} else {
			log.Printf("gateway: build command parser session=%s: %v", sessionID, pErr)
		}
	}

	stdinReader := io.Reader(ch)
	stdoutWriter := io.Writer(ch)
	stderrWriter := io.Writer(ch.Stderr())
	if recorder != nil {
		stdinReader = recorder.TeeReader(DirectionInput, stdinReader)
		stdoutWriter = recorder.TeeWriter(DirectionOutput, stdoutWriter)
		stderrWriter = recorder.TeeWriter(DirectionStderr, stderrWriter)
	}
	if parser != nil {
		stdinReader = &commandParserTap{src: stdinReader, parser: parser, ctx: ctx, evaluator: l.cfg.CommandPolicy, workspaceID: workspaceID, ch: ch}
		stdoutWriter = &commandParserOutputTap{dst: stdoutWriter, parser: parser}
		stderrWriter = &commandParserOutputTap{dst: stderrWriter, parser: parser}
	}

	var wg sync.WaitGroup
	wg.Add(3)
	// Closing the upstream stdin pipe after io.Copy returns is
	// what gives the upstream shell a definite EOF — without it,
	// a client that closes its own stdin (e.g. "ssh host < script")
	// would leave the upstream session reading forever and
	// upstreamSession.Wait() below would never return, pinning
	// the whole handleChannel goroutine.
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stdin, stdinReader)
		_ = stdin.Close()
	}()
	go func() { defer wg.Done(); _, _ = io.Copy(stdoutWriter, stdout) }()
	go func() { defer wg.Done(); _, _ = io.Copy(stderrWriter, stderr) }()
	waitErr := upstreamSession.Wait()
	// Forward the upstream's exit status so the operator's
	// ssh.Session.Wait() returns a real ExitError instead of the
	// generic "exited without exit status" error.
	var status uint32
	if exitErr, ok := waitErr.(*ssh.ExitError); ok {
		status = uint32(exitErr.ExitStatus())
	} else if waitErr != nil {
		status = 1
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, _ = ch.SendRequest("exit-status", false, payload)
	// upstreamSession.Wait returning closes the upstream stdout /
	// stderr pipes (so the ch <- stdout / ch.Stderr <- stderr
	// goroutines fall out of io.Copy on their own) but does NOT
	// unblock the stdin <- ch goroutine, which is reading from the
	// downstream client channel. A slow or misbehaving client could
	// then keep that goroutine pinned until it eventually closes the
	// channel. Closing ch here gives every io.Copy a definite
	// terminal state so wg.Wait() can never deadlock on the stdin
	// reader. Subsequent close on the deferred path is a no-op.
	_ = ch.Close()
	wg.Wait()

	// Flush the audit trail and recording. flushCtx is detached
	// from the request ctx so a SIGTERM mid-flush still completes —
	// otherwise the final replay upload would be silently dropped.
	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelFlush()
	if parser != nil {
		parser.Close(flushCtx)
	}
	if recorder != nil {
		if err := recorder.Close(flushCtx); err != nil {
			log.Printf("gateway: flush recording session=%s: %v", sessionID, err)
		}
	}
}

// commandParserTap wraps the downstream-client stdin reader so the
// parser sees every byte the operator types. Bytes flow through
// unchanged to the upstream shell unless the command policy engine
// (Milestone 9) rejects them — denied lines are replaced with an
// empty newline before being forwarded to the shell, and a
// plain-language reason is written directly to the operator's SSH
// channel so they see why the command was blocked.
type commandParserTap struct {
	src         io.Reader
	parser      *CommandParser
	ctx         context.Context
	evaluator   CommandPolicyEvaluator
	workspaceID string
	ch          ssh.Channel
	lineBuf     []byte
}

func (t *commandParserTap) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n == 0 {
		return n, err
	}

	// Walk the read buffer ONE LINE AT A TIME so SetRiskFlag (called
	// from evaluatePolicy when a newline closes a line) always
	// targets the right pending command.
	//
	// Why this matters: CommandParser.WriteInput treats every newline
	// in its input as a command boundary — flushPendingLocked
	// enqueues the previous pending command to the sink, then
	// startCommandLocked promotes the just-accumulated bytes into a
	// new pending command. If we hand the full read buffer to
	// WriteInput in one shot, a paste like "denied-cmd\nnext-cmd\n"
	// causes WriteInput to advance pending past "denied-cmd" before
	// evaluatePolicy has a chance to tag it. The subsequent
	// SetRiskFlag would then land on "next-cmd" instead — corrupting
	// the audit trail by hiding the deny on the actually-denied
	// command and falsely flagging an unrelated one.
	//
	// Per-line processing keeps the flag on the right command: each
	// newline-terminated chunk is fed to WriteInput (which makes the
	// just-typed line the pending command), then evaluatePolicy is
	// run on the same chunk so the deny flag lands on pending while
	// pending still refers to the just-closed line. The NEXT chunk's
	// WriteInput flushes the flagged pending to the sink, exactly
	// once, with the right risk_flag.
	//
	// Output buffer: denied lines collapse to a single '\n' so the
	// upstream shell sees an empty input. Allowed lines pass through
	// unchanged. We allocate a fresh slice (rather than aliasing
	// p[:0]) so the denied-line shrink does not race with the
	// source bytes still queued behind it.
	out := make([]byte, 0, n)
	lineStart := 0
	for i := 0; i < n; i++ {
		if p[i] != '\n' && p[i] != '\r' {
			continue
		}
		chunk := p[lineStart : i+1]
		t.parser.WriteInput(t.ctx, chunk)
		if t.evaluatePolicy(chunk) {
			out = append(out, '\n')
		} else {
			out = append(out, chunk...)
		}
		lineStart = i + 1
	}
	// Trailing bytes without a newline terminator: feed both
	// WriteInput and evaluatePolicy so the parser's input buffer and
	// the policy tap's lineBuf stay in lockstep. Pass them through
	// unchanged — we cannot decide deny/allow until we see the
	// newline.
	if lineStart < n {
		partial := p[lineStart:n]
		t.parser.WriteInput(t.ctx, partial)
		_ = t.evaluatePolicy(partial)
		out = append(out, partial...)
	}
	copy(p, out)
	return len(out), err
}

// evaluatePolicy keeps a running line buffer so newline-terminated
// commands can be checked against the policy engine. Returns true
// when the line was denied — the caller substitutes an empty
// newline for the remainder so the line never reaches the upstream
// shell. The deny reason is written directly to the operator's SSH
// channel here (not buffered for Read) because Read's output is
// piped to upstream stdin, not back to the operator.
func (t *commandParserTap) evaluatePolicy(b []byte) bool {
	if t.evaluator == nil {
		return false
	}
	for _, c := range b {
		if c == '\n' || c == '\r' {
			line := string(t.lineBuf)
			t.lineBuf = t.lineBuf[:0]
			if line == "" {
				continue
			}
			ctx, cancel := context.WithTimeout(t.ctx, 2*time.Second)
			action, reason, err := t.evaluator.EvaluateCommand(ctx, t.workspaceID, t.parser.sessionID, line)
			cancel()
			if err != nil {
				log.Printf("gateway: evaluate command session=%s: %v", t.parser.sessionID, err)
				continue
			}
			switch action {
			case "deny":
				t.parser.SetRiskFlag("policy:deny")
				if t.ch != nil {
					msg := fmt.Sprintf("\r\npam-gateway: command blocked by policy: %s\r\n", reason)
					if _, werr := t.ch.Write([]byte(msg)); werr != nil {
						log.Printf("gateway: write deny message to operator session=%s: %v", t.parser.sessionID, werr)
					}
				}
				return true
			case "step_up":
				t.parser.SetRiskFlag("policy:step_up")
			}
		} else {
			if len(t.lineBuf) < defaultMaxInputBytes {
				t.lineBuf = append(t.lineBuf, c)
			}
		}
	}
	return false
}

// commandParserOutputTap mirrors output bytes into the parser so
// the running per-command SHA-256 hash sees the target's response.
type commandParserOutputTap struct {
	dst    io.Writer
	parser *CommandParser
}

func (t *commandParserOutputTap) Write(p []byte) (int, error) {
	t.parser.WriteOutput(p)
	return t.dst.Write(p)
}

// buildTargetClientConfig resolves the authentication strategy for
// the upstream connection. The preferred path is the SSH CA: the
// gateway signs an ephemeral keypair with the CA private key and
// uses the resulting certificate to authenticate. Falling back to
// the injected password / private key is the second path.
func (l *SSHListener) buildTargetClientConfig(ctx context.Context, sessionID, accountID, username string) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // host-key pinning lands in a follow-up milestone
		Timeout:         10 * time.Second,
	}
	if l.cfg.CA != nil {
		cert, signer, err := l.cfg.CA.MintEphemeralCert(username)
		if err == nil {
			certSigner, certErr := ssh.NewCertSigner(cert, signer)
			if certErr == nil {
				cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(certSigner)}
				return cfg, nil
			}
			log.Printf("gateway: build cert signer: %v — falling back to injected credential", certErr)
		} else {
			log.Printf("gateway: mint ephemeral cert: %v — falling back to injected credential", err)
		}
	}
	if l.cfg.Injector == nil {
		return nil, errors.New("gateway: no SSH CA and no injector configured")
	}
	secretType, plaintext, err := l.cfg.Injector.InjectSecret(ctx, sessionID, accountID)
	if err != nil {
		return nil, fmt.Errorf("inject secret: %w", err)
	}
	switch secretType {
	case "password", "":
		cfg.Auth = []ssh.AuthMethod{ssh.Password(string(plaintext))}
	case "ssh_key":
		signer, err := ssh.ParsePrivateKey(plaintext)
		if err != nil {
			return nil, fmt.Errorf("parse injected ssh key: %w", err)
		}
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	default:
		return nil, fmt.Errorf("unsupported secret_type %q", secretType)
	}
	return cfg, nil
}

// LoadOrGenerateHostKey resolves the SSH host key from one of three
// places, in priority order:
//
//  1. inline PEM content (when valueOrPath begins with a `-----BEGIN`
//     header, after whitespace trimming) — this is what K8s Secret
//     env injection via `valueFrom: secretKeyRef` produces;
//  2. a filesystem path (any non-empty value that is NOT inline PEM) —
//     this is the production pattern where the Secret is mounted as
//     a file and the env var points at the mount path;
//  3. an ephemeral 2048-bit RSA key (when valueOrPath is empty or the
//     referenced file does not exist) — fine for dev, NOT for
//     production because operator clients will see a host-key change
//     after every pod restart.
//
// Accepting both forms means an operator can pick whichever K8s
// Secret pattern they prefer (env injection vs. volume mount) without
// having to re-template the manifest.
func LoadOrGenerateHostKey(valueOrPath string) (ssh.Signer, error) {
	if isInlinePEM(valueOrPath) {
		return ssh.ParsePrivateKey([]byte(strings.TrimSpace(valueOrPath)))
	}
	if valueOrPath != "" {
		pem, err := os.ReadFile(valueOrPath)
		if err == nil {
			return ssh.ParsePrivateKey(pem)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("gateway: read host key %s: %w", valueOrPath, err)
		}
		log.Printf("gateway: ssh host key %s not found — generating ephemeral key", valueOrPath)
	} else {
		log.Printf("gateway: PAM_GATEWAY_SSH_HOST_KEY unset — generating ephemeral key")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("gateway: signer from generated host key: %w", err)
	}
	return signer, nil
}

// isInlinePEM reports whether s contains PEM-encoded key material
// rather than a filesystem path. A leading `-----BEGIN` marker (after
// trimming whitespace) is the canonical PEM frame, so a value
// starting with that prefix cannot also be a valid filesystem path
// on any common OS — making the path-vs-content discrimination
// unambiguous.
func isInlinePEM(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "-----BEGIN")
}
