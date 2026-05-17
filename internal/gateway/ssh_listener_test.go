package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSSHListener_EndToEnd_RecordsAndCapturesCommands wires the
// real SSH listener against an in-process upstream SSH server, then
// drives a session through it as a client and asserts that:
//   - the replay store received a framed I/O blob,
//   - the command sink received one row per typed command, in order,
//   - the recorder + parser flushed cleanly on session teardown.
//
// The test deliberately exercises the full handleChannel path: the
// listener accepts a real SSH handshake, validates the token via a
// stub authorizer, dials a real upstream session, and proxies both
// directions through the recorder + parser taps.
func TestSSHListener_EndToEnd_RecordsAndCapturesCommands(t *testing.T) {
	upstream := newFakeUpstreamSSH(t)
	defer upstream.Close()

	const (
		sessionID = "01HXYE2EQR8K4PAMZJ4N7N9X7K"
		username  = "ops"
		token     = "connect-token-end-to-end"
	)

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}
	authz := &fakeSessionAuthorizer{
		session: AuthorizedSession{
			SessionID:   sessionID,
			WorkspaceID: "ws-1",
			LeaseID:     "lease-1",
			AssetID:     "asset-1",
			AccountID:   "acct-1",
			Protocol:    "ssh",
			TargetHost:  host,
			TargetPort:  port,
			Username:    username,
		},
		expectedToken: token,
	}
	injector := &fakeSecretInjector{secretType: "password", secret: []byte("ignored-by-fake-target")}
	replayStore := NewMemoryReplayStore()
	commandSink := NewMemoryCommandSink()

	hostKey := mustGenerateHostKey(t)
	listener, err := NewSSHListener(SSHListenerConfig{
		Port:        0, // 0 → pick a free port
		HostKey:     hostKey,
		Authorizer:  authz,
		Injector:    injector,
		ReplayStore: replayStore,
		CommandSink: commandSink,
	})
	if err != nil {
		t.Fatalf("NewSSHListener: %v", err)
	}

	gw, gwAddr := startListener(t, listener)
	defer gw.cancel()

	// Drive a client through the gateway. The client sends two
	// commands then closes stdin; the upstream "shell" replies on
	// stdout with deterministic output we can hash and assert on.
	clientCfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cli, err := ssh.Dial("tcp", gwAddr, clientCfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("client new session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("client stdin pipe: %v", err)
	}
	stdoutR, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("client stdout pipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("client shell start: %v", err)
	}

	const (
		cmd1 = "uptime"
		cmd2 = "whoami"
	)
	// Drive the session like a human operator: send a command,
	// wait for its output line, send the next. Pipelining both
	// commands at once would let cmd2's newline reach the parser
	// before cmd1's output arrives, leaving cmd1 with an empty
	// output hash. That is a separate (real) limitation of
	// CommandParser; testing the happy path requires a properly
	// interleaved exchange.
	stdoutBuf := bufio.NewReader(stdoutR)
	readUntilLine := func(want string) string {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		var sb strings.Builder
		for time.Now().Before(deadline) {
			line, err := stdoutBuf.ReadString('\n')
			if line != "" {
				sb.WriteString(line)
				if strings.Contains(line, want) {
					return sb.String()
				}
			}
			if err != nil {
				t.Fatalf("read stdout while waiting for %q: collected=%q err=%v", want, sb.String(), err)
			}
		}
		t.Fatalf("timed out waiting for %q in stdout; collected=%q", want, sb.String())
		return sb.String()
	}

	if _, err := io.WriteString(stdin, cmd1+"\n"); err != nil {
		t.Fatalf("write cmd1 to stdin: %v", err)
	}
	out1 := readUntilLine("uptime: ok")
	if _, err := io.WriteString(stdin, cmd2+"\n"); err != nil {
		t.Fatalf("write cmd2 to stdin: %v", err)
	}
	out2 := readUntilLine("whoami: " + username)
	_ = stdin.Close()

	// Drain anything that may follow EOF so the read side closes
	// cleanly. The session exits when the upstream sends
	// exit-status and the gateway tears down the channel.
	rest, _ := io.ReadAll(stdoutBuf)
	output := out1 + out2 + string(rest)
	if !strings.Contains(output, "uptime: ok") {
		t.Fatalf("expected uptime echo in output, got %q", output)
	}
	if !strings.Contains(output, "whoami: "+username) {
		t.Fatalf("expected whoami echo in output, got %q", output)
	}

	// Wait for the upstream session to finish. The gateway closes
	// the recorder + parser on the way out, so by the time Wait
	// returns the replay blob + command rows are flushed.
	if err := sess.Wait(); err != nil && !errors.Is(err, io.EOF) {
		// Many shells exit nonzero on EOF; tolerate any wait error
		// that isn't a hard transport failure.
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("client session wait: %v", err)
		}
	}
	_ = cli.Close()

	// The listener owns the recorder + parser lifecycle so the
	// flush is async; poll with a tight bound rather than sleeping
	// a fixed interval.
	deadline := time.Now().Add(3 * time.Second)
	var replayBytes []byte
	for time.Now().Before(deadline) {
		if b, ok := replayStore.Get(sessionID); ok && len(b) > 0 {
			replayBytes = b
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(replayBytes) == 0 {
		t.Fatalf("expected replay store to receive a non-empty blob for %s; got %v", sessionID, replayStore.Keys())
	}

	frames, err := DecodeFrames(replayBytes)
	if err != nil {
		t.Fatalf("DecodeFrames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatalf("expected at least one frame in replay; got 0")
	}
	var sawInput, sawOutput bool
	for _, f := range frames {
		switch f.Direction {
		case DirectionInput:
			sawInput = true
		case DirectionOutput:
			sawOutput = true
		}
	}
	if !sawInput || !sawOutput {
		t.Fatalf("expected replay to contain both input and output frames, got input=%v output=%v", sawInput, sawOutput)
	}

	// Poll the command sink the same way — flushPendingLocked
	// enqueues into a buffered channel that the worker drains.
	deadline = time.Now().Add(3 * time.Second)
	var rows []AppendCommandInput
	for time.Now().Before(deadline) {
		rows = commandSink.Commands()
		if len(rows) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) < 2 {
		t.Fatalf("expected at least 2 command rows; got %d (%+v)", len(rows), rows)
	}
	// Each row's sequence is assigned by the parser worker so the
	// first row must be seq=1 and the second seq=2, in input order.
	if rows[0].Sequence != 1 || rows[0].Input != cmd1 {
		t.Fatalf("row 0 mismatch: want seq=1 input=%q; got seq=%d input=%q", cmd1, rows[0].Sequence, rows[0].Input)
	}
	if rows[1].Sequence != 2 || rows[1].Input != cmd2 {
		t.Fatalf("row 1 mismatch: want seq=2 input=%q; got seq=%d input=%q", cmd2, rows[1].Sequence, rows[1].Input)
	}
	for _, r := range rows {
		if r.SessionID != sessionID {
			t.Fatalf("row session mismatch: want %s; got %s", sessionID, r.SessionID)
		}
		if r.OutputHash == "" {
			t.Fatalf("row %d has empty output hash — expected non-empty SHA-256", r.Sequence)
		}
	}
}

// TestSSHListener_CommandPolicyDeny verifies that when the command
// policy evaluator returns "deny" for a typed command, the deny
// reason is written *to the operator's SSH channel* (visible on
// the client's stdout) and NOT smuggled back into upstream stdin
// (which would execute the human-readable reason as shell input
// on the target asset). It is the regression test for the bug
// Devin Review caught on PR #96.
func TestSSHListener_CommandPolicyDeny(t *testing.T) {
	upstream := newFakeUpstreamSSH(t)
	defer upstream.Close()

	const (
		sessionID  = "01HXYE2EQR8K4PAMZJ4N7N9X7L"
		username   = "ops"
		token      = "deny-token"
		denyCmd    = "rm-rf-prod"
		denyReason = "destructive command on prod asset"
	)

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}

	authz := &fakeSessionAuthorizer{
		session: AuthorizedSession{
			SessionID:   sessionID,
			WorkspaceID: "ws-deny",
			LeaseID:     "lease-deny",
			AssetID:     "asset-deny",
			AccountID:   "acct-deny",
			Protocol:    "ssh",
			TargetHost:  host,
			TargetPort:  port,
			Username:    username,
		},
		expectedToken: token,
	}
	injector := &fakeSecretInjector{secretType: "password", secret: []byte("ignored")}
	replayStore := NewMemoryReplayStore()
	commandSink := NewMemoryCommandSink()
	policy := &fakeCommandPolicy{denyExact: denyCmd, reason: denyReason}

	hostKey := mustGenerateHostKey(t)
	listener, err := NewSSHListener(SSHListenerConfig{
		HostKey:       hostKey,
		Authorizer:    authz,
		Injector:      injector,
		ReplayStore:   replayStore,
		CommandSink:   commandSink,
		CommandPolicy: policy,
	})
	if err != nil {
		t.Fatalf("NewSSHListener: %v", err)
	}
	gw, gwAddr := startListener(t, listener)
	defer gw.cancel()

	clientCfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cli, err := ssh.Dial("tcp", gwAddr, clientCfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("client new session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("client stdin pipe: %v", err)
	}
	stdoutR, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("client stdout pipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("client shell start: %v", err)
	}

	// Issue the denied command. The listener should swap its bytes
	// for an empty newline on the upstream side and emit the deny
	// reason directly to the operator's channel (stdout from the
	// client's perspective).
	if _, err := io.WriteString(stdin, denyCmd+"\n"); err != nil {
		t.Fatalf("write deny cmd to stdin: %v", err)
	}
	stdoutBuf := bufio.NewReader(stdoutR)
	deadline := time.Now().Add(3 * time.Second)
	var collected strings.Builder
	for time.Now().Before(deadline) {
		line, rerr := stdoutBuf.ReadString('\n')
		if line != "" {
			collected.WriteString(line)
			if strings.Contains(collected.String(), "command blocked by policy") {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(collected.String(), "command blocked by policy") {
		t.Fatalf("expected deny banner on operator stdout; got %q", collected.String())
	}
	if !strings.Contains(collected.String(), denyReason) {
		t.Fatalf("expected deny reason %q on operator stdout; got %q", denyReason, collected.String())
	}

	// The fake upstream echoes any unknown command back as "unknown: <line>".
	// The denied command was rewritten to an empty newline before
	// reaching the upstream shell, so we MUST NOT see an "unknown:
	// rm-rf-prod" echo — that would mean the policy bypass we're
	// fixing has regressed. We also must not see the deny reason
	// echoed as input ("unknown: pam-gateway: command blocked …").
	_ = stdin.Close()
	rest, _ := io.ReadAll(stdoutBuf)
	combined := collected.String() + string(rest)
	if strings.Contains(combined, "unknown: "+denyCmd) {
		t.Fatalf("upstream shell received the denied command; got %q", combined)
	}
	if strings.Contains(combined, "unknown: pam-gateway") {
		t.Fatalf("deny banner was smuggled into upstream stdin and echoed back; got %q", combined)
	}

	// Tear the session down so the listener flushes the parser /
	// recorder.
	if err := sess.Wait(); err != nil {
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) && !errors.Is(err, io.EOF) {
			t.Logf("client session wait: %v", err)
		}
	}
	_ = cli.Close()

	// The deny path still records the typed bytes as a command row,
	// flagged with policy:deny so audit downstream can spot the
	// attempt. Poll the sink with a small timeout.
	pollDeadline := time.Now().Add(2 * time.Second)
	var rows []AppendCommandInput
	for time.Now().Before(pollDeadline) {
		rows = commandSink.Commands()
		if len(rows) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) < 1 {
		t.Fatalf("expected the denied command to be captured as a sink row; got 0 rows")
	}
	row := rows[0]
	if row.Input != denyCmd {
		t.Fatalf("captured row input mismatch: want %q; got %q", denyCmd, row.Input)
	}
	if row.RiskFlag == nil {
		t.Fatalf("captured row should carry a policy:deny risk flag; got nil")
	}
	if !strings.Contains(*row.RiskFlag, "policy:deny") {
		t.Fatalf("captured row should carry policy:deny reason; got %q", *row.RiskFlag)
	}
}

// TestSSHListener_CommandPolicyDeny_PastedBatch is the regression
// test for the per-line policy-evaluation bug that Devin Review
// caught: when the operator pastes (or pipes) two newline-terminated
// commands in a single Read buffer and only the first is denied,
// the audit trail must still tag the right command. Before the fix
// commandParserTap.Read fed the full buffer to WriteInput in one
// shot — both newlines were processed, advancing the parser's
// pending pointer past the denied command before SetRiskFlag ran,
// so the deny flag landed on the SECOND (innocent) command and the
// actually-denied command appeared unflagged.
//
// The test pastes "denied-cmd\nallowed-cmd\n" in a single io.Write
// and asserts:
//   - the row for the denied command carries the policy:deny flag
//   - the row for the allowed command does NOT carry a flag
//   - the denied command never reaches the upstream shell
//   - the allowed command DOES reach the upstream shell (so the
//     gateway is not silently dropping otherwise-legal traffic).
func TestSSHListener_CommandPolicyDeny_PastedBatch(t *testing.T) {
	upstream := newFakeUpstreamSSH(t)
	defer upstream.Close()

	const (
		sessionID  = "01HXYE2EQR8K4PAMZJ4N7N9X7P"
		username   = "ops"
		token      = "deny-paste-token"
		denyCmd    = "rm-rf-prod"
		allowedCmd = "ls-allowed"
		denyReason = "destructive command on prod asset"
	)

	host, portStr, err := net.SplitHostPort(upstream.Addr())
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}

	authz := &fakeSessionAuthorizer{
		session: AuthorizedSession{
			SessionID:   sessionID,
			WorkspaceID: "ws-paste",
			LeaseID:     "lease-paste",
			AssetID:     "asset-paste",
			AccountID:   "acct-paste",
			Protocol:    "ssh",
			TargetHost:  host,
			TargetPort:  port,
			Username:    username,
		},
		expectedToken: token,
	}
	injector := &fakeSecretInjector{secretType: "password", secret: []byte("ignored")}
	replayStore := NewMemoryReplayStore()
	commandSink := NewMemoryCommandSink()
	policy := &fakeCommandPolicy{denyExact: denyCmd, reason: denyReason}

	hostKey := mustGenerateHostKey(t)
	listener, err := NewSSHListener(SSHListenerConfig{
		HostKey:       hostKey,
		Authorizer:    authz,
		Injector:      injector,
		ReplayStore:   replayStore,
		CommandSink:   commandSink,
		CommandPolicy: policy,
	})
	if err != nil {
		t.Fatalf("NewSSHListener: %v", err)
	}
	gw, gwAddr := startListener(t, listener)
	defer gw.cancel()

	clientCfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cli, err := ssh.Dial("tcp", gwAddr, clientCfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("client new session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("client stdin pipe: %v", err)
	}
	stdoutR, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("client stdout pipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("client shell start: %v", err)
	}

	// Single write — both lines hit the gateway's commandParserTap.Read
	// in one buffer, which is exactly the trigger condition for the
	// original bug.
	if _, err := io.WriteString(stdin, denyCmd+"\n"+allowedCmd+"\n"); err != nil {
		t.Fatalf("write batch to stdin: %v", err)
	}

	// Read upstream stdout until we see the allowed command echo, the
	// deny banner, and EOF (or our deadline). The fake upstream echoes
	// unknown commands as "unknown: <line>".
	stdoutBuf := bufio.NewReader(stdoutR)
	deadline := time.Now().Add(3 * time.Second)
	var collected strings.Builder
	sawAllowedEcho := false
	sawDenyBanner := false
	for time.Now().Before(deadline) {
		line, rerr := stdoutBuf.ReadString('\n')
		if line != "" {
			collected.WriteString(line)
			if strings.Contains(collected.String(), "command blocked by policy") {
				sawDenyBanner = true
			}
			if strings.Contains(collected.String(), "unknown: "+allowedCmd) {
				sawAllowedEcho = true
			}
			if sawAllowedEcho && sawDenyBanner {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if !sawDenyBanner {
		t.Fatalf("expected deny banner on operator stdout; got %q", collected.String())
	}
	if !sawAllowedEcho {
		t.Fatalf("expected upstream echo of allowed command %q; got %q", allowedCmd, collected.String())
	}

	_ = stdin.Close()
	rest, _ := io.ReadAll(stdoutBuf)
	combined := collected.String() + string(rest)
	if strings.Contains(combined, "unknown: "+denyCmd) {
		t.Fatalf("upstream shell received the denied command; got %q", combined)
	}
	if strings.Contains(combined, "unknown: pam-gateway") {
		t.Fatalf("deny banner was smuggled into upstream stdin and echoed back; got %q", combined)
	}

	if err := sess.Wait(); err != nil {
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) && !errors.Is(err, io.EOF) {
			t.Logf("client session wait: %v", err)
		}
	}
	_ = cli.Close()

	// Audit assertions — the meat of the regression. Poll until BOTH
	// rows are visible (the parser flushes the second command on
	// session teardown).
	pollDeadline := time.Now().Add(2 * time.Second)
	var rows []AppendCommandInput
	for time.Now().Before(pollDeadline) {
		rows = commandSink.Commands()
		if len(rows) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) < 2 {
		t.Fatalf("expected 2 sink rows (deny + allow); got %d: %+v", len(rows), rows)
	}
	deniedRow, allowedRow := rows[0], rows[1]
	if deniedRow.Input != denyCmd {
		t.Fatalf("row[0] input = %q; want %q", deniedRow.Input, denyCmd)
	}
	if deniedRow.RiskFlag == nil {
		t.Fatalf("row[0] (denied) should carry policy:deny flag; got nil")
	}
	if !strings.Contains(*deniedRow.RiskFlag, "policy:deny") {
		t.Fatalf("row[0] (denied) risk_flag = %q; want substring policy:deny", *deniedRow.RiskFlag)
	}
	if allowedRow.Input != allowedCmd {
		t.Fatalf("row[1] input = %q; want %q", allowedRow.Input, allowedCmd)
	}
	if allowedRow.RiskFlag != nil {
		t.Fatalf("row[1] (allowed) must NOT carry a risk_flag; got %q", *allowedRow.RiskFlag)
	}
}

// fakeCommandPolicy is a minimal CommandPolicyEvaluator that returns
// "deny" with a fixed reason whenever the incoming command matches
// denyExact, and "allow" for everything else.
type fakeCommandPolicy struct {
	denyExact string
	reason    string
}

func (p *fakeCommandPolicy) EvaluateCommand(_ context.Context, _, _, input string) (string, string, error) {
	if p == nil {
		return "allow", "", nil
	}
	if input == p.denyExact {
		return "deny", p.reason, nil
	}
	return "allow", "", nil
}

// TestSSHListener_RejectsBadToken proves the gateway never opens a
// channel to the upstream when the operator's connect token does
// not authorize against the control plane.
func TestSSHListener_RejectsBadToken(t *testing.T) {
	authz := &fakeSessionAuthorizer{expectedToken: "the-real-token"}
	injector := &fakeSecretInjector{secretType: "password", secret: []byte("ignored")}
	hostKey := mustGenerateHostKey(t)
	listener, err := NewSSHListener(SSHListenerConfig{
		HostKey:    hostKey,
		Authorizer: authz,
		Injector:   injector,
	})
	if err != nil {
		t.Fatalf("NewSSHListener: %v", err)
	}
	gw, gwAddr := startListener(t, listener)
	defer gw.cancel()

	clientCfg := &ssh.ClientConfig{
		User:            "ops",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong-token")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	cli, err := ssh.Dial("tcp", gwAddr, clientCfg)
	if err == nil {
		_ = cli.Close()
		t.Fatalf("expected dial to fail with an auth error; got nil")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") && !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("expected auth/handshake error; got %v", err)
	}
}

// --- helpers -----------------------------------------------------

type gatewayHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// startListener stands up the SSHListener on a random localhost
// port and returns the bound address + a cancel hook. The hook
// terminates Serve and waits for it to exit (bounded by the
// listener's own ShutdownTimeout).
func startListener(t *testing.T, listener *SSHListener) (*gatewayHandle, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = listener.serveListener(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Logf("warning: gateway listener did not exit within 5s")
		}
	})
	return &gatewayHandle{cancel: cancel, done: done}, addr
}

// fakeSessionAuthorizer always returns the configured AuthorizedSession
// when the supplied token matches expectedToken; otherwise it errors.
type fakeSessionAuthorizer struct {
	session       AuthorizedSession
	expectedToken string
}

func (a *fakeSessionAuthorizer) AuthorizeConnectToken(_ context.Context, token string) (*AuthorizedSession, error) {
	if a == nil {
		return nil, errors.New("nil authorizer")
	}
	if token != a.expectedToken {
		return nil, errors.New("unauthorized")
	}
	s := a.session
	return &s, nil
}

// fakeSecretInjector returns a canned secret without contacting any
// external service. The injected value is intentionally not used by
// the fake upstream — the upstream accepts any password — so tests
// stay deterministic.
type fakeSecretInjector struct {
	secretType string
	secret     []byte
	err        error
}

func (i *fakeSecretInjector) InjectSecret(_ context.Context, _, _ string) (string, []byte, error) {
	if i == nil {
		return "", nil, errors.New("nil injector")
	}
	if i.err != nil {
		return "", nil, i.err
	}
	return i.secretType, i.secret, nil
}

func mustGenerateHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // 1024 is fine for unit tests
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer from generated key: %v", err)
	}
	return signer
}

// fakeUpstreamSSH is a minimal in-process SSH server that accepts
// any password, echoes "uptime: ok\n" / "whoami: <user>\n" in
// response to the corresponding commands, then closes the session
// when stdin reaches EOF. Used as the "target asset" the gateway
// proxies into.
type fakeUpstreamSSH struct {
	ln       net.Listener
	hostKey  ssh.Signer
	addr     string
	wg       sync.WaitGroup
	closing  chan struct{}
	closeOnc sync.Once
}

func newFakeUpstreamSSH(t *testing.T) *fakeUpstreamSSH {
	t.Helper()
	hk := mustGenerateHostKey(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	srv := &fakeUpstreamSSH{
		ln:      ln,
		hostKey: hk,
		addr:    ln.Addr().String(),
		closing: make(chan struct{}),
	}
	srv.wg.Add(1)
	go srv.acceptLoop()
	return srv
}

func (s *fakeUpstreamSSH) Addr() string { return s.addr }

func (s *fakeUpstreamSSH) Close() {
	s.closeOnc.Do(func() {
		close(s.closing)
		_ = s.ln.Close()
	})
	s.wg.Wait()
}

func (s *fakeUpstreamSSH) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handle(c)
		}(conn)
	}
}

func (s *fakeUpstreamSSH) handle(c net.Conn) {
	defer c.Close()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(s.hostKey)
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		go s.serveSession(newCh, sconn.User())
	}
}

func (s *fakeUpstreamSSH) serveSession(newCh ssh.NewChannel, user string) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	// Drain reqs and reply true to shell/exec requests so the
	// upstream session looks like a real shell to the gateway.
	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell", "exec", "pty-req", "env":
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

	// Read input until EOF, splitting on '\n' and responding to a
	// fixed vocabulary. The output is deterministic so the test
	// can assert on the SHA-256 captured by the command parser.
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := ch.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := indexOfByte(buf, '\n')
				if idx < 0 {
					break
				}
				line := strings.TrimSpace(string(buf[:idx]))
				buf = buf[idx+1:]
				switch line {
				case "uptime":
					_, _ = io.WriteString(ch, "uptime: ok\r\n")
				case "whoami":
					_, _ = fmt.Fprintf(ch, "whoami: %s\r\n", user)
				default:
					if line != "" {
						_, _ = fmt.Fprintf(ch, "unknown: %s\r\n", line)
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	_ = ch.Close()
}

func indexOfByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
