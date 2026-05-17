package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

// CommandSink is the narrow contract CommandParser uses to persist
// per-command audit rows. The production implementation is
// APICommandSink (HTTP POST to ztna-api's
// /pam/sessions/:id/commands endpoint); tests substitute
// MemoryCommandSink so the parser suite can assert on captured
// rows without a live ztna-api.
type CommandSink interface {
	AppendCommand(ctx context.Context, in AppendCommandInput) error
}

// AppendCommandInput is the wire shape APICommandSink marshals to
// JSON. Keep the field names aligned with the
// ztna-api /pam/sessions/:id/commands handler — drift here breaks
// every gateway → API round trip.
type AppendCommandInput struct {
	SessionID  string    `json:"session_id"`
	Sequence   int       `json:"sequence"`
	Input      string    `json:"input"`
	OutputHash string    `json:"output_hash,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	RiskFlag   *string   `json:"risk_flag,omitempty"`
}

// CommandParser tracks newline-delimited command boundaries in a
// session's terminal I/O and flushes one audit row per command. The
// parser is bidirectional:
//
//   - WriteInput is called for every byte the operator types into
//     the SSH session (DirectionInput). Newlines close the current
//     command — the input line up to the newline is captured and
//     the output buffer is reset for the next command's response.
//   - WriteOutput / WriteStderr is called for every byte the target
//     emits back. The bytes feed an incremental SHA-256 so the
//     audit row carries an OutputHash without retaining the full
//     output blob in memory.
//
// Each command captured here is also embedded in the S3 replay
// blob via IORecorder — the row is the index, the blob is the
// content.
//
// The parser is safe for concurrent use: WriteInput and the output
// writers run in separate goroutines under the SSH proxy.
type CommandParser struct {
	sessionID string
	sink      CommandSink
	now       func() time.Time
	maxInput  int

	mu        sync.Mutex
	closed    bool
	seq       int
	inputBuf  strings.Builder
	hasOutput bool
	outHash   hashStateProvider
	pending   *AppendCommandInput

	// queueCh serialises commands into the sink so the order seen
	// by AppendCommand matches the order the operator typed them.
	// A buffered channel (capacity 256) absorbs short bursts; if the
	// sink stalls and the queue saturates, further commands are
	// dropped and logged — the operator's session keeps running.
	queueCh    chan AppendCommandInput
	workerDone chan struct{}
}

// CommandParserConfig captures the optional knobs for
// NewCommandParser.
type CommandParserConfig struct {
	// MaxInputBytes bounds a single input line. A pathological
	// client could otherwise pin a goroutine on an infinite
	// no-newline stream. Default 4096 bytes; lines longer than
	// the cap are flushed truncated.
	MaxInputBytes int

	// Now overrides time.Now for testability. nil → time.Now.
	Now func() time.Time
}

// defaultMaxInputBytes caps a single command line at 4 KiB so a
// malicious or buggy client cannot pin the parser's input buffer.
const defaultMaxInputBytes = 4096

// hashStateProvider lets the parser hold an incremental hash and
// reset it between commands without re-allocating.
type hashStateProvider interface {
	Reset()
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
}

// NewCommandParser builds a CommandParser bound to sessionID +
// sink. sessionID must be non-empty; sink must be non-nil. cfg is
// optional.
//
// A background worker goroutine drains queued commands into the
// sink one at a time so the AppendCommand order matches the order
// the operator typed them. The goroutine exits when Close is
// called.
func NewCommandParser(sessionID string, sink CommandSink, cfg CommandParserConfig) (*CommandParser, error) {
	if sessionID == "" {
		return nil, errors.New("gateway: NewCommandParser: empty session id")
	}
	if sink == nil {
		return nil, errors.New("gateway: NewCommandParser: nil sink")
	}
	if cfg.MaxInputBytes <= 0 {
		cfg.MaxInputBytes = defaultMaxInputBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p := &CommandParser{
		sessionID:  sessionID,
		sink:       sink,
		now:        cfg.Now,
		maxInput:   cfg.MaxInputBytes,
		outHash:    sha256.New(),
		queueCh:    make(chan AppendCommandInput, 256),
		workerDone: make(chan struct{}),
	}
	go p.worker()
	return p, nil
}

// worker drains queueCh into the sink. The sink is given a 5s
// timeout per call so a hung HTTP endpoint cannot pin shutdown.
//
// Worker lifecycle invariant: this goroutine is started exactly once
// by NewCommandParser and exits exactly once, when Close closes
// queueCh. Concurrent Close calls are serialised by the p.closed
// guard in Close; only the first invocation closes queueCh, so the
// worker is never sent on a closed channel and never exits early.
func (p *CommandParser) worker() {
	defer close(p.workerDone)
	for cmd := range p.queueCh {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := p.sink.AppendCommand(ctx, cmd); err != nil {
			log.Printf("gateway: append command session=%s seq=%d: %v", cmd.SessionID, cmd.Sequence, err)
		}
		cancel()
	}
}

// WriteInput feeds operator-typed bytes into the parser. Newlines
// close the current command; intermediate bytes accumulate in the
// input buffer. WriteInput consumes the entire slice — partial
// writes are not surfaced because tee writers always pass the full
// payload.
func (p *CommandParser) WriteInput(ctx context.Context, b []byte) {
	if p == nil || len(b) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	for _, c := range b {
		if c == '\n' || c == '\r' {
			// Flush the previous command's pending output (if any)
			// alongside the newly-closed input line. The newline
			// is dropped from the input field — the audit UI
			// adds it back when rendering.
			p.flushPendingLocked(ctx)
			p.startCommandLocked()
			continue
		}
		if p.inputBuf.Len() >= p.maxInput {
			continue
		}
		_ = p.inputBuf.WriteByte(c)
	}
}

// WriteOutput accumulates output bytes into the running hash for
// the current command. The full payload is NOT retained — only the
// SHA-256 digest, so a verbose `cat` does not pin the parser's
// memory.
func (p *CommandParser) WriteOutput(b []byte) {
	if p == nil || len(b) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.pending == nil && p.inputBuf.Len() == 0 {
		return
	}
	p.hasOutput = true
	_, _ = p.outHash.Write(b)
}

// startCommandLocked closes the in-progress input line into the
// pending command struct and resets the input buffer for the next
// line. The caller must hold p.mu.
func (p *CommandParser) startCommandLocked() {
	line := p.inputBuf.String()
	p.inputBuf.Reset()
	if line == "" {
		return
	}
	p.seq++
	cmd := &AppendCommandInput{
		SessionID: p.sessionID,
		Sequence:  p.seq,
		Input:     line,
		Timestamp: p.now().UTC(),
	}
	p.pending = cmd
	p.hasOutput = false
	p.outHash.Reset()
}

// flushPendingLocked finalises the most recently captured command
// and enqueues it on the worker channel. The caller must hold
// p.mu.
//
// Enqueue is best-effort: when the queue is saturated the command
// is dropped and logged so the SSH proxy's input flow never stalls
// on a backed-up sink. Order across the queue is preserved by the
// single-worker drain in worker().
func (p *CommandParser) flushPendingLocked(_ context.Context) {
	cmd := p.pending
	if cmd == nil {
		return
	}
	if p.hasOutput {
		cmd.OutputHash = hex.EncodeToString(p.outHash.Sum(nil))
	}
	p.pending = nil
	select {
	case p.queueCh <- *cmd:
	default:
		log.Printf("gateway: command queue full, dropping session=%s seq=%d", cmd.SessionID, cmd.Sequence)
	}
}

// SetRiskFlag tags the pending (most-recently captured) command
// with a free-text risk identifier. Used by the command-policy
// engine (Milestone 9) to mark commands that matched a deny or
// step-up rule.
func (p *CommandParser) SetRiskFlag(flag string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		return
	}
	f := flag
	p.pending.RiskFlag = &f
}

// Close flushes any pending command, signals the worker goroutine
// to exit, and waits for it to drain (bounded by ctx). Subsequent
// WriteInput / WriteOutput calls are no-ops so the SSH proxy
// shutdown path can defer Close safely.
func (p *CommandParser) Close(ctx context.Context) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	// If the operator typed a line but never sent a newline (e.g.
	// they exited via Ctrl-D), flush whatever we have. Otherwise
	// the last command would silently disappear from the audit
	// trail.
	if p.inputBuf.Len() > 0 {
		p.startCommandLocked()
	}
	p.flushPendingLocked(ctx)
	close(p.queueCh)
	p.mu.Unlock()
	// Wait for the worker to drain the channel — or for the
	// caller's ctx to fire, whichever comes first. Bounded so a
	// hung sink cannot pin the SSH proxy's shutdown.
	if ctx == nil {
		<-p.workerDone
		return
	}
	select {
	case <-p.workerDone:
	case <-ctx.Done():
	}
}

// Sequence returns the most-recently allocated command sequence
// number. Useful for tests and metrics.
func (p *CommandParser) Sequence() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seq
}

// MemoryCommandSink is the in-memory CommandSink used by tests. It
// records every AppendCommand call so assertions can inspect the
// captured rows.
type MemoryCommandSink struct {
	mu       sync.Mutex
	commands []AppendCommandInput
}

// NewMemoryCommandSink returns an empty sink.
func NewMemoryCommandSink() *MemoryCommandSink {
	return &MemoryCommandSink{}
}

// AppendCommand stores in for later inspection. Returns nil unless
// FailNext was set.
func (s *MemoryCommandSink) AppendCommand(_ context.Context, in AppendCommandInput) error {
	if s == nil {
		return errors.New("gateway: MemoryCommandSink is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, in)
	return nil
}

// Commands returns a copy of the recorded command rows.
func (s *MemoryCommandSink) Commands() []AppendCommandInput {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AppendCommandInput, len(s.commands))
	copy(out, s.commands)
	return out
}
