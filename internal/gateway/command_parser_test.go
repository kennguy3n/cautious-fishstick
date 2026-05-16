package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

func sha256Hex(in string) string {
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:])
}

func TestNewCommandParser_RejectsBadInput(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	if _, err := NewCommandParser("", sink, CommandParserConfig{}); err == nil {
		t.Fatal("empty session id should error")
	}
	if _, err := NewCommandParser("sess", nil, CommandParserConfig{}); err == nil {
		t.Fatal("nil sink should error")
	}
}

func waitForCommands(t *testing.T, sink *MemoryCommandSink, n int) []AppendCommandInput {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cmds := sink.Commands()
		if len(cmds) >= n {
			return cmds
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %d commands, got %d: %+v", n, len(cmds), cmds)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCommandParser_CapturesNewlineDelimitedCommands(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	fixed := time.Unix(1700000000, 0).UTC()
	parser, err := NewCommandParser("sess-a", sink, CommandParserConfig{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()

	parser.WriteInput(ctx, []byte("ls\n"))
	parser.WriteOutput([]byte("file1\nfile2\n"))
	parser.WriteInput(ctx, []byte("pwd\n"))
	parser.WriteOutput([]byte("/tmp\n"))
	parser.Close(ctx)

	cmds := waitForCommands(t, sink, 2)
	if len(cmds) != 2 {
		t.Fatalf("len(cmds)=%d, want 2", len(cmds))
	}
	if cmds[0].SessionID != "sess-a" || cmds[0].Sequence != 1 || cmds[0].Input != "ls" {
		t.Errorf("cmds[0] = %+v", cmds[0])
	}
	if cmds[0].OutputHash != sha256Hex("file1\nfile2\n") {
		t.Errorf("cmds[0].OutputHash = %q, want %q", cmds[0].OutputHash, sha256Hex("file1\nfile2\n"))
	}
	if !cmds[0].Timestamp.Equal(fixed) {
		t.Errorf("cmds[0].Timestamp = %v, want %v", cmds[0].Timestamp, fixed)
	}
	if cmds[1].Sequence != 2 || cmds[1].Input != "pwd" {
		t.Errorf("cmds[1] = %+v", cmds[1])
	}
	if cmds[1].OutputHash != sha256Hex("/tmp\n") {
		t.Errorf("cmds[1].OutputHash = %q", cmds[1].OutputHash)
	}
}

func TestCommandParser_HandlesByteAtATimeInput(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-b", sink, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	for _, c := range []byte("echo hi\n") {
		parser.WriteInput(ctx, []byte{c})
	}
	parser.Close(ctx)
	cmds := waitForCommands(t, sink, 1)
	if cmds[0].Input != "echo hi" {
		t.Errorf("input=%q, want echo hi", cmds[0].Input)
	}
}

func TestCommandParser_EmptyInputBetweenNewlines(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-c", sink, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	// Three carriage returns with nothing typed in between — must
	// not generate any commands (they would be empty Input).
	parser.WriteInput(ctx, []byte("\r\n\n"))
	parser.Close(ctx)
	// Give the goroutine a moment to fire if it would have.
	time.Sleep(50 * time.Millisecond)
	cmds := sink.Commands()
	if len(cmds) != 0 {
		t.Errorf("len(cmds)=%d, want 0: %+v", len(cmds), cmds)
	}
}

func TestCommandParser_CloseFlushesUnterminatedLine(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-d", sink, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	parser.WriteInput(ctx, []byte("exit"))
	parser.Close(ctx)
	cmds := waitForCommands(t, sink, 1)
	if cmds[0].Input != "exit" {
		t.Errorf("input=%q, want exit", cmds[0].Input)
	}
}

func TestCommandParser_SetRiskFlagTagsPending(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-e", sink, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	// Newline terminates the input line and promotes it to the
	// pending command; the policy engine can then tag it before
	// Close flushes the row.
	parser.WriteInput(ctx, []byte("rm -rf /\n"))
	parser.SetRiskFlag("policy:deny")
	parser.Close(ctx)
	cmds := waitForCommands(t, sink, 1)
	if cmds[0].RiskFlag == nil || *cmds[0].RiskFlag != "policy:deny" {
		t.Errorf("RiskFlag=%v, want policy:deny", cmds[0].RiskFlag)
	}
}

func TestCommandParser_BoundsInputLineLength(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-f", sink, CommandParserConfig{MaxInputBytes: 8})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	parser.WriteInput(ctx, []byte("0123456789ABCDEF\n"))
	parser.Close(ctx)
	cmds := waitForCommands(t, sink, 1)
	if cmds[0].Input != "01234567" {
		t.Errorf("input=%q, want 01234567 (truncated)", cmds[0].Input)
	}
}

func TestCommandParser_PostCloseWritesAreNoOp(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-g", sink, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	parser.WriteInput(ctx, []byte("first\n"))
	parser.Close(ctx)
	parser.WriteInput(ctx, []byte("post-close\n"))
	parser.WriteOutput([]byte("ignored"))
	time.Sleep(20 * time.Millisecond)
	cmds := sink.Commands()
	if len(cmds) != 1 {
		t.Errorf("len(cmds)=%d, want 1 (post-close ignored)", len(cmds))
	}
}

func TestCommandParser_ConcurrentWritesAreSafe(t *testing.T) {
	t.Parallel()
	sink := NewMemoryCommandSink()
	parser, err := NewCommandParser("sess-h", sink, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	const lines = 20
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < lines; i++ {
			parser.WriteInput(ctx, []byte("ping\n"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < lines*4; i++ {
			parser.WriteOutput([]byte("pong"))
		}
	}()
	wg.Wait()
	parser.Close(ctx)
	cmds := waitForCommands(t, sink, lines)
	for i, c := range cmds {
		if c.Input != "ping" {
			t.Errorf("cmd %d input=%q", i, c.Input)
		}
		if c.Sequence != i+1 {
			t.Errorf("cmd %d seq=%d, want %d", i, c.Sequence, i+1)
		}
	}
}

type errSink struct{}

func (errSink) AppendCommand(context.Context, AppendCommandInput) error {
	return errors.New("forced")
}

func TestCommandParser_SinkErrorsAreLoggedNotPanicked(t *testing.T) {
	t.Parallel()
	parser, err := NewCommandParser("sess-i", errSink{}, CommandParserConfig{})
	if err != nil {
		t.Fatalf("NewCommandParser: %v", err)
	}
	ctx := context.Background()
	parser.WriteInput(ctx, []byte("hello\n"))
	parser.Close(ctx)
	// We just want the parser to survive a sink error. The
	// goroutine logs the failure but does not panic.
	time.Sleep(20 * time.Millisecond)
	if parser.Sequence() != 1 {
		t.Errorf("Sequence=%d, want 1", parser.Sequence())
	}
}
