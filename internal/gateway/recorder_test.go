package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReplayKey_FormatsCanonical(t *testing.T) {
	t.Parallel()
	got := ReplayKey("01H8XYZ")
	want := "sessions/01H8XYZ/replay.bin"
	if got != want {
		t.Fatalf("ReplayKey = %q, want %q", got, want)
	}
}

func TestNewIORecorder_RejectsBadInput(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	if _, err := NewIORecorder("", store, IORecorderConfig{}); err == nil {
		t.Fatal("empty session id should error")
	}
	if _, err := NewIORecorder("sess-1", nil, IORecorderConfig{}); err == nil {
		t.Fatal("nil store should error")
	}
}

func TestIORecorder_FlushesFramedReplay(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	fixed := time.Unix(1700000000, 0).UTC()
	rec, err := NewIORecorder("sess-1", store, IORecorderConfig{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	rec.Record(DirectionInput, []byte("ls\n"))
	rec.Record(DirectionOutput, []byte("file1\nfile2\n"))
	rec.Record(DirectionStderr, []byte("warning\n"))

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	body, ok := store.Get("sess-1")
	if !ok {
		t.Fatal("replay not flushed")
	}
	frames, err := DecodeFrames(body)
	if err != nil {
		t.Fatalf("DecodeFrames: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("len(frames)=%d, want 3", len(frames))
	}
	if string(frames[0].Payload) != "ls\n" || frames[0].Direction != DirectionInput {
		t.Errorf("frame0 = %+v", frames[0])
	}
	if string(frames[1].Payload) != "file1\nfile2\n" || frames[1].Direction != DirectionOutput {
		t.Errorf("frame1 = %+v", frames[1])
	}
	if string(frames[2].Payload) != "warning\n" || frames[2].Direction != DirectionStderr {
		t.Errorf("frame2 = %+v", frames[2])
	}
	for i, f := range frames {
		if !f.Timestamp.Equal(fixed) {
			t.Errorf("frame %d ts=%v, want %v", i, f.Timestamp, fixed)
		}
	}
}

func TestIORecorder_TeeReaderMirrors(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	rec, err := NewIORecorder("sess-2", store, IORecorderConfig{})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	tee := rec.TeeReader(DirectionInput, src)
	out, err := io.ReadAll(tee)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(out) != "hello world" {
		t.Errorf("io.ReadAll(tee) = %q, want %q", out, "hello world")
	}
	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body, _ := store.Get("sess-2")
	frames, err := DecodeFrames(body)
	if err != nil {
		t.Fatalf("DecodeFrames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("no frames captured")
	}
	var combined strings.Builder
	for _, f := range frames {
		combined.Write(f.Payload)
	}
	if combined.String() != "hello world" {
		t.Errorf("combined frames = %q, want %q", combined.String(), "hello world")
	}
}

func TestIORecorder_TeeWriterMirrors(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	rec, err := NewIORecorder("sess-3", store, IORecorderConfig{})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	var dst bytes.Buffer
	tee := rec.TeeWriter(DirectionOutput, &dst)
	if _, err := tee.Write([]byte("uptime\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if dst.String() != "uptime\n" {
		t.Errorf("dst = %q, want %q", dst.String(), "uptime\n")
	}
	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body, _ := store.Get("sess-3")
	frames, _ := DecodeFrames(body)
	if len(frames) != 1 || string(frames[0].Payload) != "uptime\n" {
		t.Errorf("frames = %+v", frames)
	}
}

func TestIORecorder_RespectsMaxBytes(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	rec, err := NewIORecorder("sess-4", store, IORecorderConfig{MaxBytes: 32})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	// First record fits (13 header + 4 payload = 17), second
	// (17 + 17 = 34 > 32) is dropped.
	rec.Record(DirectionInput, []byte("aaaa"))
	rec.Record(DirectionInput, []byte("bbbb"))
	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body, _ := store.Get("sess-4")
	frames, _ := DecodeFrames(body)
	if len(frames) != 1 {
		t.Fatalf("len(frames)=%d, want 1 (overflow dropped)", len(frames))
	}
	if string(frames[0].Payload) != "aaaa" {
		t.Errorf("frame payload = %q", frames[0].Payload)
	}
}

func TestIORecorder_CloseIsIdempotent(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	rec, err := NewIORecorder("sess-5", store, IORecorderConfig{})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	rec.Record(DirectionInput, []byte("once"))
	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close #1: %v", err)
	}
	if err := rec.Close(context.Background()); err != nil {
		t.Errorf("Close #2 should be no-op, got %v", err)
	}
	// Recording after close is a no-op: no panics, no extra frames.
	rec.Record(DirectionInput, []byte("post-close"))
	body, _ := store.Get("sess-5")
	frames, _ := DecodeFrames(body)
	if len(frames) != 1 {
		t.Errorf("len(frames)=%d, want 1", len(frames))
	}
}

func TestIORecorder_ConcurrentRecordIsSafe(t *testing.T) {
	t.Parallel()
	store := NewMemoryReplayStore()
	rec, err := NewIORecorder("sess-6", store, IORecorderConfig{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	const goroutines = 16
	const writesPer = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < writesPer; i++ {
				rec.Record(DirectionInput, []byte("x"))
			}
		}()
	}
	wg.Wait()
	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body, _ := store.Get("sess-6")
	frames, _ := DecodeFrames(body)
	if len(frames) != goroutines*writesPer {
		t.Errorf("len(frames)=%d, want %d", len(frames), goroutines*writesPer)
	}
}

type errStore struct{}

func (errStore) PutReplay(context.Context, string, io.Reader) error {
	return errors.New("forced failure")
}

func TestIORecorder_Close_PropagatesPutError(t *testing.T) {
	t.Parallel()
	rec, err := NewIORecorder("sess-7", errStore{}, IORecorderConfig{})
	if err != nil {
		t.Fatalf("NewIORecorder: %v", err)
	}
	rec.Record(DirectionInput, []byte("bytes"))
	err = rec.Close(context.Background())
	if err == nil {
		t.Fatal("expected error from failing store")
	}
	if !strings.Contains(err.Error(), "flush recording") {
		t.Errorf("err=%v, want flush recording wrap", err)
	}
}

func TestDecodeFrames_TruncatedFails(t *testing.T) {
	t.Parallel()
	// 13-byte header but no payload.
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 0, byte(DirectionInput), 0, 0, 0, 5}
	_, err := DecodeFrames(hdr)
	if err == nil {
		t.Fatal("expected truncated-frame error")
	}
}
