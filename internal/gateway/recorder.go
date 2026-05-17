package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ReplayStore is the minimal contract IORecorder uses to flush
// session I/O blobs to durable storage. The production implementation
// is S3-compatible (NewS3ReplayStore) but tests substitute
// MemoryReplayStore so the SSH/K8s/DB listener suites can run without
// a live S3 endpoint.
//
// Key shape: callers MUST use the canonical
// "sessions/{session_id}/replay.bin" key so PAMAuditService can later
// issue a pre-signed GET (see internal/services/pam/audit_service.go).
// ReplayKey is the only helper that builds the key — never construct
// it by hand at the call site.
type ReplayStore interface {
	// PutReplay uploads the buffered replay bytes for sessionID
	// to the underlying store. r is the full replay payload; the
	// implementation is free to read it in one shot (the recorder
	// buffers in memory before flushing).
	PutReplay(ctx context.Context, sessionID string, r io.Reader) error
}

// ReplayKey returns the canonical storage key for a session's replay
// blob. Centralising the format prevents drift between the recorder
// (writes) and PAMAuditService (issues signed GETs).
func ReplayKey(sessionID string) string {
	return "sessions/" + sessionID + "/replay.bin"
}

// MemoryReplayStore is the in-memory ReplayStore used by tests.
// Bytes uploaded via PutReplay are accessible through Get; the
// store is safe for concurrent use.
type MemoryReplayStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemoryReplayStore returns an empty in-memory replay store.
func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{objects: map[string][]byte{}}
}

// PutReplay buffers r in memory under the canonical replay key for
// sessionID. Calling PutReplay twice for the same sessionID
// overwrites the previous blob — matching the S3 semantics callers
// observe in production.
func (m *MemoryReplayStore) PutReplay(_ context.Context, sessionID string, r io.Reader) error {
	if m == nil {
		return errors.New("gateway: MemoryReplayStore is nil")
	}
	if sessionID == "" {
		return errors.New("gateway: PutReplay: empty session id")
	}
	if r == nil {
		return errors.New("gateway: PutReplay: nil reader")
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("gateway: read replay body: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[ReplayKey(sessionID)] = body
	return nil
}

// Get returns the bytes previously uploaded for sessionID along with
// a found bool. Tests use this to assert on the recorded replay.
func (m *MemoryReplayStore) Get(sessionID string) ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[ReplayKey(sessionID)]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, true
}

// Keys returns every storage key seen by the store. Useful for
// tests that assert on the exact key shape.
func (m *MemoryReplayStore) Keys() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		out = append(out, k)
	}
	return out
}

// RecordDirection labels which side of the proxy produced the bytes
// written to the recorder. The direction is embedded as a header
// byte at the start of every frame so the replay can be deserialised
// frame-by-frame in the operator console (a trivial parser walks the
// blob and decodes frame headers).
type RecordDirection byte

const (
	// DirectionInput marks bytes typed by the operator and sent to
	// the upstream target (stdin).
	DirectionInput RecordDirection = 'I'

	// DirectionOutput marks bytes produced by the target and sent
	// back to the operator (stdout).
	DirectionOutput RecordDirection = 'O'

	// DirectionStderr marks bytes produced by the target on stderr.
	DirectionStderr RecordDirection = 'E'
)

// IORecorder buffers bidirectional session bytes in memory and
// flushes them to ReplayStore on Close. Writes are framed:
//
//	[8 bytes: unix microsecond timestamp BE]
//	[1 byte:  RecordDirection]
//	[4 bytes: payload length BE]
//	[N bytes: payload]
//
// The frame format is intentionally fixed-width and self-describing
// so the operator console (Milestone 7+) can stream-decode the blob
// without consulting a separate index.
//
// IORecorder is safe for concurrent use — the SSH listener's stdin /
// stdout / stderr tee goroutines all share the same recorder
// instance.
type IORecorder struct {
	sessionID string
	store     ReplayStore
	maxBytes  int

	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
	now    func() time.Time
}

// IORecorderConfig captures the optional knobs for NewIORecorder.
// Tests pin Now so the framed timestamps are deterministic.
type IORecorderConfig struct {
	// MaxBytes bounds the in-memory buffer. Once exceeded, further
	// frames are silently dropped (the session is still proxied,
	// only the recording stops growing). Default 64 MiB.
	MaxBytes int

	// Now overrides time.Now for testability. nil → time.Now.
	Now func() time.Time
}

// defaultRecorderMaxBytes caps a single session recording at 64 MiB
// so a runaway shell cannot pin the gateway's heap.
const defaultRecorderMaxBytes = 64 * 1024 * 1024

// NewIORecorder builds a recorder bound to sessionID + store.
// sessionID must be non-empty; store must be non-nil. cfg is
// optional — pass IORecorderConfig{} for production defaults.
func NewIORecorder(sessionID string, store ReplayStore, cfg IORecorderConfig) (*IORecorder, error) {
	if sessionID == "" {
		return nil, errors.New("gateway: NewIORecorder: empty session id")
	}
	if store == nil {
		return nil, errors.New("gateway: NewIORecorder: nil store")
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultRecorderMaxBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &IORecorder{
		sessionID: sessionID,
		store:     store,
		maxBytes:  cfg.MaxBytes,
		now:       cfg.Now,
	}, nil
}

// SessionID returns the recorder's session identifier. Used by
// CommandParser to stamp command rows.
func (r *IORecorder) SessionID() string {
	if r == nil {
		return ""
	}
	return r.sessionID
}

// Record appends a framed payload to the in-memory buffer. The
// frame format is described in the IORecorder doc comment.
//
// Record is a no-op when the recorder is closed or when adding the
// frame would exceed MaxBytes — the SSH proxy keeps running, only
// the recording stops growing.
func (r *IORecorder) Record(dir RecordDirection, payload []byte) {
	if r == nil || len(payload) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	frameSize := 8 + 1 + 4 + len(payload)
	if r.buf.Len()+frameSize > r.maxBytes {
		return
	}
	ts := uint64(r.now().UnixMicro())
	var header [13]byte
	header[0] = byte(ts >> 56)
	header[1] = byte(ts >> 48)
	header[2] = byte(ts >> 40)
	header[3] = byte(ts >> 32)
	header[4] = byte(ts >> 24)
	header[5] = byte(ts >> 16)
	header[6] = byte(ts >> 8)
	header[7] = byte(ts)
	header[8] = byte(dir)
	n := uint32(len(payload))
	header[9] = byte(n >> 24)
	header[10] = byte(n >> 16)
	header[11] = byte(n >> 8)
	header[12] = byte(n)
	_, _ = r.buf.Write(header[:])
	_, _ = r.buf.Write(payload)
}

// TeeReader returns an io.Reader that reads from src and mirrors
// every read into the recorder under direction dir. The returned
// reader is intended to slot into io.Copy: e.g.
//
//	io.Copy(stdin, recorder.TeeReader(DirectionInput, ch))
//
// so every byte streaming from the operator's client to the
// upstream target is also captured.
//
// The recorder never returns an error from Record itself, so the
// io.Copy pipeline behaves exactly like the unwrapped version.
func (r *IORecorder) TeeReader(dir RecordDirection, src io.Reader) io.Reader {
	return &teeReader{r: r, src: src, dir: dir}
}

type teeReader struct {
	r   *IORecorder
	src io.Reader
	dir RecordDirection
}

func (t *teeReader) Read(p []byte) (int, error) {
	if t == nil || t.src == nil {
		return 0, io.EOF
	}
	n, err := t.src.Read(p)
	if n > 0 {
		t.r.Record(t.dir, append([]byte(nil), p[:n]...))
	}
	return n, err
}

// TeeWriter returns an io.Writer that writes to dst and mirrors
// every write into the recorder under direction dir. Pair with
// TeeReader so the stdout / stderr direction can be captured too:
//
//	io.Copy(recorder.TeeWriter(DirectionOutput, ch), stdout)
//
// will mirror every byte coming back from the target into the
// recording.
func (r *IORecorder) TeeWriter(dir RecordDirection, dst io.Writer) io.Writer {
	return &teeWriter{r: r, dst: dst, dir: dir}
}

type teeWriter struct {
	r   *IORecorder
	dst io.Writer
	dir RecordDirection
}

func (t *teeWriter) Write(p []byte) (int, error) {
	if t == nil || t.dst == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := t.dst.Write(p)
	if n > 0 {
		t.r.Record(t.dir, append([]byte(nil), p[:n]...))
	}
	return n, err
}

// Close flushes the in-memory buffer to the ReplayStore under the
// canonical replay key and marks the recorder closed. After Close,
// further Record / Read / Write calls are no-ops so the SSH proxy
// shutdown path is safe to call Close exactly once via defer.
//
// Calling Close twice is a no-op (the second call returns nil) so
// the deferred shutdown path can be defensive.
func (r *IORecorder) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	payload := r.buf.Bytes()
	body := make([]byte, len(payload))
	copy(body, payload)
	r.buf.Reset()
	r.mu.Unlock()
	if len(body) == 0 {
		return nil
	}
	if err := r.store.PutReplay(ctx, r.sessionID, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("gateway: flush recording: %w", err)
	}
	return nil
}

// Bytes returns a copy of the buffered (not-yet-flushed) recording.
// Useful for tests; production callers should call Close to flush
// to the ReplayStore. The returned slice is a copy — the caller is
// free to mutate it without affecting the recorder.
func (r *IORecorder) Bytes() []byte {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, r.buf.Len())
	copy(out, r.buf.Bytes())
	return out
}

// Frame is the decoded form of a single recorder frame. Tests and
// the replay-viewer use DecodeFrames to walk a replay blob without
// re-implementing the framing logic.
type Frame struct {
	Timestamp time.Time
	Direction RecordDirection
	Payload   []byte
}

// DecodeFrames walks blob and returns the sequence of Frames it
// contains. Returns the frames decoded so far plus an error if blob
// is truncated or contains an over-long payload length.
func DecodeFrames(blob []byte) ([]Frame, error) {
	var out []Frame
	for len(blob) > 0 {
		if len(blob) < 13 {
			return out, fmt.Errorf("gateway: truncated frame header (%d bytes remaining)", len(blob))
		}
		ts := uint64(blob[0])<<56 | uint64(blob[1])<<48 | uint64(blob[2])<<40 | uint64(blob[3])<<32 |
			uint64(blob[4])<<24 | uint64(blob[5])<<16 | uint64(blob[6])<<8 | uint64(blob[7])
		dir := RecordDirection(blob[8])
		n := uint32(blob[9])<<24 | uint32(blob[10])<<16 | uint32(blob[11])<<8 | uint32(blob[12])
		blob = blob[13:]
		if uint32(len(blob)) < n {
			return out, fmt.Errorf("gateway: truncated frame payload (%d/%d bytes)", len(blob), n)
		}
		payload := make([]byte, n)
		copy(payload, blob[:n])
		blob = blob[n:]
		out = append(out, Frame{
			//nolint:gosec // ts originates from time.UnixMicro and is safely in int64 range.
			Timestamp: time.UnixMicro(int64(ts)).UTC(),
			Direction: dir,
			Payload:   payload,
		})
	}
	return out, nil
}
