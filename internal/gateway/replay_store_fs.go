package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FilesystemReplayStore is a ReplayStore that writes session
// recordings to a local directory tree mirroring the canonical
// ReplayKey path. It is the default store wired into the pam-gateway
// dev binary when no S3 endpoint is configured — production
// deployments install the S3-backed store from Milestone 7.
//
// The on-disk layout matches the storage key shape so the same
// session-id resolves the blob regardless of which backend the
// audit service queries:
//
//	{Root}/sessions/{session_id}/replay.bin
//
// All operations are best-effort: the recorder's Close path returns
// the underlying error so the caller can decide whether to drop the
// blob silently (recommended) or surface it to the operator.
type FilesystemReplayStore struct {
	root string
}

// NewFilesystemReplayStore returns a store rooted at root. root is
// created if it does not exist. An empty root is rejected so a
// misconfigured deployment cannot accidentally write into the
// process CWD.
func NewFilesystemReplayStore(root string) (*FilesystemReplayStore, error) {
	if root == "" {
		return nil, errors.New("gateway: NewFilesystemReplayStore: empty root")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("gateway: mkdir replay root %q: %w", root, err)
	}
	return &FilesystemReplayStore{root: root}, nil
}

// PutReplay writes the replay blob for sessionID under
// {Root}/sessions/{session_id}/replay.bin. The destination directory
// is created on demand so callers do not need to pre-provision it.
//
// The file is written atomically via a temp file + rename so a
// concurrent reader (the audit service's signed-URL flow) cannot
// observe a partial blob mid-upload.
func (f *FilesystemReplayStore) PutReplay(ctx context.Context, sessionID string, r io.Reader) error {
	if f == nil {
		return errors.New("gateway: FilesystemReplayStore is nil")
	}
	if sessionID == "" {
		return errors.New("gateway: PutReplay: empty session id")
	}
	if r == nil {
		return errors.New("gateway: PutReplay: nil reader")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dst := filepath.Join(f.root, ReplayKey(sessionID))
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("gateway: mkdir replay dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "replay-*.bin.partial")
	if err != nil {
		return fmt.Errorf("gateway: create temp replay file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if anything below this point fails. If
	// the rename succeeds the temp file no longer exists so Remove
	// is a harmless no-op.
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gateway: write replay body: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("gateway: close replay file: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("gateway: rename replay file: %w", err)
	}
	return nil
}

// Root returns the directory the store is rooted at — used by tests
// and the audit service to compute relative replay paths.
func (f *FilesystemReplayStore) Root() string {
	if f == nil {
		return ""
	}
	return f.root
}
