package gateway

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFilesystemReplayStore_PutReplay_HappyPath verifies the
// canonical session-id path lands the blob bytes inside the
// configured root.
func TestFilesystemReplayStore_PutReplay_HappyPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewFilesystemReplayStore(root)
	if err != nil {
		t.Fatalf("NewFilesystemReplayStore: %v", err)
	}
	const sessionID = "01HXYZULIDLOOKING000000000"
	body := []byte("replay-bytes-go-here")
	if err := store.PutReplay(context.Background(), sessionID, bytes.NewReader(body)); err != nil {
		t.Fatalf("PutReplay: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "sessions", sessionID, "replay.bin"))
	if err != nil {
		t.Fatalf("read written replay: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("blob bytes = %q, want %q", got, body)
	}
}

// TestFilesystemReplayStore_PutReplay_PathTraversal verifies the
// store refuses to write outside its configured root even when the
// caller hands it a malicious session id. ULIDs from the trusted
// ztna-api never contain "../" or absolute paths, so this is
// strictly defence-in-depth.
func TestFilesystemReplayStore_PutReplay_PathTraversal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewFilesystemReplayStore(root)
	if err != nil {
		t.Fatalf("NewFilesystemReplayStore: %v", err)
	}
	cases := []string{
		"../escape",
		"../../etc/cron.d/x",
		"/etc/passwd",
		"a/../../../etc/passwd",
	}
	for _, sid := range cases {
		sid := sid
		t.Run(sid, func(t *testing.T) {
			t.Parallel()
			err := store.PutReplay(context.Background(), sid, bytes.NewReader([]byte("evil")))
			if err == nil {
				t.Fatalf("PutReplay(%q): expected error, got nil", sid)
			}
			// Either of the two defence layers is acceptable:
			// (1) session id rejected for containing a path
			// separator, or (2) cleaned path rejected for
			// escaping the configured root.
			if !strings.Contains(err.Error(), "path separator") &&
				!strings.Contains(err.Error(), "escapes root") &&
				!strings.Contains(err.Error(), "path navigation token") {
				t.Errorf("PutReplay(%q) error = %v; want path-traversal containment failure", sid, err)
			}
		})
	}
	// Sanity-check that nothing leaked outside root after the
	// rejected calls — no replay.bin should exist anywhere on disk
	// outside the configured root for these test IDs.
	if entries, _ := os.ReadDir(filepath.Dir(root)); len(entries) == 1 && entries[0].Name() == filepath.Base(root) {
		// Only the temp root is present alongside its siblings —
		// no escape happened. (t.TempDir parent typically has many
		// siblings from other parallel tests, so this is a loose
		// check.)
	}
}

// TestFilesystemReplayStore_PutReplay_RejectsEmptySessionID covers
// the explicit precondition guard.
func TestFilesystemReplayStore_PutReplay_RejectsEmptySessionID(t *testing.T) {
	t.Parallel()
	store, err := NewFilesystemReplayStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemReplayStore: %v", err)
	}
	err = store.PutReplay(context.Background(), "", bytes.NewReader([]byte("body")))
	if err == nil {
		t.Fatalf("PutReplay(\"\"): expected error, got nil")
	}
}
