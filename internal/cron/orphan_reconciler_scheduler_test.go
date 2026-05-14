package cron

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubOrphanReconciler implements WorkspaceOrphanReconciler for
// scheduler tests.
type stubOrphanReconciler struct {
	mu       sync.Mutex
	calls    atomic.Int64
	calledWS []string
	out      map[string][]models.AccessOrphanAccount
	err      map[string]error
}

func (s *stubOrphanReconciler) ReconcileWorkspace(_ context.Context, workspaceID string) ([]models.AccessOrphanAccount, error) {
	s.calls.Add(1)
	s.mu.Lock()
	s.calledWS = append(s.calledWS, workspaceID)
	s.mu.Unlock()
	if s.err != nil {
		if e, ok := s.err[workspaceID]; ok {
			return nil, e
		}
	}
	if s.out != nil {
		if rows, ok := s.out[workspaceID]; ok {
			return rows, nil
		}
	}
	return nil, nil
}

type stubOrphanNotifier struct {
	mu      sync.Mutex
	calls   atomic.Int64
	gotWS   []string
	gotRows int
}

func (n *stubOrphanNotifier) NotifyOrphansDetected(_ context.Context, workspaceID string, rows []models.AccessOrphanAccount) error {
	n.calls.Add(1)
	n.mu.Lock()
	n.gotWS = append(n.gotWS, workspaceID)
	n.gotRows += len(rows)
	n.mu.Unlock()
	return nil
}

func newReconcilerSchedDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedConnectorForWS(t *testing.T, db *gorm.DB, id, workspaceID, provider string) {
	t.Helper()
	if err := db.Create(&models.AccessConnector{
		ID:            id,
		WorkspaceID:   workspaceID,
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
}

// TestOrphanReconcilerScheduler_RunsPerWorkspace asserts the
// scheduler invokes the reconciler exactly once per distinct
// workspace_id in access_connectors.
func TestOrphanReconcilerScheduler_RunsPerWorkspace(t *testing.T) {
	db := newReconcilerSchedDB(t)
	seedConnectorForWS(t, db, "01HCONN0ORPHANSCHED000001", "ws-a", "okta")
	seedConnectorForWS(t, db, "01HCONN0ORPHANSCHED000002", "ws-a", "google_workspace")
	seedConnectorForWS(t, db, "01HCONN0ORPHANSCHED000003", "ws-b", "microsoft")

	rec := &stubOrphanReconciler{}
	sched := NewOrphanReconcilerScheduler(db, rec)
	if err := sched.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rec.calls.Load(); got != 2 {
		t.Errorf("ReconcileWorkspace calls = %d; want 2 (ws-a and ws-b)", got)
	}
}

// TestOrphanReconcilerScheduler_FiresNotifierForNewOrphans asserts
// the notification hook is called exactly when new orphans are
// detected and skipped otherwise.
func TestOrphanReconcilerScheduler_FiresNotifierForNewOrphans(t *testing.T) {
	db := newReconcilerSchedDB(t)
	seedConnectorForWS(t, db, "01HCONN0ORPHANNOTIFY00001", "ws-orphan", "okta")
	seedConnectorForWS(t, db, "01HCONN0ORPHANNOTIFY00002", "ws-clean", "google_workspace")

	rec := &stubOrphanReconciler{
		out: map[string][]models.AccessOrphanAccount{
			"ws-orphan": {{ID: "o1", WorkspaceID: "ws-orphan"}, {ID: "o2", WorkspaceID: "ws-orphan"}},
		},
	}
	notifier := &stubOrphanNotifier{}
	sched := NewOrphanReconcilerScheduler(db, rec)
	sched.SetNotifier(notifier)
	if err := sched.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := notifier.calls.Load(); got != 1 {
		t.Errorf("notifier calls = %d; want 1 (only ws-orphan had detections)", got)
	}
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if notifier.gotRows != 2 {
		t.Errorf("notifier saw %d rows; want 2", notifier.gotRows)
	}
}

// TestOrphanReconcilerScheduler_EmitsStructuredStats asserts the
// scheduler emits one JSON orphan_reconcile_summary log line per
// workspace with the expected fields populated.
func TestOrphanReconcilerScheduler_EmitsStructuredStats(t *testing.T) {
	db := newReconcilerSchedDB(t)
	seedConnectorForWS(t, db, "01HCONN0ORPHANSTATS00001", "ws-stats", "okta")
	seedConnectorForWS(t, db, "01HCONN0ORPHANSTATS00002", "ws-stats", "google_workspace")

	rec := &stubOrphanReconciler{
		out: map[string][]models.AccessOrphanAccount{
			"ws-stats": {{ID: "o1", WorkspaceID: "ws-stats"}, {ID: "o2", WorkspaceID: "ws-stats"}, {ID: "o3", WorkspaceID: "ws-stats"}},
		},
	}
	sched := NewOrphanReconcilerScheduler(db, rec)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	if err := sched.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, `"event":"orphan_reconcile_summary"`) {
		t.Fatalf("log output missing orphan_reconcile_summary envelope:\n%s", logged)
	}

	// Decode the first orphan_reconcile_summary line.
	var found bool
	for _, line := range strings.Split(logged, "\n") {
		idx := strings.Index(line, "{")
		if idx < 0 {
			continue
		}
		payload := line[idx:]
		var entry struct {
			Event             string `json:"event"`
			WorkspaceID       string `json:"workspace_id"`
			OrphansDetected   int    `json:"orphans_detected"`
			OrphansNew        int    `json:"orphans_new"`
			ConnectorsScanned int    `json:"connectors_scanned"`
		}
		if err := json.Unmarshal([]byte(payload), &entry); err != nil {
			continue
		}
		if entry.Event != "orphan_reconcile_summary" {
			continue
		}
		found = true
		if entry.WorkspaceID != "ws-stats" {
			t.Errorf("workspace_id = %q; want ws-stats", entry.WorkspaceID)
		}
		if entry.OrphansDetected != 3 {
			t.Errorf("orphans_detected = %d; want 3", entry.OrphansDetected)
		}
		if entry.OrphansNew != 3 {
			t.Errorf("orphans_new = %d; want 3", entry.OrphansNew)
		}
		if entry.ConnectorsScanned != 2 {
			t.Errorf("connectors_scanned = %d; want 2", entry.ConnectorsScanned)
		}
	}
	if !found {
		t.Errorf("did not find any decodable orphan_reconcile_summary entries in:\n%s", logged)
	}
}

// TestOrphanReconcilerScheduler_PerWorkspaceErrorIsLogged asserts
// a single workspace failure does not abort the rest of the run.
func TestOrphanReconcilerScheduler_PerWorkspaceErrorIsLogged(t *testing.T) {
	db := newReconcilerSchedDB(t)
	seedConnectorForWS(t, db, "01HCONN0ORPHANERR0000001", "ws-bad", "okta")
	seedConnectorForWS(t, db, "01HCONN0ORPHANERR0000002", "ws-good", "google_workspace")

	rec := &stubOrphanReconciler{
		err: map[string]error{"ws-bad": errors.New("boom")},
	}
	sched := NewOrphanReconcilerScheduler(db, rec)
	if err := sched.Run(context.Background()); err == nil {
		t.Error("Run returned nil; want last-error propagated")
	}
	if got := rec.calls.Load(); got != 2 {
		t.Errorf("ReconcileWorkspace calls = %d; want 2", got)
	}
}
