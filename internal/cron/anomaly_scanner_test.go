package cron

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubWorkspaceScanner is a tiny WorkspaceScanner test double that
// records every workspaceID it sees and replays a per-call (result,
// error) script. err defaults to nil; res defaults to an empty
// AnomalyScanResult.
type stubWorkspaceScanner struct {
	mu    sync.Mutex
	calls []string
	err   error
	res   *access.AnomalyScanResult
}

func (s *stubWorkspaceScanner) ScanWorkspace(_ context.Context, workspaceID string) (*access.AnomalyScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, workspaceID)
	if s.err != nil {
		return nil, s.err
	}
	if s.res != nil {
		return s.res, nil
	}
	return &access.AnomalyScanResult{}, nil
}

func newAnomalyDB(t *testing.T) *gorm.DB {
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

func seedConnector(t *testing.T, db *gorm.DB, id, workspaceID, provider string) {
	t.Helper()
	row := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   workspaceID,
		Provider:      provider,
		ConnectorType: "test",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
}

// TestAnomalyScanner_Run_DispatchesPerWorkspace asserts that Run
// enumerates the distinct workspace IDs from access_connectors and
// dispatches one ScanWorkspace call per workspace.
func TestAnomalyScanner_Run_DispatchesPerWorkspace(t *testing.T) {
	db := newAnomalyDB(t)
	seedConnector(t, db, "01HCONNECTOR000000000000A1", "01HWORKSPACE0000000000000A", "okta")
	seedConnector(t, db, "01HCONNECTOR000000000000A2", "01HWORKSPACE0000000000000A", "github") // same workspace
	seedConnector(t, db, "01HCONNECTOR000000000000B1", "01HWORKSPACE0000000000000B", "github")

	scanner := &stubWorkspaceScanner{}
	s := NewAnomalyScanner(db, scanner)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(scanner.calls) != 2 {
		t.Fatalf("ScanWorkspace calls = %d; want 2 (distinct workspaces)", len(scanner.calls))
	}
	got := map[string]bool{}
	for _, w := range scanner.calls {
		got[w] = true
	}
	if !got["01HWORKSPACE0000000000000A"] || !got["01HWORKSPACE0000000000000B"] {
		t.Errorf("calls = %v; want both workspaces", scanner.calls)
	}
}

// TestAnomalyScanner_Run_ScanErrorContinuesLoop asserts that an
// error scanning workspace A does NOT abort the loop; workspace B
// must still be scanned. The error is surfaced via Run's return
// value.
func TestAnomalyScanner_Run_ScanErrorContinuesLoop(t *testing.T) {
	db := newAnomalyDB(t)
	seedConnector(t, db, "01HCONNECTOR000000000000A1", "01HWORKSPACE0000000000000A", "okta")
	seedConnector(t, db, "01HCONNECTOR000000000000B1", "01HWORKSPACE0000000000000B", "github")

	scanner := &stubWorkspaceScanner{err: errors.New("boom")}
	s := NewAnomalyScanner(db, scanner)
	err := s.Run(context.Background())
	if err == nil {
		t.Fatal("Run returned nil; want last-seen error")
	}
	if len(scanner.calls) != 2 {
		t.Errorf("ScanWorkspace calls = %d; want 2 (loop must continue past error)", len(scanner.calls))
	}
}

// TestAnomalyScanner_Run_NoWorkspacesIsNoop asserts that Run with
// zero connectors logs and returns nil — no error, no call.
func TestAnomalyScanner_Run_NoWorkspacesIsNoop(t *testing.T) {
	db := newAnomalyDB(t)
	scanner := &stubWorkspaceScanner{}
	s := NewAnomalyScanner(db, scanner)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(scanner.calls) != 0 {
		t.Errorf("ScanWorkspace calls = %d; want 0", len(scanner.calls))
	}
}

// TestAnomalyScanner_Run_MissingDependenciesError asserts the
// scanner refuses to run with a nil db or nil scanner. This is the
// error a cmd/* misconfiguration would surface.
func TestAnomalyScanner_Run_MissingDependenciesError(t *testing.T) {
	if err := (&AnomalyScanner{}).Run(context.Background()); err == nil {
		t.Error("Run with nil db+scanner returned nil; want error")
	}
}

// TestAnomalyScanner_SoftDeletedConnectorsAreSkipped asserts that a
// soft-deleted connector does NOT keep its workspace alive — the
// workspace is dropped from the scan loop once all its connectors
// are deleted. This guards against scanning workspaces that no
// longer have any access surface.
func TestAnomalyScanner_SoftDeletedConnectorsAreSkipped(t *testing.T) {
	db := newAnomalyDB(t)
	seedConnector(t, db, "01HCONNECTOR000000000000A1", "01HWORKSPACE0000000000000A", "okta")
	seedConnector(t, db, "01HCONNECTOR000000000000B1", "01HWORKSPACE0000000000000B", "github")

	if err := db.Delete(&models.AccessConnector{}, "id = ?", "01HCONNECTOR000000000000B1").Error; err != nil {
		t.Fatalf("soft-delete: %v", err)
	}

	scanner := &stubWorkspaceScanner{}
	s := NewAnomalyScanner(db, scanner)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(scanner.calls) != 1 || scanner.calls[0] != "01HWORKSPACE0000000000000A" {
		t.Errorf("calls = %v; want only [01HWORKSPACE0000000000000A]", scanner.calls)
	}
}
