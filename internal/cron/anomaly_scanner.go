package cron

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// WorkspaceScanner is the narrow contract AnomalyScanner uses to
// dispatch a per-workspace anomaly scan. The production
// implementation is *access.AnomalyDetectionService.ScanWorkspace;
// tests substitute a stub that captures every workspaceID it sees.
type WorkspaceScanner interface {
	ScanWorkspace(ctx context.Context, workspaceID string) (*access.AnomalyScanResult, error)
}

// AnomalyScanner is the Phase 6 background worker that drives
// AnomalyDetectionService periodically. On each call to Run it
// enumerates the workspaces with at least one connected
// access_connector, dispatches ScanWorkspace per workspace, and logs
// the per-workspace observation / skip counters so operators can see
// whether the AI agent is degraded.
//
// AnomalyScanner is intentionally not a long-lived goroutine; it
// expects an external ticker (or test loop) to drive Run. This makes
// it trivial to unit-test with a synthetic clock and matches the
// pattern of CampaignScheduler.
//
// The scanner deliberately enumerates workspaces from
// access_connectors (rather than a workspaces table — there is no
// such table in this repo): a workspace with zero connectors has
// no entitlements to anomaly-check, so skipping them costs nothing.
type AnomalyScanner struct {
	db      *gorm.DB
	scanner WorkspaceScanner
	now     func() time.Time
}

// NewAnomalyScanner returns a scanner bound to db and scanner. db
// and scanner must both be non-nil; scanner is the
// AnomalyDetectionService that ScanWorkspace-s each workspace.
func NewAnomalyScanner(db *gorm.DB, scanner WorkspaceScanner) *AnomalyScanner {
	return &AnomalyScanner{
		db:      db,
		scanner: scanner,
		now:     time.Now,
	}
}

// SetClock overrides time.Now. Tests use this to pin log timestamps
// to a deterministic value.
func (s *AnomalyScanner) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// Run enumerates active workspaces and dispatches a per-workspace
// anomaly scan. The scanner is best-effort: a failure on one
// workspace does NOT abort the loop — the error is logged and
// surfaced in the returned err (the LAST seen error). Callers
// needing per-workspace errors should add a per-workspace hook.
//
// Run never blocks indefinitely; the only sleeping it does is
// inside ScanWorkspace which respects ctx.
func (s *AnomalyScanner) Run(ctx context.Context) error {
	if s == nil || s.db == nil || s.scanner == nil {
		return errors.New("cron: anomaly scanner is not fully wired")
	}

	workspaces, err := s.listWorkspaces(ctx)
	if err != nil {
		return fmt.Errorf("cron: list workspaces: %w", err)
	}
	if len(workspaces) == 0 {
		log.Printf("cron: anomaly_scanner: no workspaces with connectors; skipping")
		return nil
	}

	var lastErr error
	for _, ws := range workspaces {
		res, err := s.scanner.ScanWorkspace(ctx, ws)
		if err != nil {
			log.Printf("cron: anomaly_scanner: workspace=%s: %v", ws, err)
			lastErr = err
			continue
		}
		obs := 0
		skipped := 0
		grants := 0
		if res != nil {
			obs = len(res.Observations)
			skipped = res.Skipped
			grants = res.GrantsScanned
		}
		log.Printf("cron: anomaly_scanner: workspace=%s grants_scanned=%d observations=%d skipped=%d", ws, grants, obs, skipped)
	}
	return lastErr
}

// listWorkspaces returns the distinct workspace IDs that have at
// least one access_connector row. Soft-deleted connectors are
// skipped via the default GORM scope. Workspaces with zero
// connectors are excluded — they have no entitlements to scan.
func (s *AnomalyScanner) listWorkspaces(ctx context.Context) ([]string, error) {
	var ids []string
	if err := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Distinct("workspace_id").
		Pluck("workspace_id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}
