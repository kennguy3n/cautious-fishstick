package cron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// WorkspaceOrphanReconciler is the narrow contract the scheduler
// uses to reconcile orphan accounts in a single workspace. The
// production implementation is *access.OrphanReconciler; tests
// substitute a stub.
type WorkspaceOrphanReconciler interface {
	ReconcileWorkspace(ctx context.Context, workspaceID string) ([]models.AccessOrphanAccount, error)
}

// orphanReconcileLog is the JSON-structured log envelope emitted at
// the end of every per-workspace pass. Operators ingest this into
// their log aggregator (e.g. Datadog, Splunk) to track reconciler
// throughput and failure rates without re-parsing free-form lines.
type orphanReconcileLog struct {
	Event             string `json:"event"`
	WorkspaceID       string `json:"workspace_id"`
	OrphansDetected   int    `json:"orphans_detected"`
	OrphansNew        int    `json:"orphans_new"`
	ConnectorsScanned int    `json:"connectors_scanned"`
	ConnectorsFailed  int    `json:"connectors_failed"`
	DurationMS        int64  `json:"duration_ms"`
	Error             string `json:"error,omitempty"`
}

// reconcilerStatsReader is the optional contract a reconciler can
// implement to expose per-workspace scan stats (connectors scanned
// / failed). The production *access.OrphanReconciler does not
// implement this yet; the scheduler falls back to len(connectors)
// for ConnectorsScanned when the type assertion fails.
type reconcilerStatsReader interface {
	WorkspaceConnectorStats(ctx context.Context, workspaceID string) (scanned, failed int, err error)
}

// OrphanReconcileNotifier is the optional notification hook the
// scheduler calls when new orphan rows are detected. Production
// wires *notify.NotificationService; tests use a stub.
type OrphanReconcileNotifier interface {
	NotifyOrphansDetected(ctx context.Context, workspaceID string, orphans []models.AccessOrphanAccount) error
}

// OrphanReconcilerScheduler is the Phase 11 background worker that
// drives the orphan-account reconciliation pass per workspace.
//
// On each call to Run it enumerates the workspaces that have at
// least one access_connectors row and asks the reconciler to find
// upstream users that the IdP does not know. Best-effort: a single
// workspace failure logs and continues. Newly detected orphans are
// optionally surfaced through the notifier.
type OrphanReconcilerScheduler struct {
	db         *gorm.DB
	reconciler WorkspaceOrphanReconciler
	notifier   OrphanReconcileNotifier
	now        func() time.Time
}

// NewOrphanReconcilerScheduler returns a scheduler bound to db and
// the reconciler. Both must be non-nil.
func NewOrphanReconcilerScheduler(db *gorm.DB, reconciler WorkspaceOrphanReconciler) *OrphanReconcilerScheduler {
	return &OrphanReconcilerScheduler{
		db:         db,
		reconciler: reconciler,
		now:        time.Now,
	}
}

// SetNotifier wires the optional notification hook.
func (s *OrphanReconcilerScheduler) SetNotifier(n OrphanReconcileNotifier) {
	s.notifier = n
}

// SetClock overrides time.Now. Tests use this for deterministic
// log timestamps.
func (s *OrphanReconcilerScheduler) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// emitStats writes one orphan_reconcile_summary log line in JSON
// shape so log-aggregator pipelines can ingest the per-workspace
// stats without parsing free-form text.
func (s *OrphanReconcilerScheduler) emitStats(stats orphanReconcileLog) {
	stats.Event = "orphan_reconcile_summary"
	raw, err := json.Marshal(stats)
	if err != nil {
		log.Printf("cron: orphan_reconciler: stats encode failed: %v", err)
		return
	}
	log.Printf("%s", string(raw))
}

// Run reconciles every workspace exactly once. Returns the last
// per-workspace error so callers needing per-row errors should
// inspect logs.
func (s *OrphanReconcilerScheduler) Run(ctx context.Context) error {
	if s == nil || s.db == nil || s.reconciler == nil {
		return errors.New("cron: orphan reconciler scheduler is not fully wired")
	}
	var workspaceIDs []string
	if err := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Distinct("workspace_id").
		Pluck("workspace_id", &workspaceIDs).Error; err != nil {
		return fmt.Errorf("cron: list workspaces: %w", err)
	}

	var lastErr error
	for _, ws := range workspaceIDs {
		start := s.now()
		connectorsScanned := 0
		connectorsFailed := 0
		if statsReader, ok := s.reconciler.(reconcilerStatsReader); ok {
			if scanned, failed, serr := statsReader.WorkspaceConnectorStats(ctx, ws); serr == nil {
				connectorsScanned = scanned
				connectorsFailed = failed
			}
		}
		if connectorsScanned == 0 {
			var cnt int64
			if cerr := s.db.WithContext(ctx).Model(&models.AccessConnector{}).
				Where("workspace_id = ?", ws).Count(&cnt).Error; cerr == nil {
				connectorsScanned = int(cnt)
			}
		}

		rows, err := s.reconciler.ReconcileWorkspace(ctx, ws)
		dur := s.now().Sub(start)
		if err != nil {
			log.Printf("cron: orphan_reconciler: workspace=%s reconcile: %v", ws, err)
			s.emitStats(orphanReconcileLog{
				WorkspaceID: ws, OrphansDetected: len(rows), OrphansNew: countNewOrphans(rows),
				ConnectorsScanned: connectorsScanned, ConnectorsFailed: connectorsFailed + 1,
				DurationMS: dur.Milliseconds(), Error: err.Error(),
			})
			lastErr = err
			continue
		}
		s.emitStats(orphanReconcileLog{
			WorkspaceID: ws, OrphansDetected: len(rows), OrphansNew: countNewOrphans(rows),
			ConnectorsScanned: connectorsScanned, ConnectorsFailed: connectorsFailed,
			DurationMS: dur.Milliseconds(),
		})
		if len(rows) == 0 {
			continue
		}
		if s.notifier != nil {
			if nerr := s.notifier.NotifyOrphansDetected(ctx, ws, rows); nerr != nil {
				log.Printf("cron: orphan_reconciler: workspace=%s notify: %v", ws, nerr)
			}
		}
	}
	return lastErr
}

// countNewOrphans returns the number of orphans whose ID is set
// (i.e. the reconciler persisted a fresh row). Re-detected orphans
// also carry an ID, so the counter is best-effort. Dry-run rows
// have no ID and are excluded.
func countNewOrphans(rows []models.AccessOrphanAccount) int {
	n := 0
	for _, r := range rows {
		if r.ID != "" {
			n++
		}
	}
	return n
}
