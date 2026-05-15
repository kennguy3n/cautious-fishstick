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
// / failed) reflecting the most recent ReconcileWorkspace pass.
// The production *access.OrphanReconciler records counts at the
// end of every pass and exposes them through this interface so
// connectors_scanned / connectors_failed in the orphan_reconcile_
// summary log line reflect rows actually processed (not the DB
// COUNT taken before the pass ran, which would over-report on a
// partial failure).
//
// The scheduler must call WorkspaceConnectorStats AFTER
// ReconcileWorkspace returns so the reconciler has a chance to
// stamp the per-run stats. On the very first call (no prior pass
// recorded for this workspace) the method returns zeros and the
// scheduler falls back to a DB COUNT estimate for scanned only.
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
		rows, err := s.reconciler.ReconcileWorkspace(ctx, ws)
		dur := s.now().Sub(start)

		// Pull per-run scanned/failed counts AFTER the reconcile so
		// connectors_scanned reflects rows the reconciler actually
		// processed in this pass. On a partial failure the reconciler
		// is best-effort across connectors (see
		// docs/architecture.md §12), so connectors_failed counts the
		// per-connector failures rather than collapsing the whole pass
		// to a single 1.
		connectorsScanned := 0
		connectorsFailed := 0
		if statsReader, ok := s.reconciler.(reconcilerStatsReader); ok {
			if scanned, failed, serr := statsReader.WorkspaceConnectorStats(ctx, ws); serr == nil {
				connectorsScanned = scanned
				connectorsFailed = failed
			}
		}
		if connectorsScanned == 0 {
			// Fallback for reconcilers that do not implement
			// reconcilerStatsReader, or for the very first pass before
			// stats have been recorded for this workspace.
			var cnt int64
			if cerr := s.db.WithContext(ctx).Model(&models.AccessConnector{}).
				Where("workspace_id = ?", ws).Count(&cnt).Error; cerr == nil {
				connectorsScanned = int(cnt)
			}
		}

		if err != nil {
			log.Printf("cron: orphan_reconciler: workspace=%s reconcile: %v", ws, err)
			// connectorsFailed already reflects the per-connector
			// failures the reconciler reported (≥1 on this branch when
			// the reconciler implements reconcilerStatsReader). When it
			// does not, fall back to 1 so SIEM consumers still see a
			// non-zero failure count for the workspace.
			if connectorsFailed == 0 {
				connectorsFailed = 1
			}
			s.emitStats(orphanReconcileLog{
				WorkspaceID: ws, OrphansDetected: len(rows), OrphansNew: countNewOrphans(rows),
				ConnectorsScanned: connectorsScanned, ConnectorsFailed: connectorsFailed,
				DurationMS: dur.Milliseconds(), Error: err.Error(),
			})
			lastErr = err
		} else {
			s.emitStats(orphanReconcileLog{
				WorkspaceID: ws, OrphansDetected: len(rows), OrphansNew: countNewOrphans(rows),
				ConnectorsScanned: connectorsScanned, ConnectorsFailed: connectorsFailed,
				DurationMS: dur.Milliseconds(),
			})
		}
		// Best-effort across connectors (see docs/architecture.md
		// §12.2): orphans surfaced by successful connectors must be
		// dispatched to the notifier even when other connectors in the
		// same workspace failed. The reconciler persists those rows
		// before returning the aggregated error, so skipping the
		// notification here would silently drop alerts operators rely
		// on for flaky-connector workspaces.
		if s.notifier != nil && len(rows) > 0 {
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
