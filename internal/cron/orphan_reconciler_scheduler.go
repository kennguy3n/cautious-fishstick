package cron

import (
	"context"
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
		rows, err := s.reconciler.ReconcileWorkspace(ctx, ws)
		if err != nil {
			log.Printf("cron: orphan_reconciler: workspace=%s reconcile: %v", ws, err)
			lastErr = err
			continue
		}
		if len(rows) == 0 {
			continue
		}
		log.Printf("cron: orphan_reconciler: workspace=%s detected %d unused app accounts", ws, len(rows))
		if s.notifier != nil {
			if nerr := s.notifier.NotifyOrphansDetected(ctx, ws, rows); nerr != nil {
				log.Printf("cron: orphan_reconciler: workspace=%s notify: %v", ws, nerr)
			}
		}
	}
	return lastErr
}
