package access

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// OrphanReconciler is the Phase 11 service that detects upstream
// SaaS users (per connector) which have no corresponding identity
// in the IdP and persists each finding as an access_orphan_accounts
// row. Operators can revoke or dismiss orphan accounts through the
// /access/orphans HTTP surface.
//
// Per docs/architecture.md §13, "orphan accounts" surface in the UI
// as "unused app accounts" — the SN360 user-facing term is set in
// the handler layer, not here.
//
// The reconciler is best-effort across connectors: a single
// connector failure logs but does not block the next connector in
// the workspace.
//
// Dry-run is threaded through the call chain as a per-call
// parameter (see ReconcileWorkspaceDryRun) rather than a shared
// struct field so two concurrent HTTP requests (one dry, one wet)
// cannot race each other: a shared bool would let request A flip
// it true, request B silently skip its persistence, then defer
// flip it back to false. Callers must go through
// ReconcileWorkspace or ReconcileWorkspaceDryRun — the public API
// never accepts a dry-run bool.
type OrphanReconciler struct {
	db              *gorm.DB
	provisioningSvc *AccessProvisioningService
	credLoader      *ConnectorCredentialsLoader
	getConnectorFn  func(provider string) (AccessConnector, error)
	now             func() time.Time
	newID           func() string
	// perConnectorDelay throttles per-connector iterations inside
	// ReconcileWorkspace so an upstream API is not hammered by N
	// connectors firing concurrently. Defaults to 1s. Set via
	// SetPerConnectorDelay (config-driven, see
	// internal/config/access.go::ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR).
	perConnectorDelay time.Duration

	// statsMu guards lastRunStats. The map is updated at the end of
	// every reconcileWorkspace pass and read by the scheduler via
	// WorkspaceConnectorStats so per-run scanned/failed counts
	// reflect rows the reconciler actually processed (not the DB
	// COUNT before the pass started).
	statsMu      sync.Mutex
	lastRunStats map[string]connectorRunStats
}

// connectorRunStats records the per-workspace outcome of the most
// recent reconcileWorkspace pass. Exposed to the scheduler through
// WorkspaceConnectorStats so the orphan_reconcile_summary log line
// reports the count of connectors actually processed instead of
// the workspace's total in the DB.
type connectorRunStats struct {
	scanned int
	failed  int
}

// NewOrphanReconciler returns a reconciler bound to db. The
// optional ConnectorCredentialsLoader and provisioning service are
// wired in via setters because the access package's other services
// follow the same construction shape.
func NewOrphanReconciler(db *gorm.DB, provisioningSvc *AccessProvisioningService, credLoader *ConnectorCredentialsLoader) *OrphanReconciler {
	return &OrphanReconciler{
		db:                db,
		provisioningSvc:   provisioningSvc,
		credLoader:        credLoader,
		getConnectorFn:    GetAccessConnector,
		now:               time.Now,
		newID:             newULID,
		perConnectorDelay: time.Second,
	}
}

// SetPerConnectorDelay overrides the per-connector throttle.
// Pass 0 to disable the delay entirely (useful in tests).
func (r *OrphanReconciler) SetPerConnectorDelay(d time.Duration) {
	if r == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	r.perConnectorDelay = d
}

// PerConnectorDelay returns the currently configured per-connector
// throttle. Exposed so the worker binary and its tests can assert
// that BuildOrphanReconciler applied the operator-supplied
// ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR value rather than
// the constructor's 1s default.
func (r *OrphanReconciler) PerConnectorDelay() time.Duration {
	if r == nil {
		return 0
	}
	return r.perConnectorDelay
}

// WorkspaceConnectorStats returns the scanned/failed connector
// counts from the most recent reconcileWorkspace pass for the
// given workspace. Returns zeros when no pass has run yet so the
// scheduler falls back to its DB COUNT estimate. This method
// satisfies the cron package's reconcilerStatsReader contract.
func (r *OrphanReconciler) WorkspaceConnectorStats(_ context.Context, workspaceID string) (scanned, failed int, err error) {
	if r == nil {
		return 0, 0, nil
	}
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if r.lastRunStats == nil {
		return 0, 0, nil
	}
	stats, ok := r.lastRunStats[workspaceID]
	if !ok {
		return 0, 0, nil
	}
	return stats.scanned, stats.failed, nil
}

// recordRunStats stores the per-workspace scanned/failed counts
// for the just-completed pass under statsMu so concurrent
// reconciles do not race on lastRunStats. Internal helper.
func (r *OrphanReconciler) recordRunStats(workspaceID string, scanned, failed int) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if r.lastRunStats == nil {
		r.lastRunStats = make(map[string]connectorRunStats)
	}
	r.lastRunStats[workspaceID] = connectorRunStats{scanned: scanned, failed: failed}
}

// SetClock overrides the default time source for deterministic
// reconciliation tests.
func (r *OrphanReconciler) SetClock(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// SetIDFn overrides the default ULID generator for deterministic
// reconciliation tests.
func (r *OrphanReconciler) SetIDFn(fn func() string) {
	if fn != nil {
		r.newID = fn
	}
}

// ReconcileWorkspaceDryRun runs the same detection pass as
// ReconcileWorkspace but without persisting any rows. The returned
// slice contains in-memory AccessOrphanAccount values populated
// with the detected upstream account metadata so operators can
// review what a real sweep would record. Dry-run is passed as a
// per-call parameter so concurrent callers can mix dry and wet
// sweeps safely.
func (r *OrphanReconciler) ReconcileWorkspaceDryRun(ctx context.Context, workspaceID string) ([]models.AccessOrphanAccount, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: orphan reconciler not configured", ErrValidation)
	}
	return r.reconcileWorkspace(ctx, workspaceID, true)
}

// ReconcileWorkspace iterates every connector in the workspace,
// asks the connector for its current upstream user list, and
// persists a new access_orphan_accounts row for any user that has
// no matching team_members.user_id pivot. Returns the set of rows
// detected (or re-detected) on this pass. Existing rows in
// "auto_revoked" / "acknowledged" / "dismissed" terminal states
// are not duplicated.
func (r *OrphanReconciler) ReconcileWorkspace(ctx context.Context, workspaceID string) ([]models.AccessOrphanAccount, error) {
	return r.reconcileWorkspace(ctx, workspaceID, false)
}

// reconcileWorkspace is the shared implementation backing both
// ReconcileWorkspace and ReconcileWorkspaceDryRun. dryRun is a
// per-call parameter (not a struct field) so concurrent callers
// cannot race on a shared flag — see the OrphanReconciler doc
// comment above for the full rationale.
func (r *OrphanReconciler) reconcileWorkspace(ctx context.Context, workspaceID string, dryRun bool) ([]models.AccessOrphanAccount, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("%w: orphan reconciler not configured", ErrValidation)
	}
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}

	var connectors []models.AccessConnector
	if err := r.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Find(&connectors).Error; err != nil {
		return nil, fmt.Errorf("access: list workspace connectors: %w", err)
	}

	out := make([]models.AccessOrphanAccount, 0)
	var connectorErrs []error
	scanned := 0
	failed := 0
	for i := range connectors {
		conn := &connectors[i]
		scanned++
		rows, err := r.reconcileConnector(ctx, conn, dryRun)
		if err != nil {
			// Per docs/architecture.md and docs/architecture.md §12 the
			// reconciler is best-effort across connectors: log this
			// connector's failure and continue to the next one so a
			// single broken upstream cannot mask orphans in the rest
			// of the workspace. Errors are collected and returned as
			// an aggregated error after the loop finishes.
			failed++
			wrapped := fmt.Errorf("access: reconcile connector %s: %w", conn.ID, err)
			log.Printf("access: orphan_reconciler: workspace=%s connector=%s: %v", workspaceID, conn.ID, err)
			connectorErrs = append(connectorErrs, wrapped)
		} else {
			out = append(out, rows...)
		}
		if i < len(connectors)-1 && r.perConnectorDelay > 0 {
			select {
			case <-ctx.Done():
				r.recordRunStats(workspaceID, scanned, failed)
				return out, ctx.Err()
			case <-time.After(r.perConnectorDelay):
			}
		}
	}
	r.recordRunStats(workspaceID, scanned, failed)
	if len(connectorErrs) > 0 {
		return out, errors.Join(connectorErrs...)
	}
	return out, nil
}

// reconcileConnector handles a single connector. Returns the slice
// of orphan rows that were persisted (new or re-detected) during
// this pass. dryRun is threaded in from reconcileWorkspace as a
// per-call parameter so this method never reads shared mutable
// state for the dry-run decision.
func (r *OrphanReconciler) reconcileConnector(ctx context.Context, conn *models.AccessConnector, dryRun bool) ([]models.AccessOrphanAccount, error) {
	if conn == nil {
		return nil, nil
	}
	if r.credLoader == nil || r.getConnectorFn == nil {
		return nil, fmt.Errorf("orphan reconciler: credentials loader / connector registry not wired")
	}

	cfg, secrets, err := r.credLoader.LoadConnectorCredentials(ctx, conn.ID)
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}
	connector, err := r.getConnectorFn(conn.Provider)
	if err != nil {
		return nil, fmt.Errorf("registry lookup %s: %w", conn.Provider, err)
	}

	// Snapshot IdP users from team_members.external_id keyed by
	// (connector_id, external_id). Anything the connector reports
	// upstream that does NOT appear in this set is an orphan.
	known := map[string]struct{}{}
	var members []models.TeamMember
	if err := r.db.WithContext(ctx).
		Where("connector_id = ?", conn.ID).
		Find(&members).Error; err != nil {
		return nil, fmt.Errorf("snapshot team_members: %w", err)
	}
	for _, m := range members {
		if m.ExternalID == "" {
			continue
		}
		known[m.ExternalID] = struct{}{}
	}

	var upstream []*Identity
	err = connector.SyncIdentities(ctx, cfg, secrets, "", func(batch []*Identity, _ string) error {
		upstream = append(upstream, batch...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("connector SyncIdentities: %w", err)
	}

	now := r.now()
	out := make([]models.AccessOrphanAccount, 0)
	for _, ident := range upstream {
		if ident == nil || ident.ExternalID == "" {
			continue
		}
		if _, ok := known[ident.ExternalID]; ok {
			continue
		}

		if dryRun {
			out = append(out, models.AccessOrphanAccount{
				WorkspaceID:    conn.WorkspaceID,
				ConnectorID:    conn.ID,
				UserExternalID: ident.ExternalID,
				Email:          ident.Email,
				DisplayName:    ident.DisplayName,
				Status:         models.OrphanStatusDetected,
				DetectedAt:     now,
			})
			continue
		}

		row, persisted, perr := r.upsertOrphan(ctx, conn, ident, now)
		if perr != nil {
			return out, fmt.Errorf("upsert orphan %s/%s: %w", conn.ID, ident.ExternalID, perr)
		}
		if persisted {
			out = append(out, row)
		}
	}
	return out, nil
}

// upsertOrphan persists or refreshes one orphan row. Returns the
// stored row alongside a boolean that is true when the row was
// newly inserted (so callers can drive notifications); false means
// an existing row was re-detected.
func (r *OrphanReconciler) upsertOrphan(ctx context.Context, conn *models.AccessConnector, ident *Identity, now time.Time) (models.AccessOrphanAccount, bool, error) {
	var existing models.AccessOrphanAccount
	err := r.db.WithContext(ctx).
		Where("connector_id = ? AND user_external_id = ?", conn.ID, ident.ExternalID).
		First(&existing).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		row := models.AccessOrphanAccount{
			ID:             r.newID(),
			WorkspaceID:    conn.WorkspaceID,
			ConnectorID:    conn.ID,
			UserExternalID: ident.ExternalID,
			Email:          ident.Email,
			DisplayName:    ident.DisplayName,
			Status:         models.OrphanStatusDetected,
			DetectedAt:     now,
		}
		if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
			return row, false, err
		}
		return row, true, nil
	case err != nil:
		return existing, false, err
	default:
		// Re-detected — re-stamp DetectedAt and refresh denorm fields
		// so the UI shows the most recent profile data. The status
		// stays whatever it was: a previously dismissed orphan is
		// still considered dismissed until the operator unsuppresses.
		if err := r.db.WithContext(ctx).
			Model(&existing).
			Updates(map[string]interface{}{
				"detected_at":  now,
				"email":        ident.Email,
				"display_name": ident.DisplayName,
				"updated_at":   now,
			}).Error; err != nil {
			return existing, false, err
		}
		return existing, false, nil
	}
}

// RevokeOrphan triggers connector-level revoke for the orphan and
// marks the row as auto_revoked. The connector's RevokeAccess is
// called with a minimal AccessGrant whose UserExternalID points at
// the orphan; ResourceExternalID is left empty because the
// reconciler is killing access globally, not a single resource.
func (r *OrphanReconciler) RevokeOrphan(ctx context.Context, orphanID string) error {
	if r == nil {
		return fmt.Errorf("%w: orphan reconciler is nil", ErrValidation)
	}
	if orphanID == "" {
		return fmt.Errorf("%w: orphan id is required", ErrValidation)
	}
	var row models.AccessOrphanAccount
	if err := r.db.WithContext(ctx).Where("id = ?", orphanID).First(&row).Error; err != nil {
		return err
	}

	if r.credLoader != nil && r.getConnectorFn != nil {
		cfg, secrets, lerr := r.credLoader.LoadConnectorCredentials(ctx, row.ConnectorID)
		if lerr != nil {
			return fmt.Errorf("orphan revoke: load credentials: %w", lerr)
		}
		var conn models.AccessConnector
		if err := r.db.WithContext(ctx).Where("id = ?", row.ConnectorID).First(&conn).Error; err != nil {
			return fmt.Errorf("orphan revoke: load connector: %w", err)
		}
		connector, cerr := r.getConnectorFn(conn.Provider)
		if cerr != nil {
			return fmt.Errorf("orphan revoke: registry lookup %s: %w", conn.Provider, cerr)
		}
		if err := connector.RevokeAccess(ctx, cfg, secrets, AccessGrant{
			UserExternalID: row.UserExternalID,
		}); err != nil {
			return fmt.Errorf("orphan revoke: connector RevokeAccess: %w", err)
		}
	}

	now := r.now()
	if err := r.db.WithContext(ctx).Model(&row).Updates(map[string]interface{}{
		"status":      models.OrphanStatusAutoRevoked,
		"resolved_at": now,
		"updated_at":  now,
	}).Error; err != nil {
		return err
	}
	return nil
}

// DismissOrphan marks the orphan as dismissed. Used when the
// operator confirms the upstream account is legitimate (e.g. shared
// service account) and should not raise further alerts.
func (r *OrphanReconciler) DismissOrphan(ctx context.Context, orphanID string) error {
	return r.transitionToTerminal(ctx, orphanID, models.OrphanStatusDismissed)
}

// AcknowledgeOrphan marks the orphan as acknowledged. Used when the
// operator wants to suppress the alert without revoking and without
// fully dismissing the row.
func (r *OrphanReconciler) AcknowledgeOrphan(ctx context.Context, orphanID string) error {
	return r.transitionToTerminal(ctx, orphanID, models.OrphanStatusAcknowledged)
}

// ListOrphans returns the orphans in a workspace, optionally
// filtered by status. Soft-deleted rows are excluded automatically.
func (r *OrphanReconciler) ListOrphans(ctx context.Context, workspaceID, status string) ([]models.AccessOrphanAccount, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("%w: orphan reconciler not configured", ErrValidation)
	}
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	q := r.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var rows []models.AccessOrphanAccount
	if err := q.Order("detected_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *OrphanReconciler) transitionToTerminal(ctx context.Context, orphanID, terminal string) error {
	if orphanID == "" {
		return fmt.Errorf("%w: orphan id is required", ErrValidation)
	}
	now := r.now()
	res := r.db.WithContext(ctx).
		Model(&models.AccessOrphanAccount{}).
		Where("id = ?", orphanID).
		Updates(map[string]interface{}{
			"status":      terminal,
			"resolved_at": now,
			"updated_at":  now,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
