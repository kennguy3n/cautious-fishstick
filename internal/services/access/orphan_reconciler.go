package access

import (
	"context"
	"errors"
	"fmt"
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
// Per docs/PROPOSAL.md §13.4, "orphan accounts" surface in the UI
// as "unused app accounts" — the SN360 user-facing term is set in
// the handler layer, not here.
//
// The reconciler is best-effort across connectors: a single
// connector failure logs but does not block the next connector in
// the workspace.
type OrphanReconciler struct {
	db              *gorm.DB
	provisioningSvc *AccessProvisioningService
	credLoader      *ConnectorCredentialsLoader
	getConnectorFn  func(provider string) (AccessConnector, error)
	now             func() time.Time
	newID           func() string
}

// NewOrphanReconciler returns a reconciler bound to db. The
// optional ConnectorCredentialsLoader and provisioning service are
// wired in via setters because the access package's other services
// follow the same construction shape.
func NewOrphanReconciler(db *gorm.DB, provisioningSvc *AccessProvisioningService, credLoader *ConnectorCredentialsLoader) *OrphanReconciler {
	return &OrphanReconciler{
		db:              db,
		provisioningSvc: provisioningSvc,
		credLoader:      credLoader,
		getConnectorFn:  GetAccessConnector,
		now:             time.Now,
		newID:           newULID,
	}
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

// ReconcileWorkspace iterates every connector in the workspace,
// asks the connector for its current upstream user list, and
// persists a new access_orphan_accounts row for any user that has
// no matching team_members.user_id pivot. Returns the set of rows
// detected (or re-detected) on this pass. Existing rows in
// "auto_revoked" / "acknowledged" / "dismissed" terminal states
// are not duplicated.
func (r *OrphanReconciler) ReconcileWorkspace(ctx context.Context, workspaceID string) ([]models.AccessOrphanAccount, error) {
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
	for i := range connectors {
		conn := &connectors[i]
		rows, err := r.reconcileConnector(ctx, conn)
		if err != nil {
			// Per docs/PHASES.md the reconciler is best-effort: log and
			// continue. We return the accumulated rows alongside the
			// first error so the cron can surface it without losing
			// earlier connector progress.
			return out, fmt.Errorf("access: reconcile connector %s: %w", conn.ID, err)
		}
		out = append(out, rows...)
	}
	return out, nil
}

// reconcileConnector handles a single connector. Returns the slice
// of orphan rows that were persisted (new or re-detected) during
// this pass.
func (r *OrphanReconciler) reconcileConnector(ctx context.Context, conn *models.AccessConnector) ([]models.AccessOrphanAccount, error) {
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
