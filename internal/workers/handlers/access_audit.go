// Package handlers — access audit handler (Task 17).
//
// AccessAudit drives the AccessAuditor optional interface end-to-end:
//
//  1. Load the access_jobs row and mark it running.
//  2. Decrypt the connector credentials (via JobContext.LoadConn).
//  3. Resolve the AccessConnector via JobContext.Resolve.
//  4. Skip cleanly when the connector does not implement
//     access.AccessAuditor (the optional interface is opt-in).
//  5. Look up the audit-kind access_sync_state cursor; treat a
//     missing row as a zero-value `since` (full backfill).
//  6. Call FetchAccessAuditLogs and publish each batch via
//     JobContext.AuditProducer.
//  7. Persist the monotonic `nextSince` returned by the handler so
//     re-runs resume where the last one stopped.
//  8. Finalise the job row (completed / failed).
package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// AccessAudit is the worker handler for access_audit_log jobs.
// AuditProducer in the JobContext is required; nil falls back to a
// NoOpAuditProducer so the worker still drains the connector and
// advances the cursor when Kafka is intentionally unconfigured (e.g.
// in dev / on-prem deployments without log infrastructure).
func AccessAudit(ctx context.Context, jc JobContext, jobID string) error {
	if jc.DB == nil || jc.Resolve == nil || jc.LoadConn == nil {
		return ErrMissingDependency
	}
	if jc.Now == nil {
		jc.Now = time.Now
	}
	producer := jc.AuditProducer
	if producer == nil {
		producer = &access.NoOpAuditProducer{}
	}

	var job models.AccessJob
	if err := jc.DB.WithContext(ctx).Where("id = ?", jobID).First(&job).Error; err != nil {
		return fmt.Errorf("handlers: load job %s: %w", jobID, err)
	}
	now := jc.Now()
	if err := jc.DB.WithContext(ctx).
		Model(&models.AccessJob{}).
		Where("id = ?", jobID).
		Updates(map[string]interface{}{
			"status":     models.AccessJobStatusRunning,
			"started_at": &now,
			"last_error": "",
		}).Error; err != nil {
		return fmt.Errorf("handlers: mark running: %w", err)
	}

	provider, cfg, secrets, err := jc.LoadConn(ctx, jc.DB, job.ConnectorID)
	if err != nil {
		return finalize(ctx, jc, jobID, err)
	}
	conn, err := jc.Resolve(provider)
	if err != nil {
		return finalize(ctx, jc, jobID, err)
	}
	auditor, ok := conn.(access.AccessAuditor)
	if !ok {
		// Connector does not advertise the AccessAuditor optional
		// interface — mark the job completed cleanly so the worker
		// doesn't retry it forever.
		return finalize(ctx, jc, jobID, nil)
	}

	since, err := loadAuditCursor(ctx, jc.DB, job.ConnectorID)
	if err != nil {
		return finalize(ctx, jc, jobID, err)
	}

	var lastCursor = since
	publishErr := auditor.FetchAccessAuditLogs(ctx, cfg, secrets, since,
		func(batch []*access.AuditLogEntry, nextSince time.Time) error {
			if len(batch) > 0 {
				if err := producer.PublishAccessAuditLogs(ctx, job.ConnectorID, batch); err != nil {
					return err
				}
			}
			if nextSince.After(lastCursor) {
				lastCursor = nextSince
			}
			return nil
		})

	// Soft-skip when the tenant doesn't expose audit logs (e.g.
	// Slack non-Enterprise-Grid, GitHub non-eligible orgs). We
	// still want the job to finish "completed" with a noted reason
	// rather than retry forever.
	if errors.Is(publishErr, access.ErrAuditNotAvailable) {
		publishErr = nil
	}

	// Persist the cursor advance even on partial failure so we
	// don't replay the published batches on retry.
	if lastCursor.After(since) {
		if perr := saveAuditCursor(ctx, jc.DB, job.ConnectorID, lastCursor, jc.Now); perr != nil && publishErr == nil {
			publishErr = perr
		}
	}
	return finalize(ctx, jc, jobID, publishErr)
}

// loadAuditCursor returns the audit-kind cursor for a connector, or
// the zero time when no row exists yet.
func loadAuditCursor(ctx context.Context, db *gorm.DB, connectorID string) (time.Time, error) {
	var row models.AccessSyncState
	err := db.WithContext(ctx).
		Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("handlers: load audit cursor: %w", err)
	}
	if row.DeltaLink == "" {
		return time.Time{}, nil
	}
	ts, perr := time.Parse(time.RFC3339Nano, row.DeltaLink)
	if perr != nil {
		// Old rows may persist alternate formats; fall back to a zero
		// `since` so we backfill rather than crash.
		return time.Time{}, nil
	}
	return ts, nil
}

// saveAuditCursor upserts the audit-kind row with the new cursor.
func saveAuditCursor(ctx context.Context, db *gorm.DB, connectorID string, cursor time.Time, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	current := now().UTC()
	stamp := cursor.UTC().Format(time.RFC3339Nano)
	row := models.AccessSyncState{
		ConnectorID: connectorID,
		Kind:        models.SyncStateKindAudit,
		DeltaLink:   stamp,
		CreatedAt:   current,
		UpdatedAt:   current,
	}

	var existing models.AccessSyncState
	err := db.WithContext(ctx).
		Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).
		First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row.ID = newAuditCursorID(connectorID, current)
		if cerr := db.WithContext(ctx).Create(&row).Error; cerr != nil {
			return fmt.Errorf("handlers: persist audit cursor: %w", cerr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("handlers: probe audit cursor: %w", err)
	}
	if uerr := db.WithContext(ctx).
		Model(&models.AccessSyncState{}).
		Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).
		Updates(map[string]interface{}{
			"delta_link": stamp,
			"updated_at": current,
		}).Error; uerr != nil {
		return fmt.Errorf("handlers: update audit cursor: %w", uerr)
	}
	return nil
}

// newAuditCursorID produces a deterministic ID for new
// access_sync_state rows so the worker doesn't need to import a
// ULID generator into the handlers package.
func newAuditCursorID(connectorID string, now time.Time) string {
	return fmt.Sprintf("aud-%s-%d", connectorID, now.UnixNano())
}
