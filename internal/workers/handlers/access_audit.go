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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
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

	persistedCursors, err := loadAuditCursors(ctx, jc.DB, job.ConnectorID)
	if err != nil {
		return finalize(ctx, jc, jobID, err)
	}

	// updatedCursors starts as a copy of the persisted map so a
	// per-partition cursor that doesn't advance in this run still
	// round-trips to storage untouched. We track each partition's
	// cursor independently — a fast-moving partition (e.g. signIns
	// at 13:00) MUST NOT shadow a slower partition's progress (e.g.
	// directoryAudits at 09:00). The single-variable design that
	// existed before this commit collapsed the two into max(...) and
	// caused `$filter ge {inflated}` to silently skip un-fetched
	// events of the slower partition on retry after partial failure.
	updatedCursors := make(map[string]time.Time, len(persistedCursors))
	for k, v := range persistedCursors {
		updatedCursors[k] = v
	}

	publishErr := auditor.FetchAccessAuditLogs(ctx, cfg, secrets, persistedCursors,
		func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error {
			if len(batch) > 0 {
				if err := producer.PublishAccessAuditLogs(ctx, job.ConnectorID, batch); err != nil {
					return err
				}
			}
			if cur, ok := updatedCursors[partitionKey]; !ok || nextSince.After(cur) {
				updatedCursors[partitionKey] = nextSince
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
	// don't replay the published batches on retry. The map is
	// serialised as JSON so partitions advance independently and a
	// failure mid-run can't shadow a slower partition's cursor.
	if !cursorsEqual(updatedCursors, persistedCursors) {
		if perr := saveAuditCursors(ctx, jc.DB, job.ConnectorID, updatedCursors, jc.Now); perr != nil && publishErr == nil {
			publishErr = perr
		}
	}
	return finalize(ctx, jc, jobID, publishErr)
}

// loadAuditCursors returns the per-partition audit cursors for a
// connector. A missing row returns an empty (nil) map. The persisted
// DeltaLink is either a JSON object mapping partition key -> RFC3339
// timestamp (new format) or a bare RFC3339 timestamp (legacy format,
// migrated as `{DefaultAuditPartition: ts}`).
func loadAuditCursors(ctx context.Context, db *gorm.DB, connectorID string) (map[string]time.Time, error) {
	var row models.AccessSyncState
	err := db.WithContext(ctx).
		Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindAudit).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("handlers: load audit cursor: %w", err)
	}
	return decodeAuditCursors(row.DeltaLink), nil
}

// decodeAuditCursors parses the persisted DeltaLink into the
// per-partition cursor map. Empty / un-parseable input returns an
// empty map so we backfill rather than crash.
func decodeAuditCursors(raw string) map[string]time.Time {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]time.Time{}
	}
	if strings.HasPrefix(trimmed, "{") {
		var encoded map[string]string
		if err := json.Unmarshal([]byte(trimmed), &encoded); err != nil {
			return map[string]time.Time{}
		}
		out := make(map[string]time.Time, len(encoded))
		for partition, stamp := range encoded {
			ts, perr := time.Parse(time.RFC3339Nano, stamp)
			if perr != nil {
				continue
			}
			out[partition] = ts
		}
		return out
	}
	// Legacy single-cursor format: migrate to default partition.
	ts, perr := time.Parse(time.RFC3339Nano, trimmed)
	if perr != nil {
		return map[string]time.Time{}
	}
	return map[string]time.Time{access.DefaultAuditPartition: ts}
}

// encodeAuditCursors serialises the per-partition cursor map as a
// JSON object (keys sorted by Go's encoding/json for stable output).
func encodeAuditCursors(cursors map[string]time.Time) (string, error) {
	encoded := make(map[string]string, len(cursors))
	for partition, ts := range cursors {
		encoded[partition] = ts.UTC().Format(time.RFC3339Nano)
	}
	buf, err := json.Marshal(encoded)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// cursorsEqual returns true when two cursor maps represent the same
// logical instants for every partition. Used by the worker to skip
// a no-op DB write when no partition advanced. Comparison goes
// through time.Equal so JSON-roundtripped and freshly-parsed Time
// values for the same instant compare as equal.
func cursorsEqual(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if !av.Equal(bv) {
			return false
		}
	}
	return true
}

// saveAuditCursors upserts the audit-kind row with the encoded
// per-partition cursor map.
func saveAuditCursors(ctx context.Context, db *gorm.DB, connectorID string, cursors map[string]time.Time, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	current := now().UTC()
	stamp, eerr := encodeAuditCursors(cursors)
	if eerr != nil {
		return fmt.Errorf("handlers: encode audit cursors: %w", eerr)
	}
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
		row.ID = newAuditCursorID()
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

// newAuditCursorID generates a 26-character ULID for new
// access_sync_state rows. AccessSyncState.ID is varchar(26); any
// longer ID format (e.g. fmt.Sprintf("aud-%s-%d", connectorID,
// unixNano)) would exceed the column on PostgreSQL and reject the
// INSERT. SQLite silently accepts over-long strings, so unit tests
// alone do not catch this — keep this function aligned with the
// codebase-wide newULID convention in
// internal/services/access/request_service.go.
func newAuditCursorID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
