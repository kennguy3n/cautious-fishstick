package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// syncIdentitiesPayload is the worker-specific payload shape for an
// access_jobs row of job_type = sync_identities. Empty payloads are
// allowed — the connector falls back to a fresh enumeration.
type syncIdentitiesPayload struct {
	Checkpoint string `json:"checkpoint,omitempty"`
}

// tombstoneFraction is the safety floor for tombstone protection.
// A full sync whose total identity count drops below
// tombstoneFraction * previousIdentityCount aborts with
// ErrTombstoneSafetyThreshold instead of soft-deleting the missing
// rows. The 70 % threshold is the SN360 default per
// docs/internal/PHASES.md Phase 6 sync rules.
const tombstoneFraction = 0.70

// ErrTombstoneSafetyThreshold surfaces when a fresh sync's total
// identity count is below tombstoneFraction of the previously
// observed count. Aborts the worker — the next pending sync_state
// row keeps the previous checkpoint so the next probe retries.
var ErrTombstoneSafetyThreshold = errors.New("handlers: sync_identities aborted: tombstone safety threshold breached")

// workspaceForConnector reads the access_connectors row's
// workspace_id so Team / TeamMember inserts inherit the correct
// scope. Returns the empty string when the row is missing — the
// caller treats that as a fatal condition.
func workspaceForConnector(ctx context.Context, db *gorm.DB, connectorID string) (string, error) {
	var c models.AccessConnector
	if err := db.WithContext(ctx).Where("id = ?", connectorID).First(&c).Error; err != nil {
		return "", err
	}
	return c.WorkspaceID, nil
}

// AccessSyncIdentities is the worker handler for sync_identities
// jobs. It calls AccessConnector.SyncIdentities and:
//
//  1. For every IdentityTypeUser, upserts a team_members row keyed
//     by (connector_id, external_id).
//  2. For every IdentityTypeGroup, upserts a teams row keyed by
//     (connector_id, external_id).
//  3. Tracks the running identity count and the latest
//     nextCheckpoint, persisting the final pair into
//     access_sync_state.
//  4. Runs a tombstone safety pass — if the new count drops below
//     70 % of the previously observed count the handler aborts
//     before touching access_sync_state, leaving the old row
//     intact.
//  5. Runs a manager-link resolution pass once the identity batch
//     is fully ingested, updating team_members.manager_id by
//     mapping external manager IDs to the freshly-upserted rows.
//
// Idempotency: re-running this handler against the same job ID is
// safe — upserts replace existing rows and the manager-link pass
// is idempotent.
func AccessSyncIdentities(ctx context.Context, jc JobContext, jobID string) error {
	return runJob(ctx, jc, jobID, func(ctx context.Context, conn access.AccessConnector, job *models.AccessJob, cfg, secrets map[string]interface{}) error {
		var pl syncIdentitiesPayload
		if len(job.Payload) > 0 {
			if err := json.Unmarshal(job.Payload, &pl); err != nil {
				return err
			}
		}

		workspaceID, err := workspaceForConnector(ctx, jc.DB, job.ConnectorID)
		if err != nil {
			return fmt.Errorf("handlers: load connector workspace: %w", err)
		}
		if workspaceID == "" {
			return fmt.Errorf("handlers: connector %s has empty workspace_id", job.ConnectorID)
		}

		// Read the previous sync_state row (if any) so we can
		// enforce the tombstone safety threshold once the new
		// batch has been counted.
		var previousState models.AccessSyncState
		hadPreviousState := true
		if err := jc.DB.WithContext(ctx).
			Where("connector_id = ? AND kind = ?", job.ConnectorID, models.SyncStateKindIdentity).
			Order("updated_at DESC").
			First(&previousState).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				hadPreviousState = false
			} else {
				return fmt.Errorf("handlers: load sync_state: %w", err)
			}
		}

		// Buffer the per-batch results so the tombstone check can
		// abort before we touch the DB. The cost (memory) is
		// linear in directory size; the SN360 implementation
		// streams to a worker-local on-disk staging table for
		// truly huge directories — Phase 6 is OK with the in-
		// memory shape.
		var users []*access.Identity
		var groups []*access.Identity
		var nextCheckpoint string
		batchCallback := func(batch []*access.Identity, next string) error {
			nextCheckpoint = next
			for _, id := range batch {
				if id == nil {
					continue
				}
				switch id.Type {
				case access.IdentityTypeUser:
					users = append(users, id)
				case access.IdentityTypeGroup:
					groups = append(groups, id)
				}
			}
			return nil
		}
		if err := conn.SyncIdentities(ctx, cfg, secrets, pl.Checkpoint, batchCallback); err != nil {
			return err
		}

		totalCount := len(users) + len(groups)
		if hadPreviousState && previousState.IdentityCount > 0 {
			minAllowed := int(float64(previousState.IdentityCount) * tombstoneFraction)
			if totalCount < minAllowed {
				return fmt.Errorf("%w: previous=%d new=%d", ErrTombstoneSafetyThreshold, previousState.IdentityCount, totalCount)
			}
		}

		now := jc.Now()
		// Persist users + groups in a single transaction so we
		// never leave the DB with half of a batch applied.
		err = jc.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, g := range groups {
				if err := upsertTeam(tx, workspaceID, job.ConnectorID, g, now); err != nil {
					return err
				}
			}
			for _, u := range users {
				if err := upsertTeamMember(tx, workspaceID, job.ConnectorID, u, now); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Manager-link resolution pass. Done in a second
		// transaction so the upsert pass above stays small and
		// readable — and so a manager-resolution failure does
		// NOT roll back the identity ingest.
		if err := resolveManagerLinks(ctx, jc.DB, job.ConnectorID, users, now); err != nil {
			return fmt.Errorf("handlers: resolve manager links: %w", err)
		}

		// Persist the new sync_state row. Upsert by
		// (connector_id, kind). Thread `now` so the row's updated_at is
		// driven by the same clock as the rest of this sync — the
		// IdentitySyncScheduler reads `updated_at` to decide whether a
		// connector is overdue, so explicit threading keeps that
		// staleness signal deterministic in tests.
		return persistSyncState(ctx, jc.DB, job.ConnectorID, nextCheckpoint, totalCount, now)
	})
}

// upsertTeam writes one teams row for a directory group. Keyed by
// (connector_id, external_id) so re-running the sync is idempotent.
func upsertTeam(tx *gorm.DB, workspaceID, connectorID string, id *access.Identity, now interface{}) error {
	var existing models.Team
	err := tx.Where("connector_id = ? AND external_id = ?", connectorID, id.ExternalID).First(&existing).Error
	if err == nil {
		updates := map[string]interface{}{
			"name":       id.DisplayName,
			"updated_at": now,
		}
		return tx.Model(&existing).Updates(updates).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	row := &models.Team{
		ID:          newEntitlementID(),
		WorkspaceID: workspaceID,
		Name:        id.DisplayName,
		ExternalID:  id.ExternalID,
		ConnectorID: connectorID,
	}
	return tx.Create(row).Error
}

// upsertTeamMember writes one team_members row for a directory
// user. Keyed by (connector_id, external_id) so re-running the
// sync is idempotent.
func upsertTeamMember(tx *gorm.DB, workspaceID, connectorID string, id *access.Identity, now interface{}) error {
	var existing models.TeamMember
	err := tx.Where("connector_id = ? AND external_id = ?", connectorID, id.ExternalID).First(&existing).Error
	if err == nil {
		updates := map[string]interface{}{
			"display_name": id.DisplayName,
			"email":        id.Email,
			"status":       id.Status,
			"updated_at":   now,
		}
		return tx.Model(&existing).Updates(updates).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	row := &models.TeamMember{
		ID:          newEntitlementID(),
		TeamID:      "", // resolved by a later policy / group-membership pass
		UserID:      "", // resolved by a later identity-link pass
		ExternalID:  id.ExternalID,
		ConnectorID: connectorID,
		DisplayName: id.DisplayName,
		Email:       id.Email,
		Status:      id.Status,
	}
	_ = workspaceID // reserved for future scoping changes
	return tx.Create(row).Error
}

// resolveManagerLinks runs the second sync pass: for every user with
// a non-empty Identity.ManagerID, look up the corresponding
// team_members row (scoped to this connector) and write its ID
// into team_members.manager_id.
func resolveManagerLinks(ctx context.Context, db *gorm.DB, connectorID string, users []*access.Identity, now interface{}) error {
	if len(users) == 0 {
		return nil
	}
	// Pre-build an external-id → internal-id index so we do one
	// SELECT per connector instead of one per user.
	var existing []models.TeamMember
	if err := db.WithContext(ctx).
		Where("connector_id = ?", connectorID).
		Find(&existing).Error; err != nil {
		return err
	}
	idx := make(map[string]string, len(existing))
	for _, m := range existing {
		idx[m.ExternalID] = m.ID
	}
	for _, u := range users {
		if u == nil || u.ManagerID == "" {
			continue
		}
		managerInternal, ok := idx[u.ManagerID]
		if !ok {
			// Manager hasn't been ingested yet (eventually
			// consistent directory). Leave the link empty — the
			// next sync pass will fill it.
			continue
		}
		userInternal, ok := idx[u.ExternalID]
		if !ok {
			continue
		}
		if err := db.WithContext(ctx).
			Model(&models.TeamMember{}).
			Where("id = ?", userInternal).
			Updates(map[string]interface{}{
				"manager_id": managerInternal,
				"updated_at": now,
			}).Error; err != nil {
			return err
		}
	}
	return nil
}

// persistSyncState writes / upserts an access_sync_state row for
// the (connector_id, identity) pair. Called once at the end of a
// successful sync so the next probe can read the new checkpoint
// and identity_count. `now` is threaded from the caller so the
// row's updated_at column is driven by the same clock the rest of
// the sync uses — the IdentitySyncScheduler keys staleness off
// updated_at, so a deterministic timestamp keeps that signal
// testable and consistent with sibling helpers (upsertTeam,
// upsertTeamMember, resolveManagerLinks).
func persistSyncState(ctx context.Context, db *gorm.DB, connectorID, checkpoint string, count int, now interface{}) error {
	var existing models.AccessSyncState
	err := db.WithContext(ctx).
		Where("connector_id = ? AND kind = ?", connectorID, models.SyncStateKindIdentity).
		First(&existing).Error
	if err == nil {
		updates := map[string]interface{}{
			"delta_link":     checkpoint,
			"identity_count": count,
			"updated_at":     now,
		}
		return db.WithContext(ctx).Model(&existing).Updates(updates).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	ts, _ := now.(time.Time)
	row := &models.AccessSyncState{
		ID:            newEntitlementID(),
		ConnectorID:   connectorID,
		Kind:          models.SyncStateKindIdentity,
		DeltaLink:     checkpoint,
		IdentityCount: count,
		UpdatedAt:     ts,
	}
	return db.WithContext(ctx).Create(row).Error
}
