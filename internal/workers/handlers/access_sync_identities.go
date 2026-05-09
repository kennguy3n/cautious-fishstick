package handlers

import (
	"context"
	"encoding/json"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// syncIdentitiesPayload is the worker-specific payload shape for an
// access_jobs row of job_type = sync_identities. Empty payloads are
// allowed — the connector falls back to a fresh enumeration.
type syncIdentitiesPayload struct {
	Checkpoint string `json:"checkpoint,omitempty"`
}

// AccessSyncIdentities is the worker handler for sync_identities
// jobs. It calls AccessConnector.SyncIdentities with the optional
// checkpoint from the payload and discards the per-batch identities
// — the Phase 6 scaffold defers Team / TeamMember persistence to a
// future ApplyImport pass.
//
// Idempotency: re-running this handler against the same job ID is
// a no-op once the job is in a terminal state (the row is already
// completed / failed). The connector itself is responsible for
// idempotent SyncIdentities behaviour (per docs/PROPOSAL §5.4).
func AccessSyncIdentities(ctx context.Context, jc JobContext, jobID string) error {
	return runJob(ctx, jc, jobID, func(ctx context.Context, conn access.AccessConnector, cfg, secrets map[string]interface{}, payload []byte) error {
		var pl syncIdentitiesPayload
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &pl); err != nil {
				return err
			}
		}
		// Phase 6 scaffold: drop the per-batch Identity slice — a
		// later phase wires this to the Team / TeamMember
		// upsert pipeline.
		return conn.SyncIdentities(ctx, cfg, secrets, pl.Checkpoint, func(_ []*access.Identity, _ string) error {
			return nil
		})
	})
}
