// Package handlers contains the access-connector-worker job handlers
// per docs/ARCHITECTURE.md §3 and §10. Each handler is a pure
// function over (ctx, db, registry, jobID) — it loads the
// access_jobs row, resolves the AccessConnector via the registry,
// dispatches the appropriate connector method, and rewrites the job
// status.
//
// The Phase 6 scaffold defers Redis-backed queueing to a later
// phase: the handlers are exercised by directly invoking them with
// a job ID. The scaffold persists every state transition through
// access_jobs so a future queue rewrite is a drop-in.
//
// All handlers share the same lifecycle:
//
//  1. Load the access_jobs row by ID.
//  2. Mark the row running (with started_at = now).
//  3. Resolve the AccessConnector by provider via
//     access.GetAccessConnector. The registry holds a single
//     connector instance per provider; secrets / config are passed
//     through as the per-job blob.
//  4. Decode the connector's (config, secrets) maps. Phase 6 keeps
//     the credential-decryption pipeline a stub — production
//     decryption lives in cmd/ztna-api / cmd/access-connector-worker
//     and is wired in via the JobContext callbacks.
//  5. Dispatch the connector method.
//  6. Rewrite status to completed (success) or failed
//     (last_error = err.Error()), with completed_at = now.
//
// The shared lifecycle is implemented in `runJob` so each handler
// only owns the dispatch step.
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

// ConnectorResolver is the narrow contract handlers use to fetch
// the AccessConnector for a given provider. The production
// implementation is access.GetAccessConnector; tests override it
// to inject a MockAccessConnector without touching the package
// registry.
type ConnectorResolver func(provider string) (access.AccessConnector, error)

// ConnectorAccessor is the narrow contract handlers use to load the
// access_connectors row for a job. The production implementation
// reads the row through the supplied DB; tests override it to pin
// (config, secrets) without touching the DB.
type ConnectorAccessor func(ctx context.Context, db *gorm.DB, connectorID string) (provider string, config, secrets map[string]interface{}, err error)

// JobContext bundles the dependencies a handler needs. Every field
// is required; nil fields surface as ErrMissingDependency from
// runJob.
type JobContext struct {
	DB        *gorm.DB
	Resolve   ConnectorResolver
	LoadConn  ConnectorAccessor
	Now       func() time.Time
}

// ErrMissingDependency surfaces when a handler runs with a partial
// JobContext.
var ErrMissingDependency = errors.New("handlers: job context missing dependencies")

// DefaultLoadConnector reads the access_connectors row by id and
// returns the provider plus the decoded config / credentials. The
// scaffold treats the encrypted credentials column as already-
// decrypted JSON so tests can exercise the dispatch logic without
// the production credential-manager wiring.
func DefaultLoadConnector(ctx context.Context, db *gorm.DB, connectorID string) (string, map[string]interface{}, map[string]interface{}, error) {
	var conn models.AccessConnector
	if err := db.WithContext(ctx).Where("id = ?", connectorID).First(&conn).Error; err != nil {
		return "", nil, nil, fmt.Errorf("handlers: load connector %s: %w", connectorID, err)
	}
	cfg := map[string]interface{}{}
	if len(conn.Config) > 0 {
		if err := json.Unmarshal(conn.Config, &cfg); err != nil {
			return "", nil, nil, fmt.Errorf("handlers: decode config for %s: %w", connectorID, err)
		}
	}
	secrets := map[string]interface{}{}
	if conn.Credentials != "" {
		// Phase 6 scaffold: decryption is wired by the production
		// binary. The default loader treats the column as a JSON
		// blob so unit tests can seed plaintext secrets directly.
		if err := json.Unmarshal([]byte(conn.Credentials), &secrets); err != nil {
			return "", nil, nil, fmt.Errorf("handlers: decode credentials for %s: %w", connectorID, err)
		}
	}
	return conn.Provider, cfg, secrets, nil
}

// runJob is the shared lifecycle every handler invokes. dispatch is
// the per-handler dispatch step that calls the connector method
// after the (provider, config, secrets) triple has been resolved.
//
// runJob intentionally rewrites the status row inside a fresh
// transaction per state transition (pending → running, then
// running → completed | failed). This mirrors the SN360 worker
// pattern: a crash mid-dispatch leaves the row in `running`, which
// the next sweeper restarts via its own pending probe.
func runJob(ctx context.Context, jc JobContext, jobID string, dispatch func(ctx context.Context, conn access.AccessConnector, config, secrets map[string]interface{}, payload []byte) error) error {
	if jc.DB == nil || jc.Resolve == nil || jc.LoadConn == nil {
		return ErrMissingDependency
	}
	if jc.Now == nil {
		jc.Now = time.Now
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

	dispatchErr := dispatch(ctx, conn, cfg, secrets, []byte(job.Payload))
	return finalize(ctx, jc, jobID, dispatchErr)
}

// finalize rewrites the job row with completed_at = now and the
// terminal status (completed | failed). dispatchErr drives the
// last_error column; nil err is success.
func finalize(ctx context.Context, jc JobContext, jobID string, dispatchErr error) error {
	now := jc.Now()
	updates := map[string]interface{}{
		"completed_at": &now,
	}
	if dispatchErr == nil {
		updates["status"] = models.AccessJobStatusCompleted
		updates["last_error"] = ""
	} else {
		updates["status"] = models.AccessJobStatusFailed
		updates["last_error"] = dispatchErr.Error()
	}
	if err := jc.DB.WithContext(ctx).
		Model(&models.AccessJob{}).
		Where("id = ?", jobID).
		Updates(updates).Error; err != nil {
		// Surface the rewrite failure first; if the dispatch also
		// failed, callers get the dispatch error elsewhere via the
		// failed row.
		return fmt.Errorf("handlers: finalize: %w", err)
	}
	return dispatchErr
}
