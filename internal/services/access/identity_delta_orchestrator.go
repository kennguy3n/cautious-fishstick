// Package access — IdentityDeltaSyncOrchestrator.
//
// The worker handler that drives connector identity sync uses two
// connector interfaces:
//
//   - AccessConnector.SyncIdentities (full enumeration)
//   - IdentityDeltaSyncer.SyncIdentitiesDelta (incremental)
//
// The orchestrator below stitches them together with the
// SyncStateService cursor so the worker handler can call a single
// method and get the right behaviour:
//
//  1. If a delta cursor exists for (connector, identity), call
//     SyncIdentitiesDelta with it.
//  2. If that returns ErrDeltaTokenExpired (410 Gone or the
//     provider-specific equivalent), drop the cursor and fall back
//     to a full SyncIdentities pass.
//  3. Persist the new finalDeltaLink on success.
//
// T27 — IdentityDeltaSyncer hardening — adds regression coverage
// that pins this fallback behaviour for the two delta-capable
// providers we care about (Auth0 + Okta) plus the connector-agnostic
// path through the orchestrator itself.
package access

import (
	"context"
	"errors"
	"fmt"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// IdentitySyncCursorStore is the narrow contract the orchestrator
// uses to read / write the persistent delta-link cursor. The
// *SyncStateService satisfies it (with kind="identity" curried in);
// tests substitute an in-memory map.
type IdentitySyncCursorStore interface {
	Get(ctx context.Context, connectorID, kind string) (string, error)
	Set(ctx context.Context, connectorID, kind, deltaLink string) error
}

// IdentityBatchHandler is the per-batch callback the orchestrator
// hands to each underlying connector. The handler MUST tolerate
// receiving the same identity twice across the delta -> full-sync
// fallback path: the platform sweep keys on ExternalID upsert
// semantics so duplicates are harmless but expected.
type IdentityBatchHandler func(batch []*Identity, removedExternalIDs []string) error

// IdentityDeltaSyncOrchestrator coordinates the delta -> full-sync
// fallback path for a single connector run. Construct with
// NewIdentityDeltaSyncOrchestrator and call Run from the worker
// handler.
type IdentityDeltaSyncOrchestrator struct {
	cursors IdentitySyncCursorStore
}

// NewIdentityDeltaSyncOrchestrator returns a new orchestrator. Pass
// in the SyncStateService (or any IdentitySyncCursorStore
// implementation).
func NewIdentityDeltaSyncOrchestrator(cursors IdentitySyncCursorStore) *IdentityDeltaSyncOrchestrator {
	return &IdentityDeltaSyncOrchestrator{cursors: cursors}
}

// SyncResult is the per-run summary the orchestrator returns so
// callers can surface delta-vs-full lifecycle metrics in their
// worker logs.
type SyncResult struct {
	// Mode is "delta", "delta_then_full_fallback", or "full"
	// depending on which path the orchestrator actually took.
	Mode string
	// Batches counts every handler invocation across all phases of
	// the run.
	Batches int
	// IdentitiesSeen is the cumulative count of identities
	// surfaced through the handler. Removed IDs are NOT counted.
	IdentitiesSeen int
	// FinalDeltaLink is the cursor the orchestrator persisted on
	// success. Empty means the provider didn't surface a cursor on
	// this run; the next call will fall back to full again.
	FinalDeltaLink string
}

// Run drives the connector's identity sync with the delta -> full
// fallback semantics described in the package comment. handler MUST
// NOT be nil. config/secrets are passed through to the connector
// verbatim.
func (o *IdentityDeltaSyncOrchestrator) Run(
	ctx context.Context,
	connectorID string,
	connector AccessConnector,
	configRaw, secretsRaw map[string]interface{},
	handler IdentityBatchHandler,
) (*SyncResult, error) {
	if o == nil || o.cursors == nil {
		return nil, errors.New("access: IdentityDeltaSyncOrchestrator is not wired (nil cursor store)")
	}
	if connector == nil {
		return nil, errors.New("access: connector is required")
	}
	if handler == nil {
		return nil, errors.New("access: handler is required")
	}
	if connectorID == "" {
		return nil, fmt.Errorf("%w: connector_id is required", ErrValidation)
	}

	deltaSyncer, _ := connector.(IdentityDeltaSyncer)
	result := &SyncResult{}

	cursor, err := o.cursors.Get(ctx, connectorID, models.SyncStateKindIdentity)
	if err != nil {
		return nil, fmt.Errorf("access: orchestrator: cursor get: %w", err)
	}

	// Delta path: only when the connector implements the optional
	// interface AND we have a stored cursor. Without a cursor the
	// connector's "delta from epoch" semantics vary too widely —
	// the platform always begins with a full sync to make the
	// first run deterministic.
	if deltaSyncer != nil && cursor != "" {
		mode := "delta"
		finalLink, err := o.runDelta(ctx, deltaSyncer, configRaw, secretsRaw, cursor, handler, result)
		if err == nil {
			result.Mode = mode
			result.FinalDeltaLink = finalLink
			if persistErr := o.cursors.Set(ctx, connectorID, models.SyncStateKindIdentity, finalLink); persistErr != nil {
				return result, fmt.Errorf("access: orchestrator: cursor set: %w", persistErr)
			}
			return result, nil
		}
		if !errors.Is(err, ErrDeltaTokenExpired) {
			return result, fmt.Errorf("access: orchestrator: delta sync: %w", err)
		}
		// 410 Gone (or provider-specific equivalent). Drop the
		// stored cursor and fall through to the full-sync path.
		if dropErr := o.cursors.Set(ctx, connectorID, models.SyncStateKindIdentity, ""); dropErr != nil {
			return result, fmt.Errorf("access: orchestrator: drop expired cursor: %w", dropErr)
		}
		result.Mode = "delta_then_full_fallback"
	} else {
		result.Mode = "full"
	}

	// Full sync — either the connector doesn't implement delta, the
	// cursor was empty, or the delta call surfaced ErrDeltaTokenExpired.
	if err := o.runFull(ctx, connector, configRaw, secretsRaw, handler, result); err != nil {
		return result, fmt.Errorf("access: orchestrator: full sync: %w", err)
	}
	// A full sync resets the cursor to whatever the connector's
	// SyncIdentities surfaced as its tail position. SyncIdentities
	// does not return a cursor itself (that's the delta interface's
	// job) so we persist an empty cursor — the next call will hit
	// the delta path on the next provider event when the connector
	// surfaces one.
	if err := o.cursors.Set(ctx, connectorID, models.SyncStateKindIdentity, ""); err != nil {
		return result, fmt.Errorf("access: orchestrator: reset cursor: %w", err)
	}
	return result, nil
}

func (o *IdentityDeltaSyncOrchestrator) runDelta(
	ctx context.Context,
	syncer IdentityDeltaSyncer,
	configRaw, secretsRaw map[string]interface{},
	cursor string,
	handler IdentityBatchHandler,
	result *SyncResult,
) (string, error) {
	return syncer.SyncIdentitiesDelta(ctx, configRaw, secretsRaw, cursor,
		func(batch []*Identity, removed []string, _ string) error {
			result.Batches++
			result.IdentitiesSeen += len(batch)
			return handler(batch, removed)
		},
	)
}

func (o *IdentityDeltaSyncOrchestrator) runFull(
	ctx context.Context,
	connector AccessConnector,
	configRaw, secretsRaw map[string]interface{},
	handler IdentityBatchHandler,
	result *SyncResult,
) error {
	return connector.SyncIdentities(ctx, configRaw, secretsRaw, "",
		func(batch []*Identity, _ string) error {
			result.Batches++
			result.IdentitiesSeen += len(batch)
			return handler(batch, nil)
		},
	)
}
