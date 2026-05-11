package access

import (
	"context"
	"time"
)

// IdentityDeltaSyncer is implemented by connectors that can stream incremental
// identity changes (Microsoft Graph delta query, Okta event hooks, Auth0
// log-stream, ...).
//
// Semantics mirror the SN360 EmployeeDeltaSyncer pattern:
//
//   - The handler is invoked once per provider page.
//   - removedExternalIDs lets the caller tombstone identities directly without
//     a separate enumeration pass.
//   - The very last page sets a non-empty finalDeltaLink and an empty nextLink.
//     Callers persist finalDeltaLink in access_sync_state and feed it back on
//     the next sync.
//   - When the provider rejects the supplied deltaLink (HTTP 410 Gone for
//     Microsoft Graph, expired token for Okta) implementations MUST return
//     ErrDeltaTokenExpired so the service drops the stored link and falls
//     back to a full enumeration.
type IdentityDeltaSyncer interface {
	SyncIdentitiesDelta(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		deltaLink string,
		handler func(batch []*Identity, removedExternalIDs []string, nextLink string) error,
	) (finalDeltaLink string, err error)
}

// GroupSyncer is implemented by connectors that expose groups / teams as a
// first-class entity separate from users (Microsoft 365 unified groups, Google
// Workspace groups, Okta groups, ...).
type GroupSyncer interface {
	CountGroups(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (int, error)

	SyncGroups(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		checkpoint string,
		handler func(batch []*Identity, nextCheckpoint string) error,
	) error

	SyncGroupMembers(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		groupExternalID string,
		checkpoint string,
		handler func(memberExternalIDs []string, nextCheckpoint string) error,
	) error
}

// DefaultAuditPartition is the partition key single-endpoint connectors
// (and the legacy single-cursor contract) emit when they call the
// AccessAuditor handler.
const DefaultAuditPartition = ""

// AccessAuditor is implemented by connectors that can stream sign-in / access
// audit events back into the audit pipeline.
//
// Semantics:
//
//   - `sincePartitions` maps a partition key to its persisted cursor.
//     A connector MUST look up its own partition keys and treat a
//     missing entry as a zero-time "full backfill" (provider default
//     window). Single-endpoint connectors look up
//     `sincePartitions[DefaultAuditPartition]`. Multi-endpoint
//     connectors (e.g. Microsoft Graph `signIns` and `directoryAudits`)
//     look up their per-endpoint keys.
//   - The handler is invoked once per provider page. Implementations MUST
//     paginate the provider's audit log API and call the handler per page
//     in chronological order so callers can persist `nextSince` as a
//     monotonic cursor.
//   - `nextSince` is the per-partition cursor the caller should persist
//     for `partitionKey` so the next invocation resumes where this one
//     left off. Implementations MUST set nextSince to the timestamp of
//     the newest entry in the batch (or beyond).
//   - `partitionKey` identifies the audit stream the batch came from.
//     Single-endpoint connectors MUST use DefaultAuditPartition.
//     Multi-endpoint connectors MUST use a stable, distinct key per
//     endpoint so the worker can advance each partition's cursor
//     independently. This prevents a fast-moving partition's max
//     timestamp from shadowing a slower partition's progress and causing
//     `$filter ge {inflated}` to skip events on retry after a partial
//     failure.
//   - Implementations MUST honour ctx cancellation between pages.
//   - The handler returning a non-nil error aborts the sync.
type AccessAuditor interface {
	FetchAccessAuditLogs(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		sincePartitions map[string]time.Time,
		handler func(batch []*AuditLogEntry, nextSince time.Time, partitionKey string) error,
	) error
}

// SCIMProvisioner is implemented by connectors that support outbound SCIM v2.0
// push for joiner / mover / leaver flows.
type SCIMProvisioner interface {
	PushSCIMUser(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		user SCIMUser,
	) error

	PushSCIMGroup(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		group SCIMGroup,
	) error

	DeleteSCIMResource(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		resourceType string,
		externalID string,
	) error
}
