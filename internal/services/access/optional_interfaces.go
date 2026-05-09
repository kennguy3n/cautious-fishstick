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

// AccessAuditor is implemented by connectors that can stream sign-in / access
// audit events back into the audit pipeline.
type AccessAuditor interface {
	FetchAccessAuditLogs(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		since time.Time,
		handler func(batch []AuditEvent) error,
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
