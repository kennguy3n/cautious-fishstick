package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// AccessProvisioningService is the service layer for the
// "approved → provisioning → provisioned/provision_failed" leg of the
// request lifecycle, plus active-grant revocation. It is the only place in
// Phase 2 that talks to AccessConnector.ProvisionAccess /
// AccessConnector.RevokeAccess.
//
// The service owns a *gorm.DB and an embedded AccessRequestService so it
// can run state transitions in the same transaction that inserts the
// access_grants row on success.
//
// Connectors are resolved through GetAccessConnector(provider). The
// provider key comes from the access_connectors row identified by
// request.ConnectorID — service code never accepts a free-form provider
// string from callers (that would let an attacker pivot to an unrelated
// connector).
type AccessProvisioningService struct {
	db          *gorm.DB
	requestSvc  *AccessRequestService
	getConnector func(provider string) (AccessConnector, error)
	now         func() time.Time
	newID       func() string
}

// NewAccessProvisioningService returns a new service backed by db. db must
// not be nil. The service constructs its own AccessRequestService with
// matching now / newID hooks so state transitions and grant inserts share
// timestamps inside the same transaction.
func NewAccessProvisioningService(db *gorm.DB) *AccessProvisioningService {
	reqSvc := NewAccessRequestService(db)
	return &AccessProvisioningService{
		db:           db,
		requestSvc:   reqSvc,
		getConnector: GetAccessConnector,
		now:          reqSvc.now,
		newID:        reqSvc.newID,
	}
}

// Provision pushes an approved request out to the upstream provider.
// Lifecycle (per docs/ARCHITECTURE.md §4):
//
//  1. Transition the request approved → provisioning.
//  2. Resolve the access_connectors row by request.ConnectorID and look
//     up the connector instance via GetAccessConnector(provider).
//  3. Call connector.ProvisionAccess. This is the only network I/O in the
//     method.
//  4. On success: transition provisioning → provisioned and INSERT an
//     access_grants row in the same DB transaction.
//  5. On failure: transition provisioning → provision_failed, recording
//     the error in the state-history Reason column.
//
// configRaw / secretsRaw are passed straight through to the connector;
// callers (typically the workflow engine or the API handler) are
// responsible for decrypting credentials before invoking the service.
//
// Provision handles retry transparently — if the request is in
// provision_failed state, callers simply call Provision again. The FSM
// allows provision_failed → provisioning, so the internal transition at
// step 1 succeeds without any caller-side state mutation. Pre-flipping
// the state to "provisioning" before calling Provision is incorrect: the
// FSM will reject "provisioning → provisioning" and return
// ErrInvalidStateTransition.
//
// Failure handling has two distinct paths:
//
//   - Connector returns an error: the upstream change never happened.
//     The request is transitioned provisioning → provision_failed and
//     a retry of Provision is safe and cheap.
//   - Connector returns success but the post-success DB transaction
//     (state flip + access_grants insert) fails: the upstream grant
//     ALREADY EXISTS but our DB has no record of it. We still
//     transition to provision_failed so the documented retry path
//     works. Connectors are required to be idempotent on
//     ProvisionAccess (a re-call with the same grant tuple is a no-op
//     for an already-provisioned grant) — Phase 1 Tier-1 connectors
//     all satisfy this. If a future connector cannot be made
//     idempotent, retries from this path will need explicit upstream
//     reconciliation before the second ProvisionAccess call.
func (s *AccessProvisioningService) Provision(
	ctx context.Context,
	request *models.AccessRequest,
	configRaw map[string]interface{},
	secretsRaw map[string]interface{},
) error {
	if request == nil {
		return fmt.Errorf("%w: request is required", ErrValidation)
	}

	// Resolve the connector first so we fail fast on
	// ErrConnectorNotFound without dirtying state. This means an unknown
	// provider key never leaves the request in "provisioning".
	provider, err := s.lookupProvider(ctx, request.ConnectorID)
	if err != nil {
		return err
	}
	connector, err := s.getConnector(provider)
	if err != nil {
		return err
	}

	// Step into "provisioning". The FSM rejects anything other than
	// "approved → provisioning" so we don't have to defensively check the
	// state here.
	if err := s.requestSvc.transitionRequest(ctx, request.ID, models.RequestStateProvisioning, "", "provisioning started"); err != nil {
		return err
	}

	// The DTO consumed by connectors (access.AccessGrant) is distinct from
	// the persisted models.AccessGrant. UserExternalID is sourced from
	// the request's TargetUserID for now; Phase 4 will resolve the real
	// external ID via identity sync state.
	now := s.now()
	dto := AccessGrant{
		UserExternalID:     request.TargetUserID,
		ResourceExternalID: request.ResourceExternalID,
		Role:               request.Role,
		GrantedAt:          now,
		ExpiresAt:          request.ExpiresAt,
	}

	if provErr := connector.ProvisionAccess(ctx, configRaw, secretsRaw, dto); provErr != nil {
		// Best-effort transition into provision_failed. We surface the
		// original provErr to the caller; if the bookkeeping update
		// itself fails we wrap and return both so log-line correlation
		// stays intact.
		if recordErr := s.requestSvc.transitionRequest(ctx, request.ID, models.RequestStateProvisionFailed, "", truncateErrorReason(provErr)); recordErr != nil {
			return fmt.Errorf("provision failed (%v); also failed to record provision_failed: %w", provErr, recordErr)
		}
		return fmt.Errorf("access: connector provision failed: %w", provErr)
	}

	// Success path: flip state and insert the access_grants row in one
	// transaction so a half-written grant can never exist.
	grantID := s.newID()
	requestID := request.ID
	grant := &models.AccessGrant{
		ID:                 grantID,
		WorkspaceID:        request.WorkspaceID,
		UserID:             request.TargetUserID,
		ConnectorID:        request.ConnectorID,
		ResourceExternalID: request.ResourceExternalID,
		Role:               request.Role,
		RequestID:          &requestID,
		GrantedAt:          now,
		ExpiresAt:          request.ExpiresAt,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, terr := s.requestSvc.TransitionInTx(tx, request.ID, models.RequestStateProvisioned, "", "provision succeeded"); terr != nil {
			return terr
		}
		if cerr := tx.Create(grant).Error; cerr != nil {
			return fmt.Errorf("access: insert access_grant: %w", cerr)
		}
		return nil
	})
	if err != nil {
		// The connector already provisioned access upstream but our DB
		// commit failed (e.g., dropped connection, deadlock, disk full).
		// Without this fallback the request stays in "provisioning"
		// forever — the FSM rejects provisioning → provisioning, so a
		// caller-side retry of Provision would fail with
		// ErrInvalidStateTransition and the upstream grant would leak
		// without a corresponding access_grants row. Transition to
		// provision_failed so the documented retry contract (call
		// Provision again from provision_failed) actually works. See
		// the connector-idempotency note in the Provision godoc.
		reason := "post-provision db commit failed: " + truncateDBErr(err)
		if recordErr := s.requestSvc.transitionRequest(ctx, request.ID, models.RequestStateProvisionFailed, "", reason); recordErr != nil {
			return fmt.Errorf("provision succeeded but db commit failed (%v); also failed to record provision_failed: %w", err, recordErr)
		}
		return fmt.Errorf("access: post-provision db commit failed (connector grant exists upstream, request marked provision_failed): %w", err)
	}
	return nil
}

// Revoke pulls an active grant from the upstream provider. On success
// RevokedAt is set on the grant; the row is preserved (not deleted) so
// audit history stays readable. The caller is responsible for transitioning
// the parent access_request, if any, to "revoked" through
// AccessRequestService.
//
// Revoke is idempotent on the connector side (per AccessConnector
// contract) but NOT idempotent on the model side — calling Revoke on an
// already-revoked grant is a programmer error and surfaces as
// ErrAlreadyRevoked.
//
// Failure handling has three distinct paths:
//
//   - Connector returns an error: the upstream change never happened;
//     the in-memory grant is left alone and a retry is safe.
//   - Connector returns success but the DB UPDATE returns an error:
//     the upstream change happened but our write failed; the in-memory
//     grant is left alone and the wrapped error is returned. Operators
//     reconcile manually.
//   - Connector returns success but the DB UPDATE affects 0 rows
//     (concurrent soft-delete, missing row, etc.): ErrGrantNotFound is
//     returned. The upstream change happened; the in-memory grant is
//     left alone so a caller cannot mistake this for a clean revoke.
func (s *AccessProvisioningService) Revoke(
	ctx context.Context,
	grant *models.AccessGrant,
	configRaw map[string]interface{},
	secretsRaw map[string]interface{},
) error {
	if grant == nil {
		return fmt.Errorf("%w: grant is required", ErrValidation)
	}
	if grant.RevokedAt != nil {
		return ErrAlreadyRevoked
	}

	provider, err := s.lookupProvider(ctx, grant.ConnectorID)
	if err != nil {
		return err
	}
	connector, err := s.getConnector(provider)
	if err != nil {
		return err
	}

	dto := AccessGrant{
		UserExternalID:     grant.UserID,
		ResourceExternalID: grant.ResourceExternalID,
		Role:               grant.Role,
		GrantedAt:          grant.GrantedAt,
		ExpiresAt:          grant.ExpiresAt,
	}

	if revErr := connector.RevokeAccess(ctx, configRaw, secretsRaw, dto); revErr != nil {
		return fmt.Errorf("access: connector revoke failed: %w", revErr)
	}

	now := s.now()
	result := s.db.WithContext(ctx).
		Model(&models.AccessGrant{}).
		Where("id = ?", grant.ID).
		Updates(map[string]interface{}{
			"revoked_at": now,
			"updated_at": now,
		})
	if result.Error != nil {
		return fmt.Errorf("access: update access_grant revoked_at: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		// The connector already revoked upstream — that side effect is
		// irrecoverable. The DB write affected 0 rows, which means the
		// grant either never existed under this ID or was concurrently
		// soft-deleted between the in-memory check and this UPDATE.
		// Returning nil here would lie to the caller (in-memory grant
		// gets RevokedAt stamped, DB stays unchanged), so surface a
		// distinct error that names both conditions and lets operators
		// reconcile manually. Mirrors the RowsAffected == 0 guard in
		// AccessRequestService.TransitionInTx.
		return fmt.Errorf("%w: %s (connector revoke already succeeded upstream)", ErrGrantNotFound, grant.ID)
	}
	grant.RevokedAt = &now
	grant.UpdatedAt = now
	return nil
}

// lookupProvider resolves a connector_id to its provider key by reading
// the access_connectors row. Returns ErrConnectorNotFound when no row
// matches — this matches the registry-layer error so callers see one
// failure mode for "we cannot reach the connector".
func (s *AccessProvisioningService) lookupProvider(ctx context.Context, connectorID string) (string, error) {
	if connectorID == "" {
		return "", fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	var row models.AccessConnector
	if err := s.db.WithContext(ctx).
		Select("provider").
		Where("id = ?", connectorID).
		First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("%w: %s", ErrConnectorNotFound, connectorID)
		}
		return "", fmt.Errorf("access: select access_connector: %w", err)
	}
	return row.Provider, nil
}

// ErrAlreadyRevoked is returned by Revoke when the grant has a non-nil
// RevokedAt. Callers can errors.Is the sentinel and treat it as a
// no-op success or a 409 depending on the call site.
var ErrAlreadyRevoked = errors.New("access: grant already revoked")

// ErrGrantNotFound is returned by Revoke when the post-connector DB
// UPDATE affects zero rows — the grant identified by ID either never
// existed or was concurrently soft-deleted. Callers must NOT treat this
// as a clean revoke, because the connector has already succeeded
// upstream by the time this error fires; the upstream change is real
// even though the DB doesn't reflect it. Operators reconcile by
// re-querying the upstream provider.
var ErrGrantNotFound = errors.New("access: grant not found or already deleted")

// truncateErrorReason caps the Reason string so a verbose connector error
// does not blow up the access_request_state_history.reason column. The
// column is TEXT, so this is a defensive cap rather than a hard limit.
func truncateErrorReason(err error) string {
	if err == nil {
		return ""
	}
	const maxLen = 512
	s := "provision error: " + err.Error()
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// truncateDBErr returns the err.Error() string capped at 480 chars so the
// surrounding "post-provision db commit failed: …" prefix still fits
// inside the 512-char audit window enforced by truncateErrorReason for
// the connector-error path. Defensive only — TEXT has no hard limit.
func truncateDBErr(err error) string {
	if err == nil {
		return ""
	}
	const maxLen = 480
	s := err.Error()
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
