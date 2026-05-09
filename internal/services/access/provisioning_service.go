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
		return err
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
	if err := s.db.WithContext(ctx).
		Model(&models.AccessGrant{}).
		Where("id = ?", grant.ID).
		Updates(map[string]interface{}{
			"revoked_at": now,
			"updated_at": now,
		}).Error; err != nil {
		return fmt.Errorf("access: update access_grant revoked_at: %w", err)
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
