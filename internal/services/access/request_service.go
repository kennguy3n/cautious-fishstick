package access

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// AccessRequestService is the service layer for the access_requests +
// access_request_state_history tables. It owns the single source of truth
// for state transitions: every read-then-write is wrapped in a DB
// transaction and gated by Transition() so the FSM and the audit trail
// can never diverge.
//
// The service does NOT call connectors directly. Provisioning is handled
// by AccessProvisioningService, which transitions the request through
// "approved → provisioning → provisioned/provision_failed".
type AccessRequestService struct {
	db *gorm.DB
	// now is overridable in tests so we can pin CreatedAt timestamps in
	// assertions. Defaults to time.Now in NewAccessRequestService.
	now func() time.Time
	// newID is overridable in tests so we can pin generated IDs. Defaults
	// to a crockford-base32 ULID in NewAccessRequestService.
	newID func() string
}

// NewAccessRequestService returns a new service backed by db. db must not
// be nil.
func NewAccessRequestService(db *gorm.DB) *AccessRequestService {
	return &AccessRequestService{
		db:    db,
		now:   time.Now,
		newID: newULID,
	}
}

// CreateAccessRequestInput is the input contract for CreateRequest. All
// string fields except Justification are required; ExpiresAt is optional
// and may be nil for "no expiry" (admins can still revoke).
type CreateAccessRequestInput struct {
	WorkspaceID        string
	RequesterUserID    string
	TargetUserID       string
	ConnectorID        string
	ResourceExternalID string
	Role               string
	Justification      string
	ExpiresAt          *time.Time
}

// Sentinel errors for the request service. Wrapped with fmt.Errorf so
// callers can errors.Is them without depending on message formats.
var (
	// ErrValidation is returned when CreateRequest input is missing a
	// required field or otherwise malformed.
	ErrValidation = errors.New("access: validation failed")

	// ErrRequestNotFound is returned by Approve / Deny / Cancel when the
	// supplied request ID does not match a row.
	ErrRequestNotFound = errors.New("access: request not found")
)

// CreateRequest validates input, generates a ULID, persists a new
// access_requests row in RequestStateRequested, and emits the initial
// "" → "requested" history row. All writes happen in a single transaction
// so a partial failure leaves no orphaned rows.
//
// CreateRequest does NOT enrich RiskScore — that is the AI agent's job in
// Phase 4. Risk-score columns are populated by callers that already have
// the score in hand (or left empty until enrichment).
func (s *AccessRequestService) CreateRequest(ctx context.Context, in CreateAccessRequestInput) (*models.AccessRequest, error) {
	if err := validateCreateRequest(in); err != nil {
		return nil, err
	}

	now := s.now()
	req := &models.AccessRequest{
		ID:                 s.newID(),
		WorkspaceID:        in.WorkspaceID,
		RequesterUserID:    in.RequesterUserID,
		TargetUserID:       in.TargetUserID,
		ConnectorID:        in.ConnectorID,
		ResourceExternalID: in.ResourceExternalID,
		Role:               in.Role,
		Justification:      in.Justification,
		State:              models.RequestStateRequested,
		ExpiresAt:          in.ExpiresAt,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	history := &models.AccessRequestStateHistory{
		ID:          s.newID(),
		RequestID:   req.ID,
		FromState:   "",
		ToState:     models.RequestStateRequested,
		ActorUserID: in.RequesterUserID,
		Reason:      "request created",
		CreatedAt:   now,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(req).Error; err != nil {
			return fmt.Errorf("access: insert access_request: %w", err)
		}
		if err := tx.Create(history).Error; err != nil {
			return fmt.Errorf("access: insert access_request_state_history: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ApproveRequest moves a request from "requested" to "approved", recording
// the actor and reason in access_request_state_history. The transition is
// validated by the FSM; an attempt to approve from any non-"requested"
// state returns ErrInvalidStateTransition.
func (s *AccessRequestService) ApproveRequest(ctx context.Context, requestID, actorUserID, reason string) error {
	return s.transitionRequest(ctx, requestID, models.RequestStateApproved, actorUserID, reason)
}

// DenyRequest moves a request from "requested" to "denied". Terminal — once
// denied, the request can only be re-created.
func (s *AccessRequestService) DenyRequest(ctx context.Context, requestID, actorUserID, reason string) error {
	return s.transitionRequest(ctx, requestID, models.RequestStateDenied, actorUserID, reason)
}

// CancelRequest moves a request to "cancelled". Legal from "requested"
// (requester pulled the ask) and from "approved" (approval rescinded
// before provisioning started). Not legal once provisioning is in flight.
func (s *AccessRequestService) CancelRequest(ctx context.Context, requestID, actorUserID, reason string) error {
	return s.transitionRequest(ctx, requestID, models.RequestStateCancelled, actorUserID, reason)
}

// transitionRequest is the shared implementation behind Approve / Deny /
// Cancel and Phase-2-internal callers. It runs in a DB transaction:
//
//  1. SELECT the row by ID.
//  2. Validate the transition through the FSM.
//  3. UPDATE State + UpdatedAt.
//  4. INSERT a state-history row.
//
// Callers that need to do extra work in the same transaction (e.g.
// AccessProvisioningService.Provision needs to insert an access_grants
// row) call TransitionInTx instead.
func (s *AccessRequestService) transitionRequest(ctx context.Context, requestID, toState, actorUserID, reason string) error {
	if requestID == "" {
		return fmt.Errorf("%w: request id is required", ErrValidation)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		_, err := s.TransitionInTx(tx, requestID, toState, actorUserID, reason)
		return err
	})
}

// TransitionInTx executes a state transition inside an existing
// transaction. Returns the post-update request so callers can chain more
// writes (e.g. AccessProvisioningService.Provision adds an access_grants
// row in the same tx as the "provisioning → provisioned" flip).
//
// The supplied tx must be a *gorm.DB inside Transaction(); passing the
// service's outer DB will work but loses atomicity.
//
// The UPDATE uses the previously-read state as an optimistic lock
// (compare-and-set on the `state` column). If two transactions race on
// the same request — both reading "requested", both passing FSM
// validation — exactly one UPDATE will match. The loser sees
// RowsAffected == 0 and is rejected with ErrInvalidStateTransition,
// preventing a denied request from being silently overwritten by a
// concurrent approve (or vice-versa) under READ COMMITTED isolation.
func (s *AccessRequestService) TransitionInTx(tx *gorm.DB, requestID, toState, actorUserID, reason string) (*models.AccessRequest, error) {
	var req models.AccessRequest
	if err := tx.Where("id = ?", requestID).First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrRequestNotFound, requestID)
		}
		return nil, fmt.Errorf("access: select access_request: %w", err)
	}
	if err := Transition(req.State, toState); err != nil {
		return nil, err
	}

	now := s.now()
	fromState := req.State
	req.State = toState
	req.UpdatedAt = now

	result := tx.Model(&models.AccessRequest{}).
		Where("id = ? AND state = ?", req.ID, fromState).
		Updates(map[string]interface{}{
			"state":      toState,
			"updated_at": now,
		})
	if result.Error != nil {
		return nil, fmt.Errorf("access: update access_request state: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf(
			"%w: request %s was concurrently modified (expected state %q)",
			ErrInvalidStateTransition, req.ID, fromState,
		)
	}

	history := &models.AccessRequestStateHistory{
		ID:          s.newID(),
		RequestID:   req.ID,
		FromState:   fromState,
		ToState:     toState,
		ActorUserID: actorUserID,
		Reason:      reason,
		CreatedAt:   now,
	}
	if err := tx.Create(history).Error; err != nil {
		return nil, fmt.Errorf("access: insert access_request_state_history: %w", err)
	}

	return &req, nil
}

// validateCreateRequest enforces the "all required fields present" contract
// for CreateRequest. Errors wrap ErrValidation so callers can errors.Is
// them and surface 4xx without coupling to the message format.
func validateCreateRequest(in CreateAccessRequestInput) error {
	switch {
	case in.WorkspaceID == "":
		return fmt.Errorf("%w: workspace_id is required", ErrValidation)
	case in.RequesterUserID == "":
		return fmt.Errorf("%w: requester_user_id is required", ErrValidation)
	case in.TargetUserID == "":
		return fmt.Errorf("%w: target_user_id is required", ErrValidation)
	case in.ConnectorID == "":
		return fmt.Errorf("%w: connector_id is required", ErrValidation)
	case in.ResourceExternalID == "":
		return fmt.Errorf("%w: resource_external_id is required", ErrValidation)
	case in.Role == "":
		return fmt.Errorf("%w: role is required", ErrValidation)
	}
	return nil
}

// newULID generates a 26-character Crockford-base32 ULID. We use
// crypto/rand as the entropy source so concurrent calls in the same
// millisecond produce distinct IDs.
//
// Exposed as a package-private function (rather than inlined) so it can be
// swapped from tests via NewAccessRequestService -> s.newID.
func newULID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
