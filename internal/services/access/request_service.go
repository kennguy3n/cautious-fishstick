package access

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// RiskAssessor is the narrow interface AccessRequestService uses to
// score a fresh request through the Phase 4 AI agent. The production
// implementation lives in internal/pkg/aiclient (an *AIClient wrapped
// in AssessRiskWithFallback); tests substitute a stub via this
// interface.
//
// The contract is: given a JSON-serialisable payload, return a
// RiskScore in {"low", "medium", "high"} and an optional list of
// RiskFactors. The ok return distinguishes "AI returned this" from
// "AI was unreachable, fallback used" so callers can audit which
// path fired.
type RiskAssessor interface {
	AssessRequestRisk(ctx context.Context, payload interface{}) (riskScore string, riskFactors []string, ok bool)
}

// AccessRequestService is the service layer for the access_requests +
// access_request_state_history tables. It owns the single source of truth
// for state transitions: every read-then-write is wrapped in a DB
// transaction and gated by Transition() so the FSM and the audit trail
// can never diverge.
//
// The service does NOT call connectors directly. Provisioning is handled
// by AccessProvisioningService, which transitions the request through
// "approved → provisioning → provisioned/provision_failed".
//
// Phase 4 wires an optional RiskAssessor in. CreateRequest enriches
// the new row with the assessor's response when configured, and uses
// the score to pick a downstream workflow lane (low → self-service
// auto-approve, medium → manager approval, high → security review).
// A nil assessor disables AI scoring; the row is persisted with an
// empty RiskScore and the caller's existing workflow logic runs
// unchanged.
type AccessRequestService struct {
	db          *gorm.DB
	riskAssessor RiskAssessor
	// now is overridable in tests so we can pin CreatedAt timestamps in
	// assertions. Defaults to time.Now in NewAccessRequestService.
	now func() time.Time
	// newID is overridable in tests so we can pin generated IDs. Defaults
	// to a crockford-base32 ULID in NewAccessRequestService.
	newID func() string
}

// NewAccessRequestService returns a new service backed by db. db must not
// be nil. The RiskAssessor hook is unset; callers wire one in via
// SetRiskAssessor when AI scoring is enabled.
func NewAccessRequestService(db *gorm.DB) *AccessRequestService {
	return &AccessRequestService{
		db:    db,
		now:   time.Now,
		newID: newULID,
	}
}

// SetRiskAssessor wires an AI-driven risk assessor onto the service.
// nil disables risk scoring (no rows get RiskScore populated).
// Callers (typically cmd/ztna-api/main.go) call this once at boot;
// it is NOT safe to call SetRiskAssessor concurrently with
// CreateRequest.
func (s *AccessRequestService) SetRiskAssessor(r RiskAssessor) {
	s.riskAssessor = r
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

	// Phase 4 AI scoring. The assessor is best-effort: a missing
	// assessor or an unreachable agent leaves RiskScore empty (when
	// no assessor is wired) or stamps the fallback score from the
	// pkg/aiclient.AssessRiskWithFallback helper. We never roll back
	// the request because of an AI failure — per PROPOSAL §5.3 AI is
	// decision-support, not on the critical path.
	if s.riskAssessor != nil {
		score, factors, _ := s.riskAssessor.AssessRequestRisk(ctx, riskAssessmentPayload{
			WorkspaceID:        req.WorkspaceID,
			RequesterUserID:    req.RequesterUserID,
			TargetUserID:       req.TargetUserID,
			ConnectorID:        req.ConnectorID,
			ResourceExternalID: req.ResourceExternalID,
			Role:               req.Role,
			Justification:      req.Justification,
		})
		if score != "" {
			req.RiskScore = score
			update := map[string]interface{}{"risk_score": score}
			if len(factors) > 0 {
				if b, mErr := json.Marshal(factors); mErr == nil {
					req.RiskFactors = datatypes.JSON(b)
					update["risk_factors"] = datatypes.JSON(b)
				}
			}
			if uerr := s.db.WithContext(ctx).
				Model(&models.AccessRequest{}).
				Where("id = ?", req.ID).
				Updates(update).Error; uerr != nil {
				// Per PROPOSAL §5.3 the AI agent is decision-support,
				// not on the request critical path. Log the persist
				// failure here (operators care about it) and return
				// the in-memory request with the score populated so
				// the caller can act on it. The DB row stays without
				// risk_score — the worst case is a stale read on the
				// admin UI, not a stuck request.
				log.Printf("access: failed to persist risk_score for request %s: %v", req.ID, uerr)
				return req, nil
			}
		}
	}

	return req, nil
}

// riskAssessmentPayload is the shape AccessRequestService passes to
// RiskAssessor.AssessRequestRisk. Kept small and stable: the AI
// agent contract documented in docs/overview.md §7 reads exactly
// these fields.
type riskAssessmentPayload struct {
	WorkspaceID        string `json:"workspace_id"`
	RequesterUserID    string `json:"requester_user_id"`
	TargetUserID       string `json:"target_user_id"`
	ConnectorID        string `json:"connector_id"`
	ResourceExternalID string `json:"resource_external_id"`
	Role               string `json:"role,omitempty"`
	Justification      string `json:"justification,omitempty"`
}

// SuggestedWorkflowStep returns the workflow step type that best
// matches risk per PROPOSAL §5.3. The mapping is:
//
//	low    → auto_approve
//	medium → manager_approval
//	high   → manager_approval (until Phase 6 introduces the
//	         security_review step type; today we route to manager
//	         approval rather than auto-approving high-risk requests)
//	""     → manager_approval (no AI score → conservative default)
//
// Callers (typically the WorkflowService) consult this when the
// matching workflow row's Steps array is missing — it is NOT a
// substitute for an explicit workflow.
func SuggestedWorkflowStep(riskScore string) string {
	switch riskScore {
	case models.RequestRiskLow:
		return models.WorkflowStepAutoApprove
	case models.RequestRiskHigh, models.RequestRiskMedium:
		return models.WorkflowStepManagerApproval
	default:
		return models.WorkflowStepManagerApproval
	}
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

// ListAccessRequestsQuery is the input contract for ListRequests.
// WorkspaceID is required; the pointer fields are wildcard filters
// — nil means "no filter on this dimension". Empty-string filters
// match exact-empty values (rare but possible for role).
type ListAccessRequestsQuery struct {
	WorkspaceID        string
	State              *string
	RequesterUserID    *string
	TargetUserID       *string
	ResourceExternalID *string
}

// ListRequests returns the access_requests rows matching q. Soft-
// deleted rows are excluded (GORM's default scope). Results are
// ordered by CreatedAt descending so the admin UI shows newest
// requests first.
//
// ListRequests is a thin GORM query — it does not run the FSM, does
// not load state-history rows, and does not page. Phase 5 may add
// cursor-based pagination once the per-workspace request volume
// makes that necessary.
func (s *AccessRequestService) ListRequests(ctx context.Context, q ListAccessRequestsQuery) ([]models.AccessRequest, error) {
	if q.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	tx := s.db.WithContext(ctx).Where("workspace_id = ?", q.WorkspaceID)
	if q.State != nil {
		tx = tx.Where("state = ?", *q.State)
	}
	if q.RequesterUserID != nil {
		tx = tx.Where("requester_user_id = ?", *q.RequesterUserID)
	}
	if q.TargetUserID != nil {
		tx = tx.Where("target_user_id = ?", *q.TargetUserID)
	}
	if q.ResourceExternalID != nil {
		tx = tx.Where("resource_external_id = ?", *q.ResourceExternalID)
	}
	var out []models.AccessRequest
	if err := tx.Order("created_at desc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("access: list access_requests: %w", err)
	}
	return out, nil
}

// AccessRequestDetail bundles a request row with its full state-history
// audit trail and, when the request has been provisioned, the
// resulting access_grants row. Returned by GetRequest so the
// GET /access/requests/:id endpoint can serve the canonical
// "request + audit log + grant" view the Admin UI's triage page
// needs without a second round-trip.
//
// Grant is nil when no access_grants row references this request.
// That covers two cases: (a) the request is still pre-provision
// (state=requested / approved without provisioning yet); (b) the
// request was denied / cancelled and no grant was ever created.
type AccessRequestDetail struct {
Request models.AccessRequest                `json:"request"`
History []models.AccessRequestStateHistory  `json:"history"`
Grant   *models.AccessGrant                 `json:"grant,omitempty"`
}

// GetRequest loads a single request by ULID and returns it alongside
// its state-history rows ordered oldest-first plus the associated
// access_grants row (when provisioned). Returns ErrRequestNotFound
// (wrapped) when the request row does not exist; the state-history
// + grant fetches are best-effort SELECTs — DB errors there are
// bubbled up rather than masked as "not found" because that would
// hide reconcilable corruption.
//
// A request can have at most one access_grants row referencing it
// today (Provision is one-shot per request). The lookup is via the
// indexed access_grants.request_id column. If a future workflow
// creates multiple grants per request we return the most-recent
// one — the Admin UI's per-grant timeline lives on a separate
// endpoint.
func (s *AccessRequestService) GetRequest(ctx context.Context, requestID string) (*AccessRequestDetail, error) {
if requestID == "" {
return nil, fmt.Errorf("%w: request id is required", ErrValidation)
}
var req models.AccessRequest
err := s.db.WithContext(ctx).Where("id = ?", requestID).First(&req).Error
if err != nil {
if errors.Is(err, gorm.ErrRecordNotFound) {
return nil, fmt.Errorf("%w: %s", ErrRequestNotFound, requestID)
}
return nil, fmt.Errorf("access: get access_request: %w", err)
}
var history []models.AccessRequestStateHistory
if err := s.db.WithContext(ctx).
Where("request_id = ?", requestID).
Order("created_at asc").
Find(&history).Error; err != nil {
return nil, fmt.Errorf("access: list access_request_state_history: %w", err)
}

detail := &AccessRequestDetail{Request: req, History: history}

// Skip the grant lookup entirely unless the request reached a
// state where Provision could have written an access_grants row.
// Pending / denied / cancelled requests never have a grant, so
// the extra round-trip would always miss — not free, given the
// per-request volume of the Admin UI's triage page.
if requestStateHasGrant(req.State) {
var grant models.AccessGrant
err = s.db.WithContext(ctx).
Where("request_id = ?", requestID).
Order("created_at desc").
First(&grant).Error
switch {
case err == nil:
detail.Grant = &grant
case errors.Is(err, gorm.ErrRecordNotFound):
// Provision succeeded but the grant row is gone (revoked,
// soft-deleted, manually cleaned up). Leave detail.Grant nil.
default:
return nil, fmt.Errorf("access: get access_grant for request: %w", err)
}
}

return detail, nil
}

// requestStateHasGrant reports whether the request lifecycle state
// could possibly have a matching access_grants row. Used by
// GetRequest to avoid an indexed SELECT on every pending/denied
// /access/requests/:id GET.
func requestStateHasGrant(state string) bool {
	switch state {
	case models.RequestStateProvisioning,
		models.RequestStateProvisioned,
		models.RequestStateActive,
		models.RequestStateExpired,
		models.RequestStateRevoked:
		return true
	}
	return false
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
