package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// AccessReviewService is the service layer for the access_reviews and
// access_review_decisions tables per docs/PROPOSAL.md §6 (Access
// Review Campaigns) and docs/ARCHITECTURE.md §6.
//
// The service owns the campaign lifecycle:
//
//   - StartCampaign creates an access_reviews row (state=open) and an
//     access_review_decisions row per access_grant matching the
//     scope filter. Each decision is created in "pending" state.
//   - SubmitDecision is the reviewer entry-point; it flips a
//     pending row to certify / revoke / escalate and (for revokes)
//     calls AccessProvisioningService.Revoke transactionally.
//   - CloseCampaign finalises the review: any decisions still
//     pending are escalated, and the review state flips to closed.
//   - AutoRevoke walks all "revoke" decisions whose RevokedAt is
//     still nil on the underlying grant and executes the revocations
//     via the provisioning service. Idempotent — already-revoked
//     grants are silently skipped.
//
// AccessReviewService is composed with an AccessProvisioningService;
// callers wire one ProvisioningService instance (which owns the
// connector registry) into both.
type AccessReviewService struct {
	db             *gorm.DB
	provisioningSvc *AccessProvisioningService
	now            func() time.Time
	newID          func() string
}

// NewAccessReviewService returns a service backed by db and the
// provided provisioningSvc. db must not be nil. provisioningSvc may be
// nil for read-only flows (StartCampaign / SubmitDecision with
// non-revoke decisions / CloseCampaign), but AutoRevoke and SubmitDecision-with-
// revoke will fail with ErrProvisioningUnavailable when it is missing.
func NewAccessReviewService(db *gorm.DB, provisioningSvc *AccessProvisioningService) *AccessReviewService {
	now := time.Now
	id := newULID
	if provisioningSvc != nil {
		now = provisioningSvc.now
		id = provisioningSvc.newID
	}
	return &AccessReviewService{
		db:              db,
		provisioningSvc: provisioningSvc,
		now:             now,
		newID:           id,
	}
}

// StartCampaignInput is the input contract for StartCampaign.
// WorkspaceID and Name are required; DueAt is required (a campaign
// without a due date is meaningless). ScopeFilter is optional —
// omitting it (or passing an empty object) enrolls every active grant
// in the workspace.
type StartCampaignInput struct {
	WorkspaceID        string
	Name               string
	DueAt              time.Time
	ScopeFilter        json.RawMessage
	AutoCertifyEnabled bool
}

// Sentinel errors for the review service. Wrapped with fmt.Errorf so
// callers can errors.Is them without depending on message formats.
var (
	// ErrReviewNotFound is returned when the supplied review ID does
	// not match a row in the supplied workspace.
	ErrReviewNotFound = errors.New("access: review not found")

	// ErrReviewClosed is returned by SubmitDecision and AutoRevoke
	// when the target review is closed or cancelled. Reviewers may
	// not submit decisions on a closed campaign.
	ErrReviewClosed = errors.New("access: review is closed")

	// ErrDecisionNotFound is returned by SubmitDecision when the
	// supplied (review_id, grant_id) tuple does not match any row.
	// This means the grant was never enrolled into the campaign;
	// reviewers cannot retroactively add decisions.
	ErrDecisionNotFound = errors.New("access: decision not found")

	// ErrInvalidDecision is returned by SubmitDecision when the
	// supplied decision string is not one of certify / revoke /
	// escalate. Reviewers cannot regress a decision back to
	// "pending".
	ErrInvalidDecision = errors.New("access: invalid decision")

	// ErrProvisioningUnavailable is returned when a revoke decision
	// is submitted but the service was constructed without a
	// provisioningSvc.
	ErrProvisioningUnavailable = errors.New("access: provisioning service unavailable")
)

// StartCampaign creates a new access_reviews row and enumerates every
// matching access_grant into access_review_decisions rows. The match
// is performed by the embedded scopeFilterMatchesGrant helper, which
// understands the same flat key-value JSON shape used elsewhere in
// Phase 3 / Phase 5:
//
//   - "connector_id"  — match AccessGrant.ConnectorID
//   - "user_id"       — match AccessGrant.UserID
//   - "role"          — match AccessGrant.Role
//   - any other key   — ignored (forward-compatibility for Phase 6
//                       fields like resource_category)
//
// The review and the decisions are inserted in a single transaction
// so a partial failure leaves no half-enrolled campaigns. Auto-
// certification is intentionally NOT applied here — the AI agent runs
// out of band and updates rows from "pending" to "certify" on its own
// schedule.
func (s *AccessReviewService) StartCampaign(ctx context.Context, in StartCampaignInput) (*models.AccessReview, []models.AccessReviewDecision, error) {
	if err := validateStartCampaign(in); err != nil {
		return nil, nil, err
	}

	now := s.now()
	review := &models.AccessReview{
		ID:                 s.newID(),
		WorkspaceID:        in.WorkspaceID,
		Name:               in.Name,
		ScopeFilter:        datatypes.JSON(in.ScopeFilter),
		DueAt:              in.DueAt,
		State:              models.ReviewStateOpen,
		AutoCertifyEnabled: in.AutoCertifyEnabled,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	scope, err := parseScopeFilter(in.ScopeFilter)
	if err != nil {
		return nil, nil, err
	}

	var decisions []models.AccessReviewDecision
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(review).Error; err != nil {
			return fmt.Errorf("access: insert access_review: %w", err)
		}

		// Enumerate active grants matching the scope filter. We
		// load every active grant in the workspace and filter in
		// Go, mirroring ImpactResolver: SQLite has no jsonb-contains
		// equivalent and the per-workspace grant set is small enough
		// for in-memory filtering to be acceptable.
		var grants []models.AccessGrant
		q := tx.Where("workspace_id = ? AND revoked_at IS NULL", in.WorkspaceID)
		if v, ok := scope["connector_id"]; ok {
			q = q.Where("connector_id = ?", v)
		}
		if err := q.Find(&grants).Error; err != nil {
			return fmt.Errorf("access: list access_grants: %w", err)
		}

		for i := range grants {
			g := &grants[i]
			if !grantMatchesScope(g, scope) {
				continue
			}
			d := models.AccessReviewDecision{
				ID:        s.newID(),
				ReviewID:  review.ID,
				GrantID:   g.ID,
				Decision:  models.DecisionPending,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Create(&d).Error; err != nil {
				return fmt.Errorf("access: insert access_review_decision: %w", err)
			}
			decisions = append(decisions, d)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return review, decisions, nil
}

// SubmitDecision flips a pending decision row to the supplied state.
//
// The decision row is updated in a short transaction, which then
// commits before any upstream side-effect runs. This mirrors Phase 2's
// AccessProvisioningService.Provision split — connector calls are
// always outside the DB transaction so a slow upstream provider does
// not pin a row-level lock for the duration of an HTTP RTT, and so
// the connection pool does not block under concurrent traffic.
//
// For "revoke" decisions, the grant's upstream side-effect is then
// executed via AccessProvisioningService.Revoke after the decision
// row is committed. If the upstream revoke fails, the decision row
// already says "revoke" but the grant is still active; AutoRevoke is
// the catch-all that re-attempts the upstream revoke until the grant
// is actually torn down.
//
// SubmitDecision is idempotent on certify / escalate — re-submitting
// the same decision is a no-op success. Revoke is NOT idempotent: a
// second revoke against an already-revoked grant returns
// ErrAlreadyRevoked from the provisioning layer.
func (s *AccessReviewService) SubmitDecision(ctx context.Context, reviewID, grantID, decision, decidedBy, reason string) error {
	if reviewID == "" || grantID == "" {
		return fmt.Errorf("%w: review_id and grant_id are required", ErrValidation)
	}
	if !validReviewerDecision(decision) {
		return fmt.Errorf("%w: %q", ErrInvalidDecision, decision)
	}
	if decision == models.DecisionRevoke && s.provisioningSvc == nil {
		return ErrProvisioningUnavailable
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var review models.AccessReview
		if err := tx.Where("id = ?", reviewID).First(&review).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: %s", ErrReviewNotFound, reviewID)
			}
			return fmt.Errorf("access: select access_review: %w", err)
		}
		if review.State != models.ReviewStateOpen {
			return fmt.Errorf("%w: %s (state=%s)", ErrReviewClosed, reviewID, review.State)
		}

		var d models.AccessReviewDecision
		if err := tx.Where("review_id = ? AND grant_id = ?", reviewID, grantID).First(&d).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: review=%s grant=%s", ErrDecisionNotFound, reviewID, grantID)
			}
			return fmt.Errorf("access: select access_review_decision: %w", err)
		}

		now := s.now()
		updates := map[string]interface{}{
			"decision":   decision,
			"decided_by": decidedBy,
			"reason":     reason,
			"decided_at": now,
			"updated_at": now,
		}
		if err := tx.Model(&models.AccessReviewDecision{}).
			Where("id = ?", d.ID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("access: update access_review_decision: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if decision != models.DecisionRevoke {
		return nil
	}

	// Decision committed — now drive the upstream Revoke. We re-load
	// the grant outside the tx because the provisioning service uses
	// its own DB handle (and would also do a fresh load internally).
	var grant models.AccessGrant
	if err := s.db.WithContext(ctx).Where("id = ?", grantID).First(&grant).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: %s", ErrGrantNotFound, grantID)
		}
		return fmt.Errorf("access: select access_grant: %w", err)
	}
	if grant.RevokedAt != nil {
		return nil
	}
	if err := s.provisioningSvc.Revoke(ctx, &grant, nil, nil); err != nil {
		return fmt.Errorf("access: revoke grant via review: %w", err)
	}
	return nil
}

// CloseCampaign flips a review from open → closed. Any decisions still
// pending at close-time are auto-escalated so the row history shows a
// terminal decision for every enrolled grant. CloseCampaign refuses to
// run on a non-open review (ErrReviewClosed) so two concurrent close
// requests can't both think they "closed" the campaign.
func (s *AccessReviewService) CloseCampaign(ctx context.Context, reviewID string) error {
	if reviewID == "" {
		return fmt.Errorf("%w: review_id is required", ErrValidation)
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var review models.AccessReview
		if err := tx.Where("id = ?", reviewID).First(&review).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: %s", ErrReviewNotFound, reviewID)
			}
			return fmt.Errorf("access: select access_review: %w", err)
		}
		if review.State != models.ReviewStateOpen {
			return fmt.Errorf("%w: %s (state=%s)", ErrReviewClosed, reviewID, review.State)
		}

		now := s.now()
		// Auto-escalate any still-pending decisions so the row
		// history shows a terminal decision for every grant.
		if err := tx.Model(&models.AccessReviewDecision{}).
			Where("review_id = ? AND decision = ?", reviewID, models.DecisionPending).
			Updates(map[string]interface{}{
				"decision":   models.DecisionEscalate,
				"reason":     "auto-escalated on campaign close",
				"decided_at": now,
				"updated_at": now,
			}).Error; err != nil {
			return fmt.Errorf("access: auto-escalate pending decisions: %w", err)
		}

		result := tx.Model(&models.AccessReview{}).
			Where("id = ? AND state = ?", reviewID, models.ReviewStateOpen).
			Updates(map[string]interface{}{
				"state":      models.ReviewStateClosed,
				"updated_at": now,
			})
		if result.Error != nil {
			return fmt.Errorf("access: close access_review: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%w: %s (concurrently closed)", ErrReviewClosed, reviewID)
		}
		return nil
	})
}

// AutoRevoke walks every "revoke" decision in the supplied review whose
// underlying grant is still active (RevokedAt IS NULL) and executes
// the revocations via the provisioning service. The method is
// idempotent: running it twice on the same review is a no-op the
// second time because the grants are already revoked.
//
// AutoRevoke is read-mostly with a series of UPDATEs. It does NOT run
// inside a single transaction — each grant's upstream revoke + DB
// UPDATE is its own atomic unit (see AccessProvisioningService.Revoke).
// A connector failure on grant N does not roll back the revocations
// of grants 1..N-1.
func (s *AccessReviewService) AutoRevoke(ctx context.Context, reviewID string) error {
	if reviewID == "" {
		return fmt.Errorf("%w: review_id is required", ErrValidation)
	}
	if s.provisioningSvc == nil {
		return ErrProvisioningUnavailable
	}

	var review models.AccessReview
	if err := s.db.WithContext(ctx).Where("id = ?", reviewID).First(&review).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: %s", ErrReviewNotFound, reviewID)
		}
		return fmt.Errorf("access: select access_review: %w", err)
	}
	// AutoRevoke is allowed on closed campaigns (the close flow may
	// trigger auto-revoke as a follow-up step) but not on cancelled
	// campaigns — a cancelled review explicitly tombstones every
	// outstanding decision.
	if review.State == models.ReviewStateCancelled {
		return fmt.Errorf("%w: %s (state=cancelled)", ErrReviewClosed, reviewID)
	}

	var decisions []models.AccessReviewDecision
	if err := s.db.WithContext(ctx).
		Where("review_id = ? AND decision = ?", reviewID, models.DecisionRevoke).
		Find(&decisions).Error; err != nil {
		return fmt.Errorf("access: list revoke decisions: %w", err)
	}

	for i := range decisions {
		d := &decisions[i]
		var grant models.AccessGrant
		if err := s.db.WithContext(ctx).Where("id = ?", d.GrantID).First(&grant).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return fmt.Errorf("access: select access_grant: %w", err)
		}
		if grant.RevokedAt != nil {
			// Already revoked upstream — nothing to do.
			continue
		}
		if err := s.provisioningSvc.Revoke(ctx, &grant, nil, nil); err != nil {
			if errors.Is(err, ErrAlreadyRevoked) {
				continue
			}
			return fmt.Errorf("access: auto-revoke grant %s: %w", grant.ID, err)
		}
	}
	return nil
}

// validateStartCampaign enforces the "all required fields present"
// contract for StartCampaign. Errors wrap ErrValidation so callers can
// errors.Is them and surface 4xx without coupling to the message format.
func validateStartCampaign(in StartCampaignInput) error {
	switch {
	case in.WorkspaceID == "":
		return fmt.Errorf("%w: workspace_id is required", ErrValidation)
	case in.Name == "":
		return fmt.Errorf("%w: name is required", ErrValidation)
	case in.DueAt.IsZero():
		return fmt.Errorf("%w: due_at is required", ErrValidation)
	}
	return nil
}

// validReviewerDecision reports whether the supplied string is a
// reviewer-eligible decision. Reviewers cannot regress a decision back
// to "pending" — that is the initial state set by StartCampaign.
func validReviewerDecision(d string) bool {
	switch d {
	case models.DecisionCertify, models.DecisionRevoke, models.DecisionEscalate:
		return true
	}
	return false
}

// parseScopeFilter unmarshals a flat scope-filter object into a
// map[string]string. An empty (or nil) selector returns an empty map
// which matches every grant. Malformed filters surface as
// ErrValidation.
func parseScopeFilter(raw json.RawMessage) (map[string]string, error) {
	out := map[string]string{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: invalid scope_filter: %v", ErrValidation, err)
	}
	return out, nil
}

// grantMatchesScope reports whether grant satisfies every key in the
// scope filter. Recognised keys: connector_id, user_id, role.
// Unrecognised keys are ignored (forward-compatibility for Phase 6
// fields like resource_category).
func grantMatchesScope(grant *models.AccessGrant, scope map[string]string) bool {
	if grant == nil {
		return false
	}
	if v, ok := scope["connector_id"]; ok && grant.ConnectorID != v {
		return false
	}
	if v, ok := scope["user_id"]; ok && grant.UserID != v {
		return false
	}
	if v, ok := scope["role"]; ok && grant.Role != v {
		return false
	}
	return true
}
