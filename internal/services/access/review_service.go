package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// AccessReviewService is the service layer for the access_reviews and
// access_review_decisions tables per docs/overview.md §6 (Access
// Review Campaigns) and docs/architecture.md §6.
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
	notifier       ReviewNotifier
	resolver       ReviewerResolver
	automator      ReviewAutomator
	now            func() time.Time
	newID          func() string
}

// ReviewNotifier is the narrow contract AccessReviewService uses to
// fan out "you have pending decisions" notifications. The concrete
// notification.NotificationService satisfies it via a small adapter
// (see notification_adapter.go).
//
// Per docs/internal/PHASES.md Phase 5 exit criteria notifications are
// best-effort — implementations MUST NOT roll back the underlying
// campaign transaction. The interface returns an error only for
// observability; the service ignores it.
type ReviewNotifier interface {
	NotifyReviewersPending(ctx context.Context, reviewID string, decisions []ReviewerPendingDecisionRef) error
}

// ReviewerResolver is the narrow contract AccessReviewService uses to
// look up reviewer assignments per (reviewID, decisions). Phase 5
// has no formal reviewer assignment model — Phase 6 introduces
// access_review_assignees. Tests + dev binaries supply a
// ReviewerResolver stub that returns a fixed reviewer set; callers
// MAY pass nil to skip notification fan-out entirely.
type ReviewerResolver interface {
	ResolveReviewers(ctx context.Context, reviewID string, decisions []models.AccessReviewDecision) ([]ReviewerPendingDecisionRef, error)
}

// ReviewerPendingDecisionRef is the per-(reviewer, grant) tuple the
// review service hands to the notifier. The struct is named "ref"
// to make it obvious it is a wire shape, not a persisted row.
type ReviewerPendingDecisionRef struct {
	ReviewerUserID string
	GrantID        string
	GrantSummary   string
	DueAt          time.Time
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

// SetNotifier wires a ReviewNotifier + ReviewerResolver into the
// service. Both must be non-nil for notifications to fire; passing
// nil for either skips notification fan-out (the dev / test default).
//
// The setter exists instead of constructor injection so the existing
// NewAccessReviewService signature stays stable while Phase 5 adds
// the optional notification path.
func (s *AccessReviewService) SetNotifier(notifier ReviewNotifier, resolver ReviewerResolver) {
	s.notifier = notifier
	s.resolver = resolver
}

// SetReviewAutomator wires a ReviewAutomator onto the service.
// Passing nil disables AI-driven auto-certification — every decision
// stays in pending state for human review. Mirrors the SetNotifier
// pattern: the setter exists instead of constructor injection so the
// existing NewAccessReviewService signature stays stable while Phase
// 5 adds the optional auto-certification path.
//
// Per docs/internal/PHASES.md Phase 5 the wire-in is best-effort: an
// unreachable AI agent leaves every decision pending and the
// campaign proceeds normally.
func (s *AccessReviewService) SetReviewAutomator(automator ReviewAutomator) {
	s.automator = automator
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
//
// StartCampaign opens its own transaction. Callers that need to
// compose the review insert with other writes (e.g. the Phase 5
// CampaignScheduler bumping access_campaign_schedules.NextRunAt in
// the same transaction) should use StartCampaignTx instead and pass
// in their own *gorm.DB.
func (s *AccessReviewService) StartCampaign(ctx context.Context, in StartCampaignInput) (*models.AccessReview, []models.AccessReviewDecision, error) {
	var (
		review    *models.AccessReview
		decisions []models.AccessReviewDecision
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		review, decisions, err = s.StartCampaignTx(ctx, tx, in)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	// AI-driven auto-certification AFTER commit but BEFORE
	// notifications. Auto-certified rows are flipped to
	// decision=certify so the notification fan-out only pings
	// reviewers about the rows that still need human attention.
	// Per PHASES Phase 5 the wire-in is best-effort: an
	// unreachable AI leaves every row pending.
	decisions = s.applyAutoCertification(ctx, review, decisions)
	// Fan-out notifications AFTER commit. Per PHASES Phase 5
	// notifications are best-effort: any error here is logged
	// inside dispatchPendingNotifications and never returned.
	s.dispatchPendingNotifications(ctx, review, filterPendingDecisions(decisions))
	return review, decisions, nil
}

// dispatchPendingNotifications resolves reviewers for the supplied
// decisions and fans out a "pending decisions" notification to each.
// All failures are logged and swallowed — notifications must NOT
// roll back the underlying campaign per PHASES Phase 5.
func (s *AccessReviewService) dispatchPendingNotifications(
	ctx context.Context,
	review *models.AccessReview,
	decisions []models.AccessReviewDecision,
) {
	if s.notifier == nil || s.resolver == nil || review == nil || len(decisions) == 0 {
		return
	}
	refs, err := s.resolver.ResolveReviewers(ctx, review.ID, decisions)
	if err != nil {
		log.Printf("access: review %s: resolve reviewers failed: %v", review.ID, err)
		return
	}
	if len(refs) == 0 {
		return
	}
	if err := s.notifier.NotifyReviewersPending(ctx, review.ID, refs); err != nil {
		log.Printf("access: review %s: notify reviewers failed: %v", review.ID, err)
	}
}

// applyAutoCertification dispatches each pending decision through
// the configured ReviewAutomator and flips matching rows to
// decision=certify, auto_certified=true, decided_at=now. Decisions
// the AI flags as escalate / revoke / unknown are left pending for
// human review.
//
// The function is a no-op (returning decisions unmodified) when:
//
//   - the review is nil, has zero pending decisions, or is not in
//     open state;
//   - AutoCertifyEnabled is false on the review;
//   - no automator is configured.
//
// Each row update is best-effort: a failed UPDATE is logged but does
// not abort the loop. The campaign proceeds with whatever subset of
// rows were successfully auto-certified.
//
// Per docs/internal/PHASES.md Phase 5: AI is decision-support, not critical
// path. AI failures (transport / decode / unrecognised verdict) are
// logged inside AutomateReviewWithFallback and surface here as
// ok=false; we leave the row pending in that case.
func (s *AccessReviewService) applyAutoCertification(
	ctx context.Context,
	review *models.AccessReview,
	decisions []models.AccessReviewDecision,
) []models.AccessReviewDecision {
	if review == nil || len(decisions) == 0 {
		return decisions
	}
	if review.State != models.ReviewStateOpen || !review.AutoCertifyEnabled {
		return decisions
	}
	if s.automator == nil {
		return decisions
	}

	for i := range decisions {
		d := &decisions[i]
		if d.Decision != models.DecisionPending {
			continue
		}
		var grant models.AccessGrant
		if err := s.db.WithContext(ctx).Where("id = ?", d.GrantID).First(&grant).Error; err != nil {
			log.Printf("access: review %s: load grant %s for auto-cert: %v", review.ID, d.GrantID, err)
			continue
		}
		payload := aiclient.ReviewAutomationPayload{
			GrantID:   grant.ID,
			UserID:    grant.UserID,
			Role:      grant.Role,
			Resource:  grant.ResourceExternalID,
			UsageData: snapshotGrantUsage(grant, s.now()),
		}
		verdict, reason, ok := s.automator.AutomateReview(ctx, payload)
		if !ok {
			// AI unreachable / unconfigured / returned an
			// unrecognised verdict; leave the row pending.
			continue
		}
		if verdict != models.DecisionCertify {
			// escalate / revoke verdicts route to human review;
			// the row stays pending so reviewers see it. Phase
			// 6+ may want to flip to escalate state directly,
			// but Phase 5 keeps the human in the loop for
			// anything other than certify.
			continue
		}

		now := s.now()
		updates := map[string]interface{}{
			"decision":       models.DecisionCertify,
			"auto_certified": true,
			"reason":         reason,
			"decided_at":     now,
			"updated_at":     now,
		}
		result := s.db.WithContext(ctx).
			Model(&models.AccessReviewDecision{}).
			Where("id = ? AND decision = ?", d.ID, models.DecisionPending).
			Updates(updates)
		if result.Error != nil {
			log.Printf("access: review %s: update auto-cert decision %s: %v", review.ID, d.ID, result.Error)
			continue
		}
		if result.RowsAffected == 0 {
			// A reviewer beat us to it (raced submitting a
			// decision between StartCampaign commit and the
			// auto-cert pass). Leave the row as the human
			// recorded it.
			continue
		}
		d.Decision = models.DecisionCertify
		d.AutoCertified = true
		d.Reason = reason
		decidedAt := now
		d.DecidedAt = &decidedAt
		d.UpdatedAt = now
	}
	return decisions
}

// filterPendingDecisions returns a slice containing only the rows
// from decisions whose Decision is still "pending". Used to scope
// the post-commit reviewer notification fan-out so reviewers are not
// pinged about rows the AI auto-certified.
func filterPendingDecisions(decisions []models.AccessReviewDecision) []models.AccessReviewDecision {
	out := make([]models.AccessReviewDecision, 0, len(decisions))
	for _, d := range decisions {
		if d.Decision == models.DecisionPending {
			out = append(out, d)
		}
	}
	return out
}

// StartCampaignTx is the transaction-aware variant of StartCampaign.
// All writes (the access_reviews row and every access_review_decisions
// row enumerated from the scope filter) happen on the supplied tx.
// The caller owns the transaction lifecycle: StartCampaignTx never
// commits or rolls back tx, only writes through it. This lets callers
// compose the campaign insert with other writes (e.g. the Phase 5
// CampaignScheduler updating access_campaign_schedules.NextRunAt) so
// the whole unit of work is atomic.
//
// tx must not be nil. If you don't already have a transaction, call
// StartCampaign instead.
func (s *AccessReviewService) StartCampaignTx(ctx context.Context, tx *gorm.DB, in StartCampaignInput) (*models.AccessReview, []models.AccessReviewDecision, error) {
	if tx == nil {
		return nil, nil, errors.New("access: StartCampaignTx: tx is nil")
	}
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

	tx = tx.WithContext(ctx)

	// Use map-mode Create so an explicit AutoCertifyEnabled=false
	// is sent to the DB. With struct-mode Create GORM omits zero
	// values and the column's default:true tag would silently
	// flip the persisted value to true, contradicting the caller.
	// Same applies to State (always non-zero here) but is included
	// for completeness.
	row := map[string]interface{}{
		"id":                   review.ID,
		"workspace_id":         review.WorkspaceID,
		"name":                 review.Name,
		"scope_filter":         review.ScopeFilter,
		"due_at":               review.DueAt,
		"state":                review.State,
		"auto_certify_enabled": review.AutoCertifyEnabled,
		"created_at":           review.CreatedAt,
		"updated_at":           review.UpdatedAt,
	}
	if err := tx.Table((&models.AccessReview{}).TableName()).Create(row).Error; err != nil {
		return nil, nil, fmt.Errorf("access: insert access_review: %w", err)
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
		return nil, nil, fmt.Errorf("access: list access_grants: %w", err)
	}

	var decisions []models.AccessReviewDecision
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
			return nil, nil, fmt.Errorf("access: insert access_review_decision: %w", err)
		}
		decisions = append(decisions, d)
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

// CampaignMetrics is the per-review tally surfaced to the admin
// UI. The struct is the canonical shape both the service and the
// HTTP handler return.
//
// Per docs/internal/PHASES.md Phase 5 exit criteria the platform tracks an
// auto-certification rate so operators can see the AI agent's
// signal-to-noise on a real campaign. AutoCertificationRate is in
// [0.0, 1.0] and is auto_certified / total_decisions. Total of zero
// surfaces as 0.0 (not NaN) to keep callers free of edge cases.
type CampaignMetrics struct {
	ReviewID              string  `json:"review_id"`
	TotalDecisions        int     `json:"total_decisions"`
	AutoCertified         int     `json:"auto_certified"`
	Pending               int     `json:"pending"`
	Certified             int     `json:"certified"`
	Revoked               int     `json:"revoked"`
	Escalated             int     `json:"escalated"`
	AutoCertificationRate float64 `json:"auto_certification_rate"`
}

// GetCampaignMetrics tallies the access_review_decisions rows for the
// supplied review and returns the per-state breakdown plus the
// auto-certification rate. The method is read-only and never opens
// a transaction.
//
// Decisions in the "certify" bucket are split into "manual certify"
// vs "auto certify" using the AutoCertified flag — the AI agent sets
// AutoCertified=true on every row it touches and the rate is
// auto_certified / total_decisions.
//
// Errors:
//   - ErrValidation   — review_id is empty
//   - ErrReviewNotFound — review row does not exist
//   - any other        — DB read failure
func (s *AccessReviewService) GetCampaignMetrics(ctx context.Context, reviewID string) (*CampaignMetrics, error) {
	if reviewID == "" {
		return nil, fmt.Errorf("%w: review_id is required", ErrValidation)
	}
	var review models.AccessReview
	if err := s.db.WithContext(ctx).Where("id = ?", reviewID).First(&review).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrReviewNotFound, reviewID)
		}
		return nil, fmt.Errorf("access: select access_review: %w", err)
	}

	var decisions []models.AccessReviewDecision
	if err := s.db.WithContext(ctx).
		Where("review_id = ?", reviewID).
		Find(&decisions).Error; err != nil {
		return nil, fmt.Errorf("access: list access_review_decisions: %w", err)
	}

	out := &CampaignMetrics{ReviewID: reviewID, TotalDecisions: len(decisions)}
	for _, d := range decisions {
		switch d.Decision {
		case models.DecisionPending:
			out.Pending++
		case models.DecisionCertify:
			out.Certified++
			if d.AutoCertified {
				out.AutoCertified++
			}
		case models.DecisionRevoke:
			out.Revoked++
		case models.DecisionEscalate:
			out.Escalated++
		}
	}
	if out.TotalDecisions > 0 {
		out.AutoCertificationRate = float64(out.AutoCertified) / float64(out.TotalDecisions)
	}
	return out, nil
}

// SetAutoCertifyEnabled flips the access_reviews.auto_certify_enabled
// column for the supplied review. Returns ErrReviewNotFound when the
// row does not exist and ErrReviewClosed when the review is closed
// or cancelled (operators cannot flip auto-certify on a finished
// campaign — the AI agent has already run).
func (s *AccessReviewService) SetAutoCertifyEnabled(ctx context.Context, reviewID string, enabled bool) error {
	if reviewID == "" {
		return fmt.Errorf("%w: review_id is required", ErrValidation)
	}
	var review models.AccessReview
	if err := s.db.WithContext(ctx).Where("id = ?", reviewID).First(&review).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: %s", ErrReviewNotFound, reviewID)
		}
		return fmt.Errorf("access: select access_review: %w", err)
	}
	if review.State == models.ReviewStateClosed || review.State == models.ReviewStateCancelled {
		return fmt.Errorf("%w: %s (state=%s)", ErrReviewClosed, reviewID, review.State)
	}
	now := s.now()
	res := s.db.WithContext(ctx).Model(&models.AccessReview{}).
		Where("id = ?", reviewID).
		Updates(map[string]interface{}{
			"auto_certify_enabled": enabled,
			"updated_at":           now,
		})
	if res.Error != nil {
		return fmt.Errorf("access: update auto_certify_enabled: %w", res.Error)
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
