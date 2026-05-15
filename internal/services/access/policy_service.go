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
)

// PolicyService is the service layer for the policies table per
// docs/overview.md §6 and docs/architecture.md §5. It owns the
// draft → simulate → promote lifecycle:
//
//   - CreateDraft persists a new row with IsDraft=true. Drafts NEVER
//     create an OpenZiti ServicePolicy (per Phase 3 exit criterion).
//   - Simulate runs ImpactResolver + ConflictDetector and stamps the
//     resulting ImpactReport into policies.draft_impact.
//   - Promote flips IsDraft to false in a transaction. The OpenZiti
//     ServicePolicy write is NOT performed in this repo — that
//     integration lives in the ZTNA business layer; Promote here just
//     mutates the DB row.
//   - TestAccess answers "Can user X access resource Y under draft P?"
//     without persisting anything; backs the admin-UI sandbox.
//
// PolicyService composes ImpactResolver and ConflictDetector. Callers
// can swap either hook from tests without spinning up the full graph
// (see SwapImpactResolver / SwapConflictDetector).
type PolicyService struct {
	db               *gorm.DB
	impactResolver   *ImpactResolver
	conflictDetector *ConflictDetector
	// riskAssessor is the optional Phase 4 AI hook. When set, Simulate
	// passes the freshly-built ImpactReport to AssessRequestRisk and
	// stamps the returned score / factors onto the report. nil
	// disables AI scoring; the report is persisted exactly as the
	// resolver + conflict detector built it.
	riskAssessor RiskAssessor
	// zitiWriter is the optional Phase 3+ OpenZiti hook. When set,
	// Promote calls WriteServicePolicy AFTER the DB transaction has
	// committed so a slow Ziti controller does not pin a row-level
	// lock for the duration of the upstream RTT. nil means no Ziti
	// integration in this repo — the ZTNA business layer is
	// responsible for materialising the ServicePolicy in OpenZiti.
	// CreateDraft and Simulate NEVER call this hook (Phase 3 exit
	// criterion: drafts must not create OpenZiti ServicePolicy).
	zitiWriter OpenZitiPolicyWriter
	// now is overridable in tests so we can pin CreatedAt / PromotedAt
	// timestamps in assertions. Defaults to time.Now in NewPolicyService.
	now func() time.Time
	// newID is overridable in tests so we can pin generated IDs.
	// Defaults to a Crockford-base32 ULID in NewPolicyService.
	newID func() string
}

// OpenZitiPolicyWriter is the narrow contract PolicyService.Promote
// uses to materialise a promoted policy as an OpenZiti ServicePolicy.
// The default PolicyService leaves this nil — in that case Promote
// only flips the DB state and the ZTNA business layer is responsible
// for the Ziti write. When set (typically at boot in cmd/ztna-api),
// Promote calls WriteServicePolicy AFTER committing the DB
// transaction. CreateDraft and Simulate NEVER call this hook.
//
// WriteServicePolicy is best-effort: a failure logs a warning but
// does NOT roll back the promotion, mirroring PHASES Phase 5
// notification semantics (the source of truth is the DB; downstream
// effects converge eventually).
type OpenZitiPolicyWriter interface {
	WriteServicePolicy(ctx context.Context, policy *models.Policy) error
}

// PolicyPromotionEvent is the richer payload emitted by Promote per
// docs/overview.md §13 (Hybrid Access Model). It wraps the freshly-
// promoted Policy alongside the access_mode classification of the
// connectors currently configured in the workspace. Downstream
// consumers (typically the ZTNA business layer) use the access-mode
// snapshot to decide whether an OpenZiti ServicePolicy is needed
// for this policy at all:
//
//   - if the workspace has no tunnel-mode connectors there is no
//     dataplane that needs a ServicePolicy and the writer can no-op;
//   - if any tunnel-mode connector exists the writer materialises
//     the ServicePolicy as before.
//
// WorkspaceAccessModes is sorted and de-duplicated for stable
// downstream consumption. Empty means "no access_connectors in the
// workspace" — the writer should treat this as a no-op rather than
// a failure.
type PolicyPromotionEvent struct {
	Policy               *models.Policy `json:"policy"`
	WorkspaceAccessModes []string       `json:"workspace_access_modes"`
}

// OpenZitiPolicyEventWriter is the optional richer variant of
// OpenZitiPolicyWriter. When the configured writer implements this
// interface, Promote calls WriteServicePolicyEvent with a
// PolicyPromotionEvent that carries the workspace's access-mode
// snapshot alongside the policy. The interface is opt-in so
// existing writer implementations remain compatible — Promote
// falls back to WriteServicePolicy when the writer only implements
// the narrow contract.
type OpenZitiPolicyEventWriter interface {
	WriteServicePolicyEvent(ctx context.Context, event *PolicyPromotionEvent) error
}

// NewPolicyService returns a new service backed by db. db must not be
// nil. The service constructs a default ImpactResolver and
// ConflictDetector against the same db; tests can swap them via the
// SwapImpactResolver / SwapConflictDetector hooks.
func NewPolicyService(db *gorm.DB) *PolicyService {
	return &PolicyService{
		db:               db,
		impactResolver:   NewImpactResolver(db),
		conflictDetector: NewConflictDetector(db),
		now:              time.Now,
		newID:            newULID,
	}
}

// SetOpenZitiPolicyWriter wires a writer onto the service. Promote
// calls writer.WriteServicePolicy AFTER the DB transaction has
// committed; passing nil restores the default "no Ziti integration in
// this repo" behaviour. Call this once at boot from cmd/ztna-api;
// it is NOT safe to call concurrently with Promote.
func (s *PolicyService) SetOpenZitiPolicyWriter(w OpenZitiPolicyWriter) {
	s.zitiWriter = w
}

// SetRiskAssessor wires an AI-driven risk assessor onto the service.
// nil disables AI scoring during Simulate. Call this once at boot
// from cmd/ztna-api/main.go; it is NOT safe to call concurrently
// with Simulate.
func (s *PolicyService) SetRiskAssessor(r RiskAssessor) {
	s.riskAssessor = r
}

// SwapImpactResolver replaces the impact resolver. Intended for tests
// that need to count or stub the resolver without seeding the full
// teams / members / resources graph.
func (s *PolicyService) SwapImpactResolver(r *ImpactResolver) {
	s.impactResolver = r
}

// SwapConflictDetector replaces the conflict detector. Intended for
// tests that need to count or stub the detector without seeding live
// policies.
func (s *PolicyService) SwapConflictDetector(d *ConflictDetector) {
	s.conflictDetector = d
}

// CreateDraftPolicyInput is the input contract for CreateDraft. Name,
// WorkspaceID and Action are required; the two selector blobs are
// optional but a policy with both selectors empty matches nothing and
// is therefore useless — callers that want one universal policy should
// pass an explicit `{}` selector.
type CreateDraftPolicyInput struct {
	WorkspaceID        string
	Name               string
	Description        string
	AttributesSelector json.RawMessage
	ResourceSelector   json.RawMessage
	Action             string
}

// TestAccessInput is the input contract for TestAccess. PolicyID must
// reference a draft (or live) policy in the same workspace; UserID and
// ResourceExternalID identify the (member, resource) pair to evaluate.
type TestAccessInput struct {
	WorkspaceID        string
	PolicyID           string
	UserID             string
	ResourceExternalID string
}

// TestAccessResult is the shape returned by TestAccess. Allowed is the
// answer to "would this draft policy grant access?". PolicyName /
// Reason are operator-visible strings for the admin UI sandbox.
// ExistingGrants lists live policies that already cover the same pair
// — surfaced so admins can see the combined effect of the draft on top
// of the live ruleset.
type TestAccessResult struct {
	Allowed        bool     `json:"allowed"`
	PolicyName     string   `json:"policy_name,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	ExistingGrants []string `json:"existing_grants,omitempty"`
}

// Sentinel errors for the policy service. Wrapped with fmt.Errorf so
// callers can errors.Is them without depending on message formats.
var (
	// ErrPolicyNotFound is returned by Get / Simulate / Promote /
	// TestAccess when the supplied policy ID does not match a row in
	// the supplied workspace.
	ErrPolicyNotFound = errors.New("access: policy not found")

	// ErrPolicyAlreadyPromoted is returned by Promote when the target
	// policy has already been promoted (IsDraft=false). A live policy
	// cannot be re-promoted; admins instead create a new draft and
	// promote that.
	ErrPolicyAlreadyPromoted = errors.New("access: policy already promoted")

	// ErrPolicyNotSimulated is returned by Promote when the target
	// draft has no draft_impact stamped — Simulate must run before
	// Promote (per PROPOSAL §6.5: simulate-before-promote).
	ErrPolicyNotSimulated = errors.New("access: policy must be simulated before promotion")

	// ErrPolicyNotDraft is returned by Simulate when the target policy
	// has already been promoted. Live policies cannot be re-simulated
	// in place; admins instead create a new draft.
	ErrPolicyNotDraft = errors.New("access: policy is not a draft")
)

// CreateDraft validates input, generates a ULID, and persists a new
// policies row with IsDraft=true. CreateDraft does NOT compute impact
// — callers must invoke Simulate to populate draft_impact before
// Promote will succeed.
func (s *PolicyService) CreateDraft(ctx context.Context, in CreateDraftPolicyInput) (*models.Policy, error) {
	if err := validateCreateDraft(in); err != nil {
		return nil, err
	}

	now := s.now()
	policy := &models.Policy{
		ID:                 s.newID(),
		WorkspaceID:        in.WorkspaceID,
		Name:               in.Name,
		Description:        in.Description,
		AttributesSelector: datatypes.JSON(in.AttributesSelector),
		ResourceSelector:   datatypes.JSON(in.ResourceSelector),
		Action:             in.Action,
		IsDraft:            true,
		IsActive:           true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := s.db.WithContext(ctx).Create(policy).Error; err != nil {
		return nil, fmt.Errorf("access: insert policy: %w", err)
	}
	return policy, nil
}

// GetDraft returns the draft policy identified by (workspaceID,
// policyID). Returns ErrPolicyNotFound if no draft matches — a row
// that exists but has IsDraft=false is treated as "not found" so
// callers cannot accidentally simulate a live policy.
func (s *PolicyService) GetDraft(ctx context.Context, workspaceID, policyID string) (*models.Policy, error) {
	if workspaceID == "" || policyID == "" {
		return nil, fmt.Errorf("%w: workspace_id and policy_id are required", ErrValidation)
	}
	var policy models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ? AND is_draft = ?", workspaceID, policyID, true).
		First(&policy).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, policyID)
		}
		return nil, fmt.Errorf("access: select draft policy: %w", err)
	}
	return &policy, nil
}

// ListDrafts returns every draft policy in the supplied workspace,
// ordered by CreatedAt descending. Soft-deleted drafts are excluded.
func (s *PolicyService) ListDrafts(ctx context.Context, workspaceID string) ([]models.Policy, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	var drafts []models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND is_draft = ?", workspaceID, true).
		Order("created_at desc").
		Find(&drafts).Error
	if err != nil {
		return nil, fmt.Errorf("access: list drafts: %w", err)
	}
	return drafts, nil
}

// GetPolicy returns any policy (draft or live) identified by
// (workspaceID, policyID). Used by TestAccess and admin code that
// needs to inspect a row regardless of draft state. Returns
// ErrPolicyNotFound when no row matches.
func (s *PolicyService) GetPolicy(ctx context.Context, workspaceID, policyID string) (*models.Policy, error) {
	if workspaceID == "" || policyID == "" {
		return nil, fmt.Errorf("%w: workspace_id and policy_id are required", ErrValidation)
	}
	var policy models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, policyID).
		First(&policy).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, policyID)
		}
		return nil, fmt.Errorf("access: select policy: %w", err)
	}
	return &policy, nil
}

// Simulate runs the impact resolver and the conflict detector against
// the supplied draft policy, merges the results into one ImpactReport,
// stamps the report into policies.draft_impact, and returns it. Per
// PROPOSAL §6.5 Simulate is the only path that populates
// draft_impact; Promote consults it before flipping IsDraft.
//
// Simulate is read-mostly with a single UPDATE at the end. It is safe
// to call Simulate repeatedly on the same draft — every call overwrites
// the previous draft_impact with the latest snapshot.
func (s *PolicyService) Simulate(ctx context.Context, workspaceID, policyID string) (*ImpactReport, error) {
	policy, err := s.loadPolicy(ctx, workspaceID, policyID)
	if err != nil {
		return nil, err
	}
	if !policy.IsDraft {
		return nil, fmt.Errorf("%w: %s", ErrPolicyNotDraft, policyID)
	}

	report, err := s.impactResolver.ResolveImpact(ctx, policy)
	if err != nil {
		return nil, fmt.Errorf("access: resolve impact: %w", err)
	}

	conflicts, err := s.conflictDetector.DetectConflicts(ctx, policy, report.AffectedMembers, report.AffectedResources)
	if err != nil {
		return nil, fmt.Errorf("access: detect conflicts: %w", err)
	}
	report.ConflictsWithExisting = conflicts
	report.Highlights = buildHighlights(policy, report)

	// Phase 4 AI scoring. PolicyService asks the assessor "how risky
	// is this draft?". Per PROPOSAL §5.3 the AI is decision-support
	// for Simulate — failure leaves the report's RiskScore empty
	// rather than synthesising "medium". The fallback semantics for
	// access requests (force "medium" on failure) intentionally do
	// NOT apply here: a draft policy with no AI score is harmless,
	// and we don't want admins acting on a synthesised score they
	// can't audit.
	if s.riskAssessor != nil {
		if score, factors, ok := s.riskAssessor.AssessRequestRisk(ctx, report); ok && score != "" {
			report.RiskScore = score
			report.RiskFactors = factors
		}
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("access: marshal impact report: %w", err)
	}
	now := s.now()
	result := s.db.WithContext(ctx).
		Model(&models.Policy{}).
		Where("id = ? AND workspace_id = ? AND is_draft = ?", policy.ID, workspaceID, true).
		Updates(map[string]interface{}{
			"draft_impact": datatypes.JSON(encoded),
			"updated_at":   now,
		})
	if result.Error != nil {
		return nil, fmt.Errorf("access: update draft_impact: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		// Concurrent promotion or soft-delete between load and
		// update. Surface as not-draft so the caller retries on a
		// fresh row rather than reading the stale local report.
		return nil, fmt.Errorf("%w: %s (concurrently promoted or deleted)", ErrPolicyNotDraft, policyID)
	}
	return report, nil
}

// Promote flips a draft policy to live in a single transaction. The FSM
// guard rails:
//
//   - Policy must exist and be IsDraft=true (else ErrPolicyAlreadyPromoted
//     or ErrPolicyNotFound).
//   - Policy.DraftImpact must be non-nil — Simulate must run first
//     (else ErrPolicyNotSimulated).
//
// The UPDATE is gated on (id, workspace_id, is_draft=true) so two
// concurrent promotions race-loser sees RowsAffected==0 and returns
// ErrPolicyAlreadyPromoted.
//
// NOTE: OpenZiti ServicePolicy creation is NOT implemented in this
// repo. The ZTNA business layer hosts the OpenZiti integration; this
// method just flips the DB state. The promote handler in the API
// layer is responsible for triggering downstream Ziti writes.
func (s *PolicyService) Promote(ctx context.Context, workspaceID, policyID, actorUserID string) (*models.Policy, error) {
	if workspaceID == "" || policyID == "" || actorUserID == "" {
		return nil, fmt.Errorf("%w: workspace_id, policy_id, and actor_user_id are required", ErrValidation)
	}

	var promoted models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var policy models.Policy
		if err := tx.Where("workspace_id = ? AND id = ?", workspaceID, policyID).First(&policy).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: %s", ErrPolicyNotFound, policyID)
			}
			return fmt.Errorf("access: select policy: %w", err)
		}
		if !policy.IsDraft {
			return fmt.Errorf("%w: %s", ErrPolicyAlreadyPromoted, policyID)
		}
		if len(policy.DraftImpact) == 0 {
			return fmt.Errorf("%w: %s", ErrPolicyNotSimulated, policyID)
		}

		now := s.now()
		actor := actorUserID
		result := tx.Model(&models.Policy{}).
			Where("id = ? AND workspace_id = ? AND is_draft = ?", policy.ID, workspaceID, true).
			Updates(map[string]interface{}{
				"is_draft":     false,
				"promoted_at":  now,
				"promoted_by":  actor,
				"updated_at":   now,
			})
		if result.Error != nil {
			return fmt.Errorf("access: update policy promotion: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%w: %s (concurrently promoted)", ErrPolicyAlreadyPromoted, policyID)
		}

		policy.IsDraft = false
		policy.PromotedAt = &now
		policy.PromotedBy = &actor
		policy.UpdatedAt = now
		promoted = policy
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Materialise the promoted policy as an OpenZiti ServicePolicy
	// AFTER commit. Best-effort: a Ziti failure logs but does not
	// roll back the promotion (the DB row is the source of truth;
	// the ZTNA business layer reconciles eventually). CreateDraft
	// and Simulate NEVER reach this branch — Phase 3 exit criterion.
	//
	// Phase 11 (docs/overview.md §13): when the writer also
	// implements OpenZitiPolicyEventWriter, hand it the richer
	// PolicyPromotionEvent that carries the workspace's
	// access-mode snapshot. Writers that only implement the
	// narrow OpenZitiPolicyWriter contract continue to receive
	// just the policy — no Phase-3 callers are broken.
	if s.zitiWriter != nil {
		if eventWriter, ok := s.zitiWriter.(OpenZitiPolicyEventWriter); ok {
			modes, mErr := s.collectWorkspaceAccessModes(ctx, workspaceID)
			if mErr != nil {
				log.Printf("access: policy %s: collect workspace access modes: %v", promoted.ID, mErr)
			}
			event := &PolicyPromotionEvent{
				Policy:               &promoted,
				WorkspaceAccessModes: modes,
			}
			if err := eventWriter.WriteServicePolicyEvent(ctx, event); err != nil {
				log.Printf("access: policy %s: openziti event write failed: %v", promoted.ID, err)
			}
		} else if err := s.zitiWriter.WriteServicePolicy(ctx, &promoted); err != nil {
			log.Printf("access: policy %s: openziti write failed: %v", promoted.ID, err)
		}
	}
	return &promoted, nil
}

// collectWorkspaceAccessModes returns the sorted, de-duplicated set
// of access_mode values currently configured on the workspace's
// access_connectors. Soft-deleted rows are excluded automatically
// by GORM. An empty result is a valid answer — it means the
// workspace has no live connectors and downstream consumers should
// treat the workspace as "no dataplane to materialise".
func (s *PolicyService) collectWorkspaceAccessModes(ctx context.Context, workspaceID string) ([]string, error) {
	if s.db == nil || workspaceID == "" {
		return nil, nil
	}
	var rows []string
	if err := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Where("workspace_id = ?", workspaceID).
		Distinct("access_mode").
		Order("access_mode ASC").
		Pluck("access_mode", &rows).Error; err != nil {
		return nil, fmt.Errorf("access: pluck workspace access_mode: %w", err)
	}
	out := make([]string, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for _, m := range rows {
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out, nil
}

// TestAccess answers "Can user X access resource Y under draft policy
// P?" without persisting anything. The flow:
//
//  1. Load the policy (any state) by (workspace, id).
//  2. Resolve teams matching the policy's AttributesSelector and check
//     whether UserID is a member of any of them.
//  3. Resolve resources matching the policy's ResourceSelector and
//     check whether ResourceExternalID matches one of them.
//  4. If both checks pass, the verdict is the policy's Action
//     ("allow" → Allowed=true, "deny" → Allowed=false). If either
//     check fails, Allowed=false with reason "user/resource not in
//     scope".
//  5. Finally enumerate live policies in the same workspace that
//     already cover the (user, resource) pair so the admin UI can show
//     the combined effect.
//
// TestAccess is read-only and safe to call on live policies; in that
// case it shows the existing access decision rather than a hypothetical.
func (s *PolicyService) TestAccess(ctx context.Context, in TestAccessInput) (*TestAccessResult, error) {
	if in.WorkspaceID == "" || in.PolicyID == "" || in.UserID == "" || in.ResourceExternalID == "" {
		return nil, fmt.Errorf("%w: workspace_id, policy_id, user_id, and resource_external_id are required", ErrValidation)
	}

	policy, err := s.GetPolicy(ctx, in.WorkspaceID, in.PolicyID)
	if err != nil {
		return nil, err
	}

	userInScope, err := s.userInScope(ctx, policy, in.UserID)
	if err != nil {
		return nil, err
	}
	resourceInScope, err := s.resourceInScope(ctx, in.WorkspaceID, policy, in.ResourceExternalID)
	if err != nil {
		return nil, err
	}

	existing, err := s.existingGrants(ctx, in.WorkspaceID, policy.ID, in.UserID, in.ResourceExternalID)
	if err != nil {
		return nil, err
	}

	res := &TestAccessResult{
		PolicyName:     policy.Name,
		ExistingGrants: existing,
	}
	if !userInScope || !resourceInScope {
		res.Allowed = false
		res.Reason = "user/resource not in scope of this policy"
		return res, nil
	}

	switch policy.Action {
	case models.PolicyActionAllow:
		res.Allowed = true
		res.Reason = fmt.Sprintf("user is in scope of policy %q (action=allow)", policy.Name)
	case models.PolicyActionDeny:
		res.Allowed = false
		res.Reason = fmt.Sprintf("user is in scope of policy %q (action=deny)", policy.Name)
	default:
		res.Allowed = false
		res.Reason = fmt.Sprintf("policy %q has unknown action %q", policy.Name, policy.Action)
	}
	return res, nil
}

// loadPolicy is a small helper shared by Simulate and TestAccess that
// returns the row identified by (workspace, id) regardless of draft
// state, mapping a missing row onto ErrPolicyNotFound.
func (s *PolicyService) loadPolicy(ctx context.Context, workspaceID, policyID string) (*models.Policy, error) {
	if workspaceID == "" || policyID == "" {
		return nil, fmt.Errorf("%w: workspace_id and policy_id are required", ErrValidation)
	}
	var policy models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, policyID).
		First(&policy).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, policyID)
		}
		return nil, fmt.Errorf("access: select policy: %w", err)
	}
	return &policy, nil
}

// userInScope reports whether userID is a member of any team matched
// by policy.AttributesSelector. An empty selector matches every team
// in the workspace (and therefore every member); callers wishing to
// scope a policy more narrowly must populate the selector.
func (s *PolicyService) userInScope(ctx context.Context, policy *models.Policy, userID string) (bool, error) {
	teams, err := s.impactResolver.matchTeams(ctx, policy.WorkspaceID, policy.AttributesSelector)
	if err != nil {
		return false, fmt.Errorf("access: match teams: %w", err)
	}
	if len(teams) == 0 {
		return false, nil
	}
	teamIDs := make([]string, 0, len(teams))
	for i := range teams {
		teamIDs = append(teamIDs, teams[i].ID)
	}
	var count int64
	if err := s.db.WithContext(ctx).
		Model(&models.TeamMember{}).
		Where("team_id IN ? AND user_id = ?", teamIDs, userID).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("access: count team members: %w", err)
	}
	return count > 0, nil
}

// resourceInScope reports whether the supplied resource ExternalID
// matches policy.ResourceSelector. The matcher uses the same flat
// key-value semantics as ImpactResolver — see resourceMatchesSelector.
func (s *PolicyService) resourceInScope(ctx context.Context, workspaceID string, policy *models.Policy, resourceExternalID string) (bool, error) {
	var resource models.Resource
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND external_id = ?", workspaceID, resourceExternalID).
		First(&resource).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Resource we have never seen. Conservatively treat as
			// out-of-scope rather than synthesising a stub row.
			return false, nil
		}
		return false, fmt.Errorf("access: select resource: %w", err)
	}
	return resourceMatchesSelector(&resource, policy.ResourceSelector), nil
}

// existingGrants returns the names of live, active policies in the
// same workspace whose scope already covers (userID, resourceExternalID).
// The current draft is excluded from the list. This is best-effort: it
// scans every live policy and re-runs the same matching logic, which
// is fine for Phase 3 where the live ruleset is small.
func (s *PolicyService) existingGrants(ctx context.Context, workspaceID, currentPolicyID, userID, resourceExternalID string) ([]string, error) {
	var live []models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND is_draft = ? AND is_active = ? AND id <> ?", workspaceID, false, true, currentPolicyID).
		Find(&live).Error
	if err != nil {
		return nil, fmt.Errorf("access: list live policies: %w", err)
	}
	names := make([]string, 0)
	for i := range live {
		p := &live[i]
		userIn, err := s.userInScope(ctx, p, userID)
		if err != nil {
			return nil, err
		}
		if !userIn {
			continue
		}
		resIn, err := s.resourceInScope(ctx, workspaceID, p, resourceExternalID)
		if err != nil {
			return nil, err
		}
		if !resIn {
			continue
		}
		names = append(names, p.Name)
	}
	return names, nil
}

// validateCreateDraft enforces the "all required fields present" contract
// for CreateDraft. Errors wrap ErrValidation so callers can errors.Is
// them and surface 4xx without coupling to the message format.
func validateCreateDraft(in CreateDraftPolicyInput) error {
	switch {
	case in.WorkspaceID == "":
		return fmt.Errorf("%w: workspace_id is required", ErrValidation)
	case in.Name == "":
		return fmt.Errorf("%w: name is required", ErrValidation)
	case in.Action != models.PolicyActionAllow && in.Action != models.PolicyActionDeny:
		return fmt.Errorf("%w: action must be %q or %q", ErrValidation, models.PolicyActionAllow, models.PolicyActionDeny)
	}
	return nil
}

// buildHighlights renders a small list of human-readable bullet points
// summarising the impact report. Surface area for the admin UI: keep
// it short and operator-grokkable.
func buildHighlights(policy *models.Policy, report *ImpactReport) []string {
	if policy == nil || report == nil {
		return nil
	}
	highlights := make([]string, 0, 4)
	switch policy.Action {
	case models.PolicyActionAllow:
		if report.MembersGainingAccess > 0 && report.NewResourcesGranted > 0 {
			highlights = append(highlights, fmt.Sprintf(
				"%d member(s) will gain access to %d resource(s)",
				report.MembersGainingAccess, report.NewResourcesGranted,
			))
		}
	case models.PolicyActionDeny:
		if report.MembersLosingAccess > 0 && report.ResourcesRevoked > 0 {
			highlights = append(highlights, fmt.Sprintf(
				"%d member(s) will lose access to %d resource(s)",
				report.MembersLosingAccess, report.ResourcesRevoked,
			))
		}
	}
	if len(report.ConflictsWithExisting) > 0 {
		highlights = append(highlights, fmt.Sprintf(
			"%d existing rule(s) overlap this draft", len(report.ConflictsWithExisting),
		))
	}
	if len(report.AffectedTeams) > 0 {
		highlights = append(highlights, fmt.Sprintf(
			"draft scopes %d team(s)", len(report.AffectedTeams),
		))
	}
	return highlights
}
