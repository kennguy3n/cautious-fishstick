package access

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// PolicyDiffReport is the structured before/after comparison returned
// by PolicyService.DiffPolicy. It pairs the draft policy itself with
// (a) a snapshot of the live access state baseline for the draft's
// scope and (b) a projected post-promotion state. The Admin UI's
// policy simulator page renders this directly — Before on the left,
// After on the right, with the Delta block summarising what changes.
//
// The shape is deliberately flat so the Admin UI can checksum the
// JSON for "has the diff drifted?" — every slice is sorted.
type PolicyDiffReport struct {
	// Policy is the draft being diffed. Includes Action ("allow" /
	// "deny") so the UI can colour the Before/After columns.
	Policy *models.Policy `json:"policy"`

	// Before is the live state baseline. AppliesDraft is false because
	// the draft has not been promoted yet — Members and Resources
	// describe who/what is already governed by other live policies on
	// the same workspace whose scope overlaps with this draft.
	Before PolicyDiffState `json:"before"`

	// After is the projected state assuming the draft is promoted.
	// AppliesDraft is true; Members and Resources include the draft's
	// effect (allow → adds members/resources, deny → removes them).
	After PolicyDiffState `json:"after"`

	// Delta is the persisted ImpactReport from the most recent
	// Simulate call. Surfaces the per-dimension counts and conflict
	// list the Admin UI badges over the Before/After columns.
	Delta *ImpactReport `json:"delta"`
}

// PolicyDiffState is one side of a PolicyDiffReport. Members and
// Resources are sorted; an empty slice is encoded as an empty JSON
// array (never null) so the Admin UI never has to disambiguate
// "absent" from "empty".
type PolicyDiffState struct {
	// AppliesDraft indicates whether this side has the draft applied.
	// false for Before, true for After. The Admin UI uses this to
	// label the column header.
	AppliesDraft bool `json:"applies_draft"`

	// Action is "allow" or "deny" — mirrors Policy.Action. Surfaced
	// here as well so a JSON viewer can read each side independently
	// without referencing the outer policy block.
	Action string `json:"action"`

	// Members are the team-member external IDs in scope on this side.
	// On Before, this is the set of members already governed by an
	// overlapping live policy. On After, it is Before extended by
	// the draft's AffectedMembers (for allow) or pruned (for deny).
	Members []string `json:"members"`

	// Resources are the resource external IDs in scope on this side.
	Resources []string `json:"resources"`
}

// DiffPolicy returns a structured before/after comparison of the
// draft policy identified by (workspaceID, policyID). The draft
// MUST have been simulated first (DraftImpact non-nil) — otherwise
// the diff has no impact data to surface and DiffPolicy returns
// ErrPolicyNotSimulated. Live policies cannot be diffed (the
// before/after is degenerate); attempting to diff a live policy
// returns ErrPolicyNotDraft.
//
// The "before" baseline is computed from the live policies in the
// same workspace whose AttributesSelector / ResourceSelector overlap
// with this draft. For Phase 4 we use the ImpactResolver to expand
// each live policy's selectors into members/resources (mirroring
// the Simulate code path) and union the results — Phase 4's exit
// criterion is "Admin UI renders a structured diff", so a same-
// resolver baseline is the source of truth.
func (s *PolicyService) DiffPolicy(ctx context.Context, workspaceID, policyID string) (*PolicyDiffReport, error) {
	if workspaceID == "" || policyID == "" {
		return nil, fmt.Errorf("%w: workspace_id and policy_id are required", ErrValidation)
	}

	policy, err := s.loadPolicy(ctx, workspaceID, policyID)
	if err != nil {
		return nil, err
	}
	if !policy.IsDraft {
		return nil, fmt.Errorf("%w: %s", ErrPolicyNotDraft, policyID)
	}
	if len(policy.DraftImpact) == 0 {
		return nil, fmt.Errorf("%w: %s (call Simulate before Diff)", ErrPolicyNotSimulated, policyID)
	}

	var impact ImpactReport
	if err := json.Unmarshal(policy.DraftImpact, &impact); err != nil {
		return nil, fmt.Errorf("access: decode draft_impact: %w", err)
	}

	beforeMembers, beforeResources, err := s.baselineLiveScope(ctx, workspaceID, policy.ID)
	if err != nil {
		return nil, err
	}

	afterMembers, afterResources := projectAfter(policy.Action, beforeMembers, beforeResources, impact.AffectedMembers, impact.AffectedResources)

	sort.Strings(beforeMembers)
	sort.Strings(beforeResources)
	sort.Strings(afterMembers)
	sort.Strings(afterResources)

	return &PolicyDiffReport{
		Policy: policy,
		Before: PolicyDiffState{
			AppliesDraft: false,
			Action:       policy.Action,
			Members:      nonNilStrings(beforeMembers),
			Resources:    nonNilStrings(beforeResources),
		},
		After: PolicyDiffState{
			AppliesDraft: true,
			Action:       policy.Action,
			Members:      nonNilStrings(afterMembers),
			Resources:    nonNilStrings(afterResources),
		},
		Delta: &impact,
	}, nil
}

// baselineLiveScope returns the union of (members, resources) governed
// by live policies in workspaceID whose impact-resolver expansion
// overlaps with the draft policyID being diffed. We exclude the draft
// itself (and any other draft policies) so the Before side reflects
// the workspace's current live state, not its pending drafts.
//
// The function is best-effort: a malformed selector on one live
// policy is logged and skipped, not propagated, so a single bad row
// does not block the entire diff endpoint.
func (s *PolicyService) baselineLiveScope(ctx context.Context, workspaceID, excludePolicyID string) (members []string, resources []string, err error) {
	var live []models.Policy
	// GORM's Find returns (empty slice, nil) when no rows match —
	// gorm.ErrRecordNotFound is only emitted by First/Last/Take.
	// Any non-nil error here is a real DB failure and propagates.
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND is_draft = ? AND is_active = ? AND id <> ?", workspaceID, false, true, excludePolicyID).
		Find(&live).Error; err != nil {
		return nil, nil, fmt.Errorf("access: select live policies: %w", err)
	}
	memberSet := make(map[string]struct{})
	resourceSet := make(map[string]struct{})
	for i := range live {
		report, rerr := s.impactResolver.ResolveImpact(ctx, &live[i])
		if rerr != nil {
			// Skip malformed live policies; Phase 4 explicitly
			// chose "best effort" over "fail closed" so a single
			// corrupt row does not lock the Admin UI's diff page.
			continue
		}
		for _, m := range report.AffectedMembers {
			memberSet[m] = struct{}{}
		}
		for _, r := range report.AffectedResources {
			resourceSet[r] = struct{}{}
		}
	}
	out := make([]string, 0, len(memberSet))
	for m := range memberSet {
		out = append(out, m)
	}
	res := make([]string, 0, len(resourceSet))
	for r := range resourceSet {
		res = append(res, r)
	}
	return out, res, nil
}

// projectAfter computes the After-side scope by combining the
// baseline live scope with the draft's effect.
//
//   - action="allow": draft extends the live scope; After is the
//     union of baseline and draft-affected sets.
//   - action="deny" : draft removes from the live scope; After is the
//     baseline minus the draft-affected sets. Members / resources
//     unique to the draft (not in baseline) are dropped because a
//     deny on a set that has no live overlap is a no-op.
func projectAfter(action string, beforeMembers, beforeResources, draftMembers, draftResources []string) ([]string, []string) {
	switch action {
	case models.PolicyActionDeny:
		return setDifference(beforeMembers, draftMembers), setDifference(beforeResources, draftResources)
	default:
		// Treat any non-deny action (including "allow" and any
		// future verbs) as additive. Future verbs should add an
		// explicit case here when their semantics are nailed down.
		return setUnion(beforeMembers, draftMembers), setUnion(beforeResources, draftResources)
	}
}

func setUnion(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		seen[v] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	return out
}

func setDifference(a, b []string) []string {
	deny := make(map[string]struct{}, len(b))
	for _, v := range b {
		deny[v] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if _, removed := deny[v]; removed {
			continue
		}
		out = append(out, v)
	}
	return out
}

// nonNilStrings replaces a nil slice with an empty (but non-nil)
// slice so encoding/json emits [] rather than null. Sort order is
// preserved.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
