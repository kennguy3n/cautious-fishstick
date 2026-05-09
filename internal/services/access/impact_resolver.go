package access

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ImpactResolver is the read-side helper that walks a draft policy's
// AttributesSelector → matching Teams → expanded TeamMembers and the
// ResourceSelector → matching Resources, then assembles an
// ImpactReport per docs/PROPOSAL.md §6.2.
//
// The resolver is deliberately stateless beyond its *gorm.DB handle —
// callers can construct one per simulation if they want fresh DB
// snapshots, or share one across calls inside a single transaction.
type ImpactResolver struct {
	db *gorm.DB
}

// NewImpactResolver returns a resolver backed by db. db must not be
// nil. The resolver does not write — every method is read-only.
func NewImpactResolver(db *gorm.DB) *ImpactResolver {
	return &ImpactResolver{db: db}
}

// ImpactReport is the structured output of ResolveImpact, persisted as
// the draft_impact JSON blob on policies. The shape mirrors
// docs/PROPOSAL.md §6.2 (fields are stable across versions; renaming
// any of them is a JSON-schema migration). Counts are intentionally
// flat int values (not int64) because ImpactReport is meant to be
// rendered in an admin UI and the counts will fit in 32 bits for the
// foreseeable future.
type ImpactReport struct {
	MembersGainingAccess  int              `json:"members_gaining_access"`
	MembersLosingAccess   int              `json:"members_losing_access"`
	NewResourcesGranted   int              `json:"new_resources_granted"`
	ResourcesRevoked      int              `json:"resources_revoked"`
	ConflictsWithExisting []PolicyConflict `json:"conflicts_with_existing_rules"`
	AffectedTeams         []string         `json:"affected_teams"`
	AffectedMembers       []string         `json:"affected_members"`
	AffectedResources     []string         `json:"affected_resources"`
	Highlights            []string         `json:"highlights"`
	RiskScore             string           `json:"risk_score,omitempty"`
	RiskFactors           []string         `json:"risk_factors,omitempty"`
}

// PolicyConflict describes a single overlap between a draft policy and
// an existing live policy. Kind is one of:
//
//   - "redundant"    — same Action on the same (member, resource) pair
//                      (the draft adds nothing).
//   - "contradictory" — opposite Action on the same pair (the draft
//                      reverses a live decision; surfaced loudly so
//                      admins notice).
type PolicyConflict struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Kind     string `json:"kind"`
}

// PolicyConflictKind enumerates the legal values of PolicyConflict.Kind.
const (
	// PolicyConflictKindRedundant is the same Action on the same pair —
	// the draft does not change behaviour.
	PolicyConflictKindRedundant = "redundant"
	// PolicyConflictKindContradictory is the opposite Action on the
	// same pair — the draft reverses an existing decision.
	PolicyConflictKindContradictory = "contradictory"
)

// ResolveImpact runs the resolver against the supplied draft policy
// and returns a populated (but conflict-free) ImpactReport. The
// returned report has ConflictsWithExisting empty — Simulate calls
// ConflictDetector separately and merges the results.
//
// All slices in the returned report are sorted (stable across calls)
// so two ResolveImpact calls on identical inputs produce
// byte-identical JSON, which lets the admin UI checksum the report
// for "has anything changed?".
func (r *ImpactResolver) ResolveImpact(ctx context.Context, policy *models.Policy) (*ImpactReport, error) {
	if policy == nil {
		return nil, fmt.Errorf("%w: policy is required", ErrValidation)
	}

	teams, err := r.matchTeams(ctx, policy.WorkspaceID, policy.AttributesSelector)
	if err != nil {
		return nil, err
	}
	teamIDs := make([]string, 0, len(teams))
	teamNames := make([]string, 0, len(teams))
	for i := range teams {
		teamIDs = append(teamIDs, teams[i].ID)
		teamNames = append(teamNames, teams[i].Name)
	}
	sort.Strings(teamNames)

	memberIDs, err := r.expandTeamsToMembers(ctx, teamIDs)
	if err != nil {
		return nil, err
	}

	resources, err := r.matchResources(ctx, policy.WorkspaceID, policy.ResourceSelector)
	if err != nil {
		return nil, err
	}
	resourceExternalIDs := make([]string, 0, len(resources))
	for i := range resources {
		resourceExternalIDs = append(resourceExternalIDs, resources[i].ExternalID)
	}
	sort.Strings(resourceExternalIDs)

	report := &ImpactReport{
		ConflictsWithExisting: []PolicyConflict{},
		AffectedTeams:         teamNames,
		AffectedMembers:       memberIDs,
		AffectedResources:     resourceExternalIDs,
		Highlights:            []string{},
		RiskFactors:           []string{},
	}
	switch policy.Action {
	case models.PolicyActionAllow:
		report.MembersGainingAccess = len(memberIDs)
		report.NewResourcesGranted = len(resourceExternalIDs)
	case models.PolicyActionDeny:
		report.MembersLosingAccess = len(memberIDs)
		report.ResourcesRevoked = len(resourceExternalIDs)
	}
	return report, nil
}

// matchTeams returns every team in workspaceID whose Attributes are a
// superset of the supplied attribute selector. An empty (or nil)
// selector matches every team in the workspace.
//
// Matching is performed in Go (not in SQL): SQLite's JSON path
// support does not match the postgres-jsonb-contains semantics we
// will see in production, and the team set per workspace is small
// enough that loading and filtering in memory is cheap. The query
// still scopes by workspace_id so we never page through other
// tenants' teams.
func (r *ImpactResolver) matchTeams(ctx context.Context, workspaceID string, selector datatypes.JSON) ([]models.Team, error) {
	var teams []models.Team
	if err := r.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Find(&teams).Error; err != nil {
		return nil, fmt.Errorf("access: list teams: %w", err)
	}
	if len(selector) == 0 {
		// An absent selector is the universal selector; every team
		// matches. Operators wishing to narrow scope must populate
		// AttributesSelector.
		return teams, nil
	}
	want := map[string]string{}
	if err := json.Unmarshal(selector, &want); err != nil {
		return nil, fmt.Errorf("%w: invalid attributes selector: %v", ErrValidation, err)
	}
	out := teams[:0]
	for i := range teams {
		t := &teams[i]
		got := map[string]string{}
		if len(t.Attributes) > 0 {
			if err := json.Unmarshal(t.Attributes, &got); err != nil {
				// Skip malformed rows rather than failing the whole
				// resolution — admins should not be unable to
				// simulate because a stale team has bad attrs.
				continue
			}
		}
		if mapContains(got, want) {
			out = append(out, *t)
		}
	}
	return out, nil
}

// expandTeamsToMembers returns the deduped, sorted set of UserIDs
// that belong to any of the supplied teams. An empty team list
// returns an empty slice (not nil) so callers can len() it without
// allocating.
func (r *ImpactResolver) expandTeamsToMembers(ctx context.Context, teamIDs []string) ([]string, error) {
	if len(teamIDs) == 0 {
		return []string{}, nil
	}
	var members []models.TeamMember
	if err := r.db.WithContext(ctx).
		Where("team_id IN ?", teamIDs).
		Find(&members).Error; err != nil {
		return nil, fmt.Errorf("access: list team_members: %w", err)
	}
	seen := make(map[string]struct{}, len(members))
	out := make([]string, 0, len(members))
	for _, m := range members {
		if _, dup := seen[m.UserID]; dup {
			continue
		}
		seen[m.UserID] = struct{}{}
		out = append(out, m.UserID)
	}
	sort.Strings(out)
	return out, nil
}

// matchResources returns every resource in workspaceID matched by the
// supplied resource selector. The Phase 3 matcher understands a flat
// JSON object whose keys are interpreted by resourceMatchesSelector.
// An empty selector matches every resource in the workspace.
func (r *ImpactResolver) matchResources(ctx context.Context, workspaceID string, selector datatypes.JSON) ([]models.Resource, error) {
	var resources []models.Resource
	if err := r.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Find(&resources).Error; err != nil {
		return nil, fmt.Errorf("access: list resources: %w", err)
	}
	if len(selector) == 0 {
		return resources, nil
	}
	out := resources[:0]
	for i := range resources {
		if resourceMatchesSelector(&resources[i], selector) {
			out = append(out, resources[i])
		}
	}
	return out, nil
}

// resourceMatchesSelector returns true iff every key in the flat
// selector object is satisfied by the resource. Recognised keys:
//
//   - "external_id" — exact match against Resource.ExternalID
//   - "category"    — exact match against Resource.Category
//   - "name"        — exact match against Resource.Name
//   - any other key — exact match against Resource.Tags[key]
//
// An empty (or unparseable) selector matches every resource. The
// matcher is intentionally forgiving on bad selectors so a stray
// admin typo does not fail an entire simulation; ImpactResolver
// surfaces "0 resources matched" instead.
func resourceMatchesSelector(resource *models.Resource, selector datatypes.JSON) bool {
	if resource == nil {
		return false
	}
	if len(selector) == 0 {
		return true
	}
	want := map[string]string{}
	if err := json.Unmarshal(selector, &want); err != nil {
		return false
	}
	tags := map[string]string{}
	if len(resource.Tags) > 0 {
		_ = json.Unmarshal(resource.Tags, &tags)
	}
	for k, v := range want {
		switch k {
		case "external_id":
			if resource.ExternalID != v {
				return false
			}
		case "category":
			if resource.Category != v {
				return false
			}
		case "name":
			if resource.Name != v {
				return false
			}
		default:
			if got, ok := tags[k]; !ok || got != v {
				return false
			}
		}
	}
	return true
}

// mapContains reports whether super contains every (key, value) pair
// in sub. A nil or empty sub is the universal selector and returns
// true unconditionally.
func mapContains(super, sub map[string]string) bool {
	for k, v := range sub {
		if got, ok := super[k]; !ok || got != v {
			return false
		}
	}
	return true
}
