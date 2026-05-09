package access

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ConflictDetector compares a draft policy's affected (member,
// resource) pairs against the live ruleset to surface redundant or
// contradictory overlaps. It is the second leg of the simulate
// pipeline (ImpactResolver runs first); the conflict list is merged
// into the ImpactReport that PolicyService.Simulate persists.
//
// Phase 3 uses an O(N×M) scan: for each live policy in the same
// workspace we resolve its own affected members / resources via the
// embedded ImpactResolver, then check whether any pair in the
// supplied draft set overlaps. The N × M cost is fine while the per-
// workspace ruleset is small (Phase 3 typical: <100 live policies);
// Phase 6+ can move this into a precomputed materialised view.
type ConflictDetector struct {
	db       *gorm.DB
	resolver *ImpactResolver
}

// NewConflictDetector returns a detector backed by db. The detector
// constructs its own ImpactResolver so calls do not need to share
// state with the policy service.
func NewConflictDetector(db *gorm.DB) *ConflictDetector {
	return &ConflictDetector{
		db:       db,
		resolver: NewImpactResolver(db),
	}
}

// SwapResolver replaces the impact resolver. Intended for tests that
// want to assert detector behaviour without seeding the full graph.
func (d *ConflictDetector) SwapResolver(r *ImpactResolver) {
	d.resolver = r
}

// DetectConflicts walks every live, active policy in the same
// workspace as the draft and surfaces overlaps with the draft's
// (affectedMembers × affectedResources) cross-product.
//
// The output is deduped per (rule_id, kind) — if a single live policy
// produces both a redundant and a contradictory overlap (which can
// only happen with malformed data), both kinds are reported. Within
// one (rule_id, kind) pair we surface a single PolicyConflict
// regardless of how many overlapping pairs there were, because the
// admin UI wants "rule X conflicts" not "rule X conflicts on 47
// pairs".
//
// DetectConflicts is read-only and safe to run repeatedly. It returns
// an empty slice (not nil) on no conflicts so callers can len() the
// result without allocating.
func (d *ConflictDetector) DetectConflicts(
	ctx context.Context,
	draft *models.Policy,
	affectedMembers []string,
	affectedResources []string,
) ([]PolicyConflict, error) {
	if draft == nil {
		return nil, fmt.Errorf("%w: draft policy is required", ErrValidation)
	}
	out := make([]PolicyConflict, 0)
	if len(affectedMembers) == 0 || len(affectedResources) == 0 {
		return out, nil
	}

	memberSet := make(map[string]struct{}, len(affectedMembers))
	for _, m := range affectedMembers {
		memberSet[m] = struct{}{}
	}
	resourceSet := make(map[string]struct{}, len(affectedResources))
	for _, r := range affectedResources {
		resourceSet[r] = struct{}{}
	}

	var live []models.Policy
	if err := d.db.WithContext(ctx).
		Where("workspace_id = ? AND is_draft = ? AND is_active = ? AND id <> ?",
			draft.WorkspaceID, false, true, draft.ID).
		Find(&live).Error; err != nil {
		return nil, fmt.Errorf("access: list live policies: %w", err)
	}

	type seenKey struct {
		ruleID string
		kind   string
	}
	seen := map[seenKey]struct{}{}

	for i := range live {
		rule := &live[i]
		// Re-resolve the live policy's affected sets so we can
		// detect overlap. This is the expensive part of the pass.
		ruleReport, err := d.resolver.ResolveImpact(ctx, rule)
		if err != nil {
			return nil, fmt.Errorf("access: resolve live policy %s: %w", rule.ID, err)
		}
		ruleMembers := ruleReport.AffectedMembers
		ruleResources := ruleReport.AffectedResources

		// Find any overlap with the draft's affected sets. We don't
		// need to enumerate the full intersection — one overlap is
		// enough to classify and emit the conflict.
		overlap := false
		for _, m := range ruleMembers {
			if _, ok := memberSet[m]; !ok {
				continue
			}
			for _, res := range ruleResources {
				if _, ok := resourceSet[res]; ok {
					overlap = true
					break
				}
			}
			if overlap {
				break
			}
		}
		if !overlap {
			continue
		}

		kind := PolicyConflictKindContradictory
		if rule.Action == draft.Action {
			kind = PolicyConflictKindRedundant
		}
		key := seenKey{ruleID: rule.ID, kind: kind}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, PolicyConflict{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Kind:     kind,
		})
	}
	return out, nil
}
