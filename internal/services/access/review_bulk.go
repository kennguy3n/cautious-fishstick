package access

import (
	"context"
	"fmt"
)

// BulkDecisionInput is one entry in a BulkSubmitDecisions call. Maps
// 1:1 to a single SubmitDecision invocation.
type BulkDecisionInput struct {
	GrantID  string `json:"grant_id"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// BulkDecisionResult reports the outcome of one decision in a bulk
// submission. Success is true when the underlying SubmitDecision
// returned nil. On failure, Error carries the canonical service
// error string so the Admin UI can render per-row diagnostics next
// to each grant.
//
// We do NOT include the wrapped error sentinel — Error is a plain
// string because the HTTP envelope is JSON and the sentinel set is
// already enumerable from the service-error map in handlers/errors.go.
type BulkDecisionResult struct {
	GrantID  string `json:"grant_id"`
	Decision string `json:"decision"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// BulkDecisionSummary is the per-call rollup returned alongside the
// per-grant results. The Admin UI uses it to render the toast / banner
// after a bulk operation completes ("12 of 15 succeeded").
type BulkDecisionSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

// BulkSubmitDecisions applies one or more decisions to the supplied
// review in a single best-effort pass. Each decision is dispatched
// through SubmitDecision (so all of the existing FSM, idempotency, and
// upstream-revoke logic continues to apply); failures on one decision
// do NOT prevent subsequent decisions from running.
//
// This mirrors the SN360 bulk-action design (PROPOSAL §6.4): the
// caller sees a per-row result list and a roll-up summary so partial
// success is visible. A single transaction would arguably be cleaner
// for the DB but it would also mean one bad grant id rolls back every
// other admin's certify — exactly the Admin-UI footgun the bulk
// endpoint is designed to avoid.
//
// Decisions are applied in the order supplied. The function does NOT
// short-circuit on first failure because admins routinely batch
// hundreds of grants and rely on partial-success semantics.
//
// Validation:
//
//   - reviewID, decidedBy, and at least one decision are required;
//     missing values surface ErrValidation per the service convention.
//   - The Decision string is NOT validated up-front — the underlying
//     SubmitDecision is the source of truth for ErrInvalidDecision so
//     the per-row Error field carries the same wording the single-
//     decision endpoint returns.
func (s *AccessReviewService) BulkSubmitDecisions(
	ctx context.Context,
	reviewID, decidedBy string,
	decisions []BulkDecisionInput,
) ([]BulkDecisionResult, BulkDecisionSummary, error) {
	if reviewID == "" {
		return nil, BulkDecisionSummary{}, fmt.Errorf("%w: review_id is required", ErrValidation)
	}
	if decidedBy == "" {
		return nil, BulkDecisionSummary{}, fmt.Errorf("%w: decided_by is required", ErrValidation)
	}
	if len(decisions) == 0 {
		return nil, BulkDecisionSummary{}, fmt.Errorf("%w: at least one decision is required", ErrValidation)
	}

	results := make([]BulkDecisionResult, 0, len(decisions))
	summary := BulkDecisionSummary{Total: len(decisions)}

	for _, d := range decisions {
		res := BulkDecisionResult{
			GrantID:  d.GrantID,
			Decision: d.Decision,
		}
		// Honour ctx cancellation between rows. A cancelled bulk
		// is reported as failures for the remaining rows so the
		// Admin UI can show which entries did and did not apply.
		if ctxErr := ctx.Err(); ctxErr != nil {
			res.Error = ctxErr.Error()
			summary.Failed++
			results = append(results, res)
			continue
		}
		if err := s.SubmitDecision(ctx, reviewID, d.GrantID, d.Decision, decidedBy, d.Reason); err != nil {
			res.Error = err.Error()
			summary.Failed++
		} else {
			res.Success = true
			summary.Succeeded++
		}
		results = append(results, res)
	}
	return results, summary, nil
}


