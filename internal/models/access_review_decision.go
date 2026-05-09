package models

import (
	"time"
)

// AccessReviewDecision mirrors the access_review_decisions table per
// docs/PROPOSAL.md §9 and docs/ARCHITECTURE.md §6. One row per grant
// enrolled into an access-review campaign; the row is the
// authoritative record of "what did the reviewer decide for this
// grant in this campaign?".
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rule). ReviewID and GrantID are indexed strings; application
//     code is responsible for referential integrity to access_reviews
//     and access_grants respectively.
//   - Decision is one of "certify" / "revoke" / "escalate" /
//     "pending". Pending is the initial state for grants that
//     auto-certification declined to handle and that no reviewer has
//     touched yet.
//   - DecidedBy is the UserID that submitted the decision. For
//     auto-certified rows this can be empty; AutoCertified=true
//     disambiguates.
//   - AutoCertified flags rows where the AI agent certified the grant
//     without human input. Used by the admin UI to surface the
//     campaign-level "auto-certification rate" metric.
//   - Reason is operator-visible free text the reviewer (or AI) types
//     when submitting the decision. Audit-grade; never truncated.
//   - DecidedAt is when the decision was recorded. Nil while the row
//     is in "pending" state.
//   - CreatedAt / UpdatedAt are the standard GORM timestamps.
//   - There is intentionally no DeletedAt: review decisions are
//     immutable for audit; soft-deletion would let an admin
//     retroactively erase a decision, which we never want.
type AccessReviewDecision struct {
	ID            string     `gorm:"primaryKey;type:varchar(26)" json:"id"`
	ReviewID      string     `gorm:"type:varchar(26);not null;index:idx_access_review_decisions_review_decision,priority:1;index:idx_access_review_decisions_grant" json:"review_id"`
	GrantID       string     `gorm:"type:varchar(26);not null;index:idx_access_review_decisions_grant" json:"grant_id"`
	Decision      string     `gorm:"type:varchar(20);not null;default:'pending';index:idx_access_review_decisions_review_decision,priority:2" json:"decision"`
	DecidedBy     string     `gorm:"type:varchar(26)" json:"decided_by,omitempty"`
	AutoCertified bool       `gorm:"not null;default:false" json:"auto_certified"`
	Reason        string     `gorm:"type:text" json:"reason,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	// Note: no DeletedAt. Decisions are immutable for audit; a future
	// "delete decision" feature would need to UPDATE Decision to a
	// new "voided" state and add a void_reason column.
}

// TableName overrides the default plural so the table name is exactly
// access_review_decisions (matching the migration and PROPOSAL §9).
func (AccessReviewDecision) TableName() string {
	return "access_review_decisions"
}

// ReviewDecision enumerates the legal values of
// AccessReviewDecision.Decision. Strings are operator-visible in the
// admin UI translation table; renaming any of them is a database
// migration, not a refactor.
const (
	// DecisionPending is the initial state for grants that auto-
	// certification declined to handle and that no reviewer has
	// touched yet.
	DecisionPending = "pending"
	// DecisionCertify is "this grant is still appropriate; keep it".
	DecisionCertify = "certify"
	// DecisionRevoke is "this grant is no longer appropriate; revoke
	// it". AutoRevoke executes the revocation via the provisioning
	// service.
	DecisionRevoke = "revoke"
	// DecisionEscalate is "this grant needs a higher-authority
	// reviewer; route to the escalation path". CloseCampaign treats
	// escalated decisions as terminal: the row stays in escalate
	// state until a follow-up campaign re-evaluates it.
	DecisionEscalate = "escalate"
)
