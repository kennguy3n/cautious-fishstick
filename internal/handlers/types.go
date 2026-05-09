package handlers

import (
	"context"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// AccessGrantReader is the read-only interface that backs
// GET /access/grants. Defined here (rather than in the access
// service) so handlers depend on a narrow contract and tests can
// substitute an in-memory fake without spinning up a full DB. The
// AccessGrantQueryService in internal/services/access is the
// canonical production implementation.
type AccessGrantReader interface {
	ListGrants(ctx context.Context, q ListGrantsQuery) ([]models.AccessGrant, error)
}

// ListGrantsQuery is the input contract for AccessGrantReader.
// Either or both pointer fields may be nil ("no filter on this
// dimension"). At least one of them MUST be non-nil so the handler
// rejects unbounded "give me every grant in the database" queries.
type ListGrantsQuery struct {
	UserID      *string
	ConnectorID *string
}

// AIInvoker is the narrow interface backing /access/explain and
// /access/suggest. The production implementation is
// *aiclient.AIClient; tests substitute a stub via the same
// interface. Defined locally so the handler package does not
// import-cycle through anything non-trivial.
type AIInvoker interface {
	InvokeSkill(ctx context.Context, skillName string, payload interface{}) (*aiclient.SkillResponse, error)
}
