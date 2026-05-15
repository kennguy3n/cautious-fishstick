package access

import (
	"context"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// ReviewAutomator is the narrow contract AccessReviewService uses to
// invoke the access_review_automation skill on the access-ai-agent.
// The aiclient.AIClient + AutomateReviewWithFallback wrapper satisfy
// it; tests stub it directly without spinning up an HTTP server.
//
// The two-return-tuple mirrors AnomalyDetector / RiskAssessor: the
// returned decision/reason tuple is the AI's verdict (one of
// "certify", "revoke", "escalate", or empty when the AI returned an
// unexpected value) and ok signals whether the AI agent was
// reachable. Callers MUST treat ok=false as "AI is down; leave the
// decision pending and continue".
//
// Per docs/internal/PHASES.md Phase 5 the wire-in MUST be best-effort: an
// unreachable AI agent leaves every decision pending and the
// campaign proceeds normally.
type ReviewAutomator interface {
	AutomateReview(ctx context.Context, payload aiclient.ReviewAutomationPayload) (decision string, reason string, ok bool)
}

// ReviewAutomatorAdapter wraps *aiclient.AIClient so the
// AccessReviewService can depend on the narrow ReviewAutomator
// contract without importing aiclient directly. The adapter
// composes AutomateReviewWithFallback so the auto-certification
// loop gets the PROPOSAL §5.3 fallback for free.
//
// Inner may be nil — in that case AutomateReview returns the
// fallback ("", "", false) so dev / test binaries stay healthy
// without an AI agent wired up. This keeps the wire-in cheap to
// add unconditionally at boot in cmd/ztna-api.
type ReviewAutomatorAdapter struct {
	Inner *aiclient.AIClient
}

// AutomateReview satisfies ReviewAutomator by forwarding to
// aiclient.AutomateReviewWithFallback and unpacking the response
// into the (decision, reason, ok) tuple AccessReviewService
// expects.
func (a *ReviewAutomatorAdapter) AutomateReview(ctx context.Context, payload aiclient.ReviewAutomationPayload) (string, string, bool) {
	if a == nil {
		return "", "", false
	}
	return aiclient.AutomateReviewWithFallback(ctx, a.Inner, payload)
}
