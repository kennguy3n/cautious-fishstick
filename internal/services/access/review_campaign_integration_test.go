package access

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestReviewCampaign_FullLifecycle_Integration wires every real
// service (AccessReviewService, AccessProvisioningService) and runs
// the full review-campaign lifecycle:
//
//  1. Seed three active grants in the workspace.
//  2. Launch a real review campaign covering all three.
//  3. Submit a real "certify" decision and a real "revoke" decision.
//  4. Run real AutoRevoke; verify the revoked grant has a real
//     revoked_at timestamp in DB and the connector saw the revoke
//     call.
//  5. Call real GetCampaignMetrics; verify the tallies match the
//     decisions submitted.
//
// MockAccessConnector is the ONLY mock; all DB writes and state
// transitions are real.
func TestReviewCampaign_FullLifecycle_Integration(t *testing.T) {
	const provider = "mock_review_campaign_integration"
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01HCONN00REVIEWINTEGRATION1"

	db := newReviewTestDB(t)
	seedE2EConnector(t, db, conn, provider)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	seedActiveGrant(t, db, "01H000000000RVWGRANT00001", ws, "u1", conn, "viewer", "host-a")
	seedActiveGrant(t, db, "01H000000000RVWGRANT00002", ws, "u2", conn, "viewer", "host-b")
	seedActiveGrant(t, db, "01H000000000RVWGRANT00003", ws, "u3", conn, "admin", "host-c")

	provSvc := NewAccessProvisioningService(db)
	svc := NewAccessReviewService(db, provSvc)

	review, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "Quarterly access review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: false,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 3 {
		t.Fatalf("decisions = %d; want 3", len(decisions))
	}
	if review.State != models.ReviewStateOpen {
		t.Fatalf("review state = %q; want open", review.State)
	}

	// Certify the first decision, revoke the second, leave the third
	// pending so we can verify AutoRevoke only revokes the explicitly-
	// revoked decision.
	if err := svc.SubmitDecision(
		context.Background(),
		review.ID,
		decisions[0].GrantID,
		models.DecisionCertify,
		"01HACTOR000000000000000001",
		"certified by manager",
	); err != nil {
		t.Fatalf("SubmitDecision certify: %v", err)
	}
	if err := svc.SubmitDecision(
		context.Background(),
		review.ID,
		decisions[1].GrantID,
		models.DecisionRevoke,
		"01HACTOR000000000000000002",
		"revoke per quarterly review",
	); err != nil {
		t.Fatalf("SubmitDecision revoke: %v", err)
	}

	// AutoRevoke walks every "revoke" decision whose grant is still
	// active and executes a real revoke through the provisioning
	// service.
	if err := svc.AutoRevoke(context.Background(), review.ID); err != nil {
		t.Fatalf("AutoRevoke: %v", err)
	}

	// The revoke decision's grant must have a real revoked_at
	// timestamp; the certify decision's grant must remain active.
	var revokedGrant models.AccessGrant
	if err := db.Where("id = ?", decisions[1].GrantID).First(&revokedGrant).Error; err != nil {
		t.Fatalf("reload revoked grant: %v", err)
	}
	if revokedGrant.RevokedAt == nil {
		t.Fatalf("revoked grant has no revoked_at: %+v", revokedGrant)
	}

	var certifiedGrant models.AccessGrant
	if err := db.Where("id = ?", decisions[0].GrantID).First(&certifiedGrant).Error; err != nil {
		t.Fatalf("reload certified grant: %v", err)
	}
	if certifiedGrant.RevokedAt != nil {
		t.Fatalf("certified grant unexpectedly revoked at %v", certifiedGrant.RevokedAt)
	}

	// The connector must have received exactly one RevokeAccess call.
	if mock.RevokeAccessCalls != 1 {
		t.Fatalf("RevokeAccess calls = %d; want 1", mock.RevokeAccessCalls)
	}

	// Metrics reflect the real decisions submitted.
	metrics, err := svc.GetCampaignMetrics(context.Background(), review.ID)
	if err != nil {
		t.Fatalf("GetCampaignMetrics: %v", err)
	}
	if metrics.TotalDecisions != 3 {
		t.Fatalf("TotalDecisions = %d; want 3", metrics.TotalDecisions)
	}
	if metrics.Certified != 1 {
		t.Fatalf("Certified = %d; want 1", metrics.Certified)
	}
	if metrics.Revoked != 1 {
		t.Fatalf("Revoked = %d; want 1", metrics.Revoked)
	}
	if metrics.Pending != 1 {
		t.Fatalf("Pending = %d; want 1", metrics.Pending)
	}
}
