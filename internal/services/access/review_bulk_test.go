package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// seedReviewWithGrants returns a review whose decision rows are
// keyed by the supplied grant IDs. All grants start in "pending"
// state. The reviewer-side decided_by string is the canonical test
// actor.
func seedReviewWithGrants(t *testing.T, svc *AccessReviewService, grantIDs []string) (string, []string) {
	t.Helper()
	now := time.Now()
	for _, id := range grantIDs {
		if err := svc.db.Create(&models.AccessGrant{
			ID:                 id,
			WorkspaceID:        "01H000000000000000WORKSPACE",
			UserID:             "01H000000000000000USER0001",
			ConnectorID:        "01H000000000000000CONN0001",
			ResourceExternalID: "host-001",
			Role:               "viewer",
			GrantedAt:          now,
			CreatedAt:          now,
			UpdatedAt:          now,
		}).Error; err != nil {
			t.Fatalf("seed grant %s: %v", id, err)
		}
	}
	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		Name:        "bulk campaign",
		DueAt:       time.Now().Add(7 * 24 * time.Hour).UTC(),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	return review.ID, grantIDs
}

func TestAccessReviewService_BulkSubmitDecisions_AllSucceed(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)
	reviewID, grants := seedReviewWithGrants(t, svc, []string{
		"01H00000000000000GRANT001",
		"01H00000000000000GRANT002",
		"01H00000000000000GRANT003",
	})

	in := []BulkDecisionInput{
		{GrantID: grants[0], Decision: models.DecisionCertify, Reason: "ok"},
		{GrantID: grants[1], Decision: models.DecisionCertify, Reason: "ok"},
		{GrantID: grants[2], Decision: models.DecisionCertify, Reason: "ok"},
	}
	results, summary, err := svc.BulkSubmitDecisions(context.Background(), reviewID, "01H000000000000000ACTORUSR", in)
	if err != nil {
		t.Fatalf("BulkSubmitDecisions: %v", err)
	}
	if summary.Total != 3 || summary.Succeeded != 3 || summary.Failed != 0 {
		t.Fatalf("summary = %+v; want all-succeeded", summary)
	}
	for _, r := range results {
		if !r.Success {
			t.Fatalf("row %+v not success", r)
		}
	}
}

func TestAccessReviewService_BulkSubmitDecisions_PartialFailure(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)
	reviewID, grants := seedReviewWithGrants(t, svc, []string{
		"01H00000000000000GRANT001",
		"01H00000000000000GRANT002",
	})

	in := []BulkDecisionInput{
		{GrantID: grants[0], Decision: models.DecisionCertify},
		{GrantID: "01H00000000000000UNKNOWN0", Decision: models.DecisionCertify},
		{GrantID: grants[1], Decision: "not-a-real-decision"},
	}
	results, summary, err := svc.BulkSubmitDecisions(context.Background(), reviewID, "01H000000000000000ACTORUSR", in)
	if err != nil {
		t.Fatalf("BulkSubmitDecisions returned envelope err = %v; want nil (per-row failures only)", err)
	}
	if summary.Total != 3 || summary.Succeeded != 1 || summary.Failed != 2 {
		t.Fatalf("summary = %+v; want 1 ok 2 failed", summary)
	}
	if !results[0].Success {
		t.Fatal("row 0 should succeed")
	}
	if results[1].Success || results[1].Error == "" {
		t.Fatal("row 1 should fail with non-empty error (unknown grant id)")
	}
	if results[2].Success || results[2].Error == "" {
		t.Fatal("row 2 should fail with non-empty error (invalid decision)")
	}
}

func TestAccessReviewService_BulkSubmitDecisions_ValidationErrors(t *testing.T) {
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)

	cases := []struct {
		name      string
		reviewID  string
		decidedBy string
		decisions []BulkDecisionInput
	}{
		{"missing review_id", "", "actor", []BulkDecisionInput{{GrantID: "g", Decision: models.DecisionCertify}}},
		{"missing decided_by", "review-1", "", []BulkDecisionInput{{GrantID: "g", Decision: models.DecisionCertify}}},
		{"empty decisions", "review-1", "actor", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.BulkSubmitDecisions(context.Background(), tc.reviewID, tc.decidedBy, tc.decisions)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v; want ErrValidation", err)
			}
		})
	}
}
