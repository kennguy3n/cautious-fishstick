package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestGetCampaignMetrics_MixedDecisions exercises the metrics math
// against a campaign with one decision in every supported state +
// one auto-certified row. The exact counts and the
// auto_certification_rate are asserted.
func TestGetCampaignMetrics_MixedDecisions(t *testing.T) {
	t.Parallel()
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"

	for i := 0; i < 5; i++ {
		seedActiveGrant(t, db,
			"01H000000000000000GRANTM"+string(rune('A'+i)),
			ws, "u-grant-"+string(rune('a'+i)), conn, "viewer", "host-"+string(rune('a'+i)))
	}

	svc := NewAccessReviewService(db, nil)
	review, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "metrics test",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter: scopeJSON(t, map[string]string{"connector_id": conn}),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 5 {
		t.Fatalf("decisions = %d; want 5", len(decisions))
	}

	// Drive to: 1 pending, 1 manual certify, 1 auto certify,
	// 1 revoke, 1 escalate.
	now := time.Now().UTC()
	cases := []struct {
		decision      string
		autoCertified bool
	}{
		{models.DecisionCertify, false},
		{models.DecisionCertify, true},
		{models.DecisionRevoke, false},
		{models.DecisionEscalate, false},
	}
	for i, tc := range cases {
		if err := db.Model(&models.AccessReviewDecision{}).
			Where("id = ?", decisions[i].ID).
			Updates(map[string]interface{}{
				"decision":       tc.decision,
				"auto_certified": tc.autoCertified,
				"decided_at":     now,
				"updated_at":     now,
			}).Error; err != nil {
			t.Fatalf("update decision %d: %v", i, err)
		}
	}
	// decisions[4] stays pending.

	got, err := svc.GetCampaignMetrics(context.Background(), review.ID)
	if err != nil {
		t.Fatalf("GetCampaignMetrics: %v", err)
	}
	if got.TotalDecisions != 5 {
		t.Errorf("Total = %d; want 5", got.TotalDecisions)
	}
	if got.Pending != 1 {
		t.Errorf("Pending = %d; want 1", got.Pending)
	}
	if got.Certified != 2 {
		t.Errorf("Certified = %d; want 2 (manual + auto)", got.Certified)
	}
	if got.AutoCertified != 1 {
		t.Errorf("AutoCertified = %d; want 1", got.AutoCertified)
	}
	if got.Revoked != 1 {
		t.Errorf("Revoked = %d; want 1", got.Revoked)
	}
	if got.Escalated != 1 {
		t.Errorf("Escalated = %d; want 1", got.Escalated)
	}
	const want = 0.2 // 1 / 5
	if got.AutoCertificationRate != want {
		t.Errorf("AutoCertificationRate = %v; want %v", got.AutoCertificationRate, want)
	}
}

// TestGetCampaignMetrics_EmptyCampaign asserts a campaign with no
// decisions reports a 0.0 auto-certification rate (not NaN).
func TestGetCampaignMetrics_EmptyCampaign(t *testing.T) {
	t.Parallel()
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	svc := NewAccessReviewService(db, nil)

	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: ws,
		Name:        "empty",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	got, err := svc.GetCampaignMetrics(context.Background(), review.ID)
	if err != nil {
		t.Fatalf("GetCampaignMetrics: %v", err)
	}
	if got.TotalDecisions != 0 {
		t.Errorf("TotalDecisions = %d; want 0", got.TotalDecisions)
	}
	if got.AutoCertificationRate != 0.0 {
		t.Errorf("AutoCertificationRate = %v; want 0.0", got.AutoCertificationRate)
	}
}

// TestGetCampaignMetrics_NotFound asserts an unknown review surfaces
// ErrReviewNotFound.
func TestGetCampaignMetrics_NotFound(t *testing.T) {
	t.Parallel()
	svc := NewAccessReviewService(newReviewTestDB(t), nil)
	_, err := svc.GetCampaignMetrics(context.Background(), "01HMISSINGREVIEWAAAAAAAAAA")
	if !errors.Is(err, ErrReviewNotFound) {
		t.Errorf("err = %v; want errors.Is(err, ErrReviewNotFound)", err)
	}
}

// TestSetAutoCertifyEnabled_Toggle asserts the column flips on/off
// across two PATCHes.
func TestSetAutoCertifyEnabled_Toggle(t *testing.T) {
	t.Parallel()
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)

	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        "01H000000000000000WORKSPACE",
		Name:               "toggle",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		AutoCertifyEnabled: true,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if err := svc.SetAutoCertifyEnabled(context.Background(), review.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	var refreshed models.AccessReview
	if err := db.Where("id = ?", review.ID).First(&refreshed).Error; err != nil {
		t.Fatalf("re-fetch: %v", err)
	}
	if refreshed.AutoCertifyEnabled {
		t.Errorf("AutoCertifyEnabled = true after disable; want false")
	}
	if err := svc.SetAutoCertifyEnabled(context.Background(), review.ID, true); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if err := db.Where("id = ?", review.ID).First(&refreshed).Error; err != nil {
		t.Fatalf("re-fetch: %v", err)
	}
	if !refreshed.AutoCertifyEnabled {
		t.Errorf("AutoCertifyEnabled = false after re-enable; want true")
	}
}

// TestSetAutoCertifyEnabled_ClosedReview asserts the toggle is
// rejected on closed campaigns with ErrReviewClosed.
func TestSetAutoCertifyEnabled_ClosedReview(t *testing.T) {
	t.Parallel()
	db := newReviewTestDB(t)
	svc := NewAccessReviewService(db, nil)

	review, _, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		Name:        "to-close",
		DueAt:       time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if err := svc.CloseCampaign(context.Background(), review.ID); err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}
	err = svc.SetAutoCertifyEnabled(context.Background(), review.ID, false)
	if !errors.Is(err, ErrReviewClosed) {
		t.Errorf("err = %v; want errors.Is(err, ErrReviewClosed)", err)
	}
}
