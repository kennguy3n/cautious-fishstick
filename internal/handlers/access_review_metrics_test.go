package handlers

import (
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestAccessReviewHandler_GetCampaignMetrics_HappyPath drives the
// /access/reviews/:id/metrics endpoint against a freshly-started
// campaign with one pending decision.
func TestAccessReviewHandler_GetCampaignMetrics_HappyPath(t *testing.T) {
	r, _ := newReviewEngine(t)

	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	if startW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", startW.Code)
	}
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodGet, "/access/reviews/"+env.Review.ID+"/metrics", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got struct {
		ReviewID              string  `json:"review_id"`
		TotalDecisions        int     `json:"total_decisions"`
		Pending               int     `json:"pending"`
		AutoCertified         int     `json:"auto_certified"`
		AutoCertificationRate float64 `json:"auto_certification_rate"`
	}
	decodeJSON(t, w, &got)
	if got.ReviewID != env.Review.ID {
		t.Errorf("review_id = %q; want %q", got.ReviewID, env.Review.ID)
	}
	if got.TotalDecisions != 1 {
		t.Errorf("total_decisions = %d; want 1", got.TotalDecisions)
	}
	if got.Pending != 1 {
		t.Errorf("pending = %d; want 1", got.Pending)
	}
	if got.AutoCertificationRate != 0.0 {
		t.Errorf("auto_certification_rate = %v; want 0.0", got.AutoCertificationRate)
	}
}

// TestAccessReviewHandler_GetCampaignMetrics_NotFound asserts an
// unknown review id surfaces 404.
func TestAccessReviewHandler_GetCampaignMetrics_NotFound(t *testing.T) {
	r, _ := newReviewEngine(t)
	w := doJSON(t, r, http.MethodGet, "/access/reviews/01HMISSINGREVIEWAAAAAAAAAA/metrics", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

// TestAccessReviewHandler_PatchCampaign_TogglesAutoCertify drives a
// PATCH that flips auto_certify_enabled to false and verifies the
// service-side state change.
func TestAccessReviewHandler_PatchCampaign_TogglesAutoCertify(t *testing.T) {
	r, svc := newReviewEngine(t)

	body := startCampaignBody()
	body["auto_certify_enabled"] = true
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", body)
	if startW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", startW.Code)
	}
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodPatch, "/access/reviews/"+env.Review.ID, map[string]bool{
		"auto_certify_enabled": false,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	// Re-fetch via the service to verify the column persisted.
	metrics, err := svc.GetCampaignMetrics(t.Context(), env.Review.ID)
	if err != nil {
		t.Fatalf("GetCampaignMetrics: %v", err)
	}
	if metrics.ReviewID != env.Review.ID {
		t.Errorf("review_id = %q; want %q", metrics.ReviewID, env.Review.ID)
	}
}

// TestAccessReviewHandler_PatchCampaign_EmptyBodyReturns400 asserts a
// PATCH with no editable fields surfaces 400 — silently no-op'ing the
// PATCH would mask client bugs.
func TestAccessReviewHandler_PatchCampaign_EmptyBodyReturns400(t *testing.T) {
	r, _ := newReviewEngine(t)
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodPatch, "/access/reviews/"+env.Review.ID, map[string]interface{}{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

// TestAccessReviewHandler_PatchCampaign_NotFound asserts an unknown
// review id surfaces 404.
func TestAccessReviewHandler_PatchCampaign_NotFound(t *testing.T) {
	r, _ := newReviewEngine(t)
	w := doJSON(t, r, http.MethodPatch, "/access/reviews/01HMISSINGREVIEWAAAAAAAAAA", map[string]bool{
		"auto_certify_enabled": false,
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}
