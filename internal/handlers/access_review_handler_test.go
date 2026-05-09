package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func newReviewEngine(t *testing.T) (http.Handler, *access.AccessReviewService) {
	t.Helper()
	db := newTestDB(t)
	svc := access.NewAccessReviewService(db, nil)
	r := Router(Dependencies{AccessReviewService: svc})

	// Seed one active grant so StartCampaign has something to enroll.
	now := time.Now()
	g := &models.AccessGrant{
		ID:                 "01H00000000000000GRANT0001",
		WorkspaceID:        "01H000000000000000WORKSPACE",
		UserID:             "01H000000000000000USER0001",
		ConnectorID:        "01H000000000000000CONN0001",
		ResourceExternalID: "host-001",
		Role:               "viewer",
		GrantedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return r, svc
}

func startCampaignBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id":         "01H000000000000000WORKSPACE",
		"name":                 "Q4 access check-up",
		"due_at":               time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"auto_certify_enabled": false,
	}
}

func TestAccessReviewHandler_StartCampaign_HappyPath(t *testing.T) {
	r, _ := newReviewEngine(t)
	w := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var env struct {
		Review    models.AccessReview            `json:"review"`
		Decisions []models.AccessReviewDecision  `json:"decisions"`
	}
	decodeJSON(t, w, &env)
	if env.Review.ID == "" {
		t.Fatal("review id is empty")
	}
	if len(env.Decisions) != 1 {
		t.Fatalf("got %d decisions; want 1", len(env.Decisions))
	}
}

func TestAccessReviewHandler_StartCampaign_MissingNameReturns400(t *testing.T) {
	r, _ := newReviewEngine(t)
	body := startCampaignBody()
	delete(body, "name")
	w := doJSON(t, r, http.MethodPost, "/access/reviews", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestAccessReviewHandler_SubmitDecision_NotFoundReturns404(t *testing.T) {
	r, _ := newReviewEngine(t)
	w := doJSON(t, r, http.MethodPost, "/access/reviews/01H000000000000NONEXIST00/decisions", map[string]string{
		"grant_id":   "01H00000000000000GRANT0001",
		"decision":   "certify",
		"decided_by": "01H000000000000000ACTORUSRID",
		"reason":     "looks fine",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestAccessReviewHandler_SubmitDecision_HappyPath(t *testing.T) {
	r, _ := newReviewEngine(t)
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	if startW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", startW.Code)
	}
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodPost, "/access/reviews/"+env.Review.ID+"/decisions", map[string]string{
		"grant_id":   "01H00000000000000GRANT0001",
		"decision":   "certify",
		"decided_by": "01H000000000000000ACTORUSRID",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestAccessReviewHandler_SubmitDecision_InvalidDecisionReturns409(t *testing.T) {
	r, _ := newReviewEngine(t)
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodPost, "/access/reviews/"+env.Review.ID+"/decisions", map[string]string{
		"grant_id":   "01H00000000000000GRANT0001",
		"decision":   "bogus",
		"decided_by": "01H000000000000000ACTORUSRID",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409 (ErrInvalidDecision)", w.Code, w.Body.String())
	}
}

func TestAccessReviewHandler_Close_HappyPath(t *testing.T) {
	r, _ := newReviewEngine(t)
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodPost, "/access/reviews/"+env.Review.ID+"/close", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestAccessReviewHandler_Close_AlreadyClosedReturns409(t *testing.T) {
	r, _ := newReviewEngine(t)
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	if w := doJSON(t, r, http.MethodPost, "/access/reviews/"+env.Review.ID+"/close", nil); w.Code != http.StatusOK {
		t.Fatalf("first close: %d", w.Code)
	}
	w := doJSON(t, r, http.MethodPost, "/access/reviews/"+env.Review.ID+"/close", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409", w.Code, w.Body.String())
	}
}

func TestAccessReviewHandler_AutoRevoke_NoProvisioningReturns503(t *testing.T) {
	// AccessReviewService was constructed with provisioningSvc=nil
	// (review-only flows), so AutoRevoke surfaces
	// ErrProvisioningUnavailable.
	r, _ := newReviewEngine(t)
	startW := doJSON(t, r, http.MethodPost, "/access/reviews", startCampaignBody())
	var env struct {
		Review models.AccessReview `json:"review"`
	}
	decodeJSON(t, startW, &env)

	w := doJSON(t, r, http.MethodPost, "/access/reviews/"+env.Review.ID+"/auto-revoke", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Code, w.Body.String())
	}
}
