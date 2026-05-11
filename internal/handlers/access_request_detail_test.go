package handlers

import (
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestAccessRequestHandler_GetRequest_HappyPath round-trips the
// detail endpoint: create a request → approve it → fetch the detail
// view → assert the request row and at least one state-history row
// come back. The history row count is at least two because
// CreateRequest writes the "→ requested" entry and ApproveRequest
// writes "requested → approved".
func TestAccessRequestHandler_GetRequest_HappyPath(t *testing.T) {
	r, _ := newRequestEngine(t)

	createW := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed create: %d body=%s", createW.Code, createW.Body.String())
	}
	var created models.AccessRequest
	decodeJSON(t, createW, &created)

	if w := doJSON(t, r, http.MethodPost, "/access/requests/"+created.ID+"/approve", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
		"reason":        "manager approved",
	}); w.Code != http.StatusOK {
		t.Fatalf("seed approve: %d body=%s", w.Code, w.Body.String())
	}

	w := doJSON(t, r, http.MethodGet, "/access/requests/"+created.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got access.AccessRequestDetail
	decodeJSON(t, w, &got)
	if got.Request.ID != created.ID {
		t.Fatalf("Request.ID = %q; want %q", got.Request.ID, created.ID)
	}
	if got.Request.State != models.RequestStateApproved {
		t.Fatalf("Request.State = %q; want %q", got.Request.State, models.RequestStateApproved)
	}
	if len(got.History) < 2 {
		t.Fatalf("len(History) = %d; want >= 2 (created + approve)", len(got.History))
	}
}

// TestAccessRequestHandler_GetRequest_NotFound asserts the
// ErrRequestNotFound sentinel maps to 404 through the error
// envelope.
func TestAccessRequestHandler_GetRequest_NotFound(t *testing.T) {
	r, _ := newRequestEngine(t)
	w := doJSON(t, r, http.MethodGet, "/access/requests/01H000000000000000NONEXIST", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}
