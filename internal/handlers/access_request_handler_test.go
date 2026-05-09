package handlers

import (
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func newRequestEngine(t *testing.T) (http.Handler, *access.AccessRequestService) {
	t.Helper()
	db := newTestDB(t)
	svc := access.NewAccessRequestService(db)
	r := Router(Dependencies{AccessRequestService: svc})
	return r, svc
}

func validCreateRequestBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id":         "01H000000000000000WORKSPACE",
		"requester_user_id":    "01H000000000000000REQUESTER",
		"target_user_id":       "01H000000000000000TARGETUSR",
		"connector_id":         "01H000000000000000CONNECTOR",
		"resource_external_id": "projects/foo",
		"role":                 "viewer",
		"justification":        "weekly on-call rotation needs read-only access",
	}
}

func TestAccessRequestHandler_Create_HappyPath(t *testing.T) {
	r, _ := newRequestEngine(t)
	w := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got models.AccessRequest
	decodeJSON(t, w, &got)
	if got.ID == "" {
		t.Fatal("returned request has empty ID")
	}
	if got.State != models.RequestStateRequested {
		t.Fatalf("State = %q; want %q", got.State, models.RequestStateRequested)
	}
}

func TestAccessRequestHandler_Create_MissingFieldReturns400(t *testing.T) {
	r, _ := newRequestEngine(t)
	body := validCreateRequestBody()
	delete(body, "workspace_id")
	w := doJSON(t, r, http.MethodPost, "/access/requests", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestAccessRequestHandler_List_HappyPath(t *testing.T) {
	r, _ := newRequestEngine(t)
	if w := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody()); w.Code != http.StatusCreated {
		t.Fatalf("seed: %d", w.Code)
	}
	w := doJSON(t, r, http.MethodGet, "/access/requests?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.AccessRequest
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("got %d requests; want 1", len(got))
	}
}

func TestAccessRequestHandler_List_MissingWorkspaceReturns400(t *testing.T) {
	r, _ := newRequestEngine(t)
	w := doJSON(t, r, http.MethodGet, "/access/requests", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestAccessRequestHandler_List_FiltersByState(t *testing.T) {
	r, _ := newRequestEngine(t)
	if w := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody()); w.Code != http.StatusCreated {
		t.Fatalf("seed: %d", w.Code)
	}
	w := doJSON(t, r, http.MethodGet, "/access/requests?workspace_id=01H000000000000000WORKSPACE&state=denied", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	var got []models.AccessRequest
	decodeJSON(t, w, &got)
	if len(got) != 0 {
		t.Fatalf("got %d denied requests; want 0", len(got))
	}
}

func TestAccessRequestHandler_Approve_HappyPath(t *testing.T) {
	r, _ := newRequestEngine(t)
	createW := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody())
	if createW.Code != http.StatusCreated {
		t.Fatalf("seed: %d", createW.Code)
	}
	var created models.AccessRequest
	decodeJSON(t, createW, &created)

	w := doJSON(t, r, http.MethodPost, "/access/requests/"+created.ID+"/approve", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
		"reason":        "approved by manager",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestAccessRequestHandler_Approve_NotFoundReturns404(t *testing.T) {
	r, _ := newRequestEngine(t)
	w := doJSON(t, r, http.MethodPost, "/access/requests/01H000000000000000NONEXIST/approve", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestAccessRequestHandler_Deny_HappyPath(t *testing.T) {
	r, _ := newRequestEngine(t)
	createW := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody())
	var created models.AccessRequest
	decodeJSON(t, createW, &created)

	w := doJSON(t, r, http.MethodPost, "/access/requests/"+created.ID+"/deny", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
		"reason":        "denied",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestAccessRequestHandler_Cancel_HappyPath(t *testing.T) {
	r, _ := newRequestEngine(t)
	createW := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody())
	var created models.AccessRequest
	decodeJSON(t, createW, &created)

	w := doJSON(t, r, http.MethodPost, "/access/requests/"+created.ID+"/cancel", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestAccessRequestHandler_Cancel_AfterDeniedIsConflict(t *testing.T) {
	r, _ := newRequestEngine(t)
	createW := doJSON(t, r, http.MethodPost, "/access/requests", validCreateRequestBody())
	var created models.AccessRequest
	decodeJSON(t, createW, &created)

	if w := doJSON(t, r, http.MethodPost, "/access/requests/"+created.ID+"/deny", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
	}); w.Code != http.StatusOK {
		t.Fatalf("deny: %d body=%s", w.Code, w.Body.String())
	}

	w := doJSON(t, r, http.MethodPost, "/access/requests/"+created.ID+"/cancel", map[string]string{
		"actor_user_id": "01H000000000000000ACTORUSRID",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409 (ErrInvalidStateTransition)", w.Code, w.Body.String())
	}
}
