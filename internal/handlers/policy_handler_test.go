package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func newPolicyEngine(t *testing.T) (http.Handler, *access.PolicyService) {
	t.Helper()
	db := newTestDB(t)
	svc := access.NewPolicyService(db)
	r := Router(Dependencies{PolicyService: svc})
	return r, svc
}

func validCreateDraftBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id":        "01H000000000000000WORKSPACE",
		"name":                "engineering ssh access",
		"description":         "engineers get SSH on prod-db hosts",
		"attributes_selector": map[string]string{"department": "engineering"},
		"resource_selector":   map[string]string{"category": "ssh-host"},
		"action":              models.PolicyActionAllow,
	}
}

func TestPolicyHandler_CreateDraft_HappyPath(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got models.Policy
	decodeJSON(t, w, &got)
	if got.ID == "" {
		t.Fatal("returned policy has empty ID")
	}
	if !got.IsDraft {
		t.Fatal("returned policy IsDraft = false; want true")
	}
}

func TestPolicyHandler_CreateDraft_InvalidJSON(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", "not-an-object")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPolicyHandler_CreateDraft_MissingWorkspaceReturns400(t *testing.T) {
	r, _ := newPolicyEngine(t)
	body := validCreateDraftBody()
	delete(body, "workspace_id")
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPolicyHandler_ListDrafts_HappyPath(t *testing.T) {
	r, _ := newPolicyEngine(t)
	// Seed via the create endpoint so we exercise the full HTTP path.
	if w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody()); w.Code != http.StatusCreated {
		t.Fatalf("seed: status = %d body=%s", w.Code, w.Body.String())
	}

	w := doJSON(t, r, http.MethodGet, "/workspace/policy/drafts?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var drafts []models.Policy
	decodeJSON(t, w, &drafts)
	if len(drafts) != 1 {
		t.Fatalf("got %d drafts; want 1", len(drafts))
	}
}

func TestPolicyHandler_ListDrafts_MissingWorkspaceReturns400(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodGet, "/workspace/policy/drafts", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPolicyHandler_GetPolicy_NotFoundReturns404(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodGet, "/workspace/policy/01H000000000000000NONEXIST?workspace_id=01H000000000000000WORKSPACE", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestPolicyHandler_GetPolicy_HappyPath(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed: status = %d body=%s", w.Code, w.Body.String())
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	getW := doJSON(t, r, http.MethodGet, "/workspace/policy/"+created.ID+"?workspace_id="+created.WorkspaceID, nil)
	if getW.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", getW.Code, getW.Body.String())
	}
	var fetched models.Policy
	decodeJSON(t, getW, &fetched)
	if fetched.ID != created.ID {
		t.Fatalf("fetched ID = %q; want %q", fetched.ID, created.ID)
	}
}

func TestPolicyHandler_Simulate_NotADraftIsConflict(t *testing.T) {
	r, _ := newPolicyEngine(t)
	// Create + simulate + promote to make a non-draft, then try to
	// simulate again.
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed: %d", w.Code)
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	if simW := doJSON(t, r, http.MethodPost, "/workspace/policy/"+created.ID+"/simulate",
		map[string]string{"workspace_id": created.WorkspaceID}); simW.Code != http.StatusOK {
		t.Fatalf("first simulate: %d body=%s", simW.Code, simW.Body.String())
	}
	if promW := doJSON(t, r, http.MethodPost, "/workspace/policy/"+created.ID+"/promote", map[string]string{
		"workspace_id":  created.WorkspaceID,
		"actor_user_id": "01H000000000000000ACTORUSRID",
	}); promW.Code != http.StatusOK {
		t.Fatalf("promote: %d body=%s", promW.Code, promW.Body.String())
	}

	w2 := doJSON(t, r, http.MethodPost, "/workspace/policy/"+created.ID+"/simulate",
		map[string]string{"workspace_id": created.WorkspaceID})
	if w2.Code != http.StatusConflict {
		t.Fatalf("re-simulate after promote: status = %d body=%s; want 409", w2.Code, w2.Body.String())
	}
}

func TestPolicyHandler_Simulate_HappyPath(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed: %d body=%s", w.Code, w.Body.String())
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	simW := doJSON(t, r, http.MethodPost, "/workspace/policy/"+created.ID+"/simulate",
		map[string]string{"workspace_id": created.WorkspaceID})
	if simW.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", simW.Code, simW.Body.String())
	}
	var report struct {
		Highlights []string        `json:"highlights"`
		Raw        json.RawMessage `json:"-"`
	}
	decodeJSON(t, simW, &report)
}

func TestPolicyHandler_Diff_HappyPath(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed draft: %d body=%s", w.Code, w.Body.String())
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	simW := doJSON(t, r, http.MethodPost, "/workspace/policy/"+created.ID+"/simulate",
		map[string]string{"workspace_id": created.WorkspaceID})
	if simW.Code != http.StatusOK {
		t.Fatalf("simulate: %d body=%s", simW.Code, simW.Body.String())
	}

	diffW := doJSON(t, r, http.MethodGet,
		"/workspace/policy/"+created.ID+"/diff?workspace_id="+created.WorkspaceID, nil)
	if diffW.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", diffW.Code, diffW.Body.String())
	}
	var diff access.PolicyDiffReport
	decodeJSON(t, diffW, &diff)
	if diff.Policy == nil || diff.Policy.ID != created.ID {
		t.Fatalf("diff.Policy = %+v; want id=%q", diff.Policy, created.ID)
	}
	if diff.Before.AppliesDraft {
		t.Fatal("Before.AppliesDraft = true; want false")
	}
	if !diff.After.AppliesDraft {
		t.Fatal("After.AppliesDraft = false; want true")
	}
	if diff.Delta == nil {
		t.Fatal("Delta = nil; want non-nil ImpactReport")
	}
}

func TestPolicyHandler_Diff_MissingWorkspaceIDReturns400(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodGet, "/workspace/policy/some-id/diff", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPolicyHandler_Diff_RequiresSimulate(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed: %d body=%s", w.Code, w.Body.String())
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	diffW := doJSON(t, r, http.MethodGet,
		"/workspace/policy/"+created.ID+"/diff?workspace_id="+created.WorkspaceID, nil)
	if diffW.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409 (ErrPolicyNotSimulated)", diffW.Code, diffW.Body.String())
	}
}

func TestPolicyHandler_Promote_RequiresSimulate(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed: %d", w.Code)
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	promW := doJSON(t, r, http.MethodPost, "/workspace/policy/"+created.ID+"/promote", map[string]string{
		"workspace_id":  created.WorkspaceID,
		"actor_user_id": "01H000000000000000ACTORUSRID",
	})
	if promW.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409 (ErrPolicyNotSimulated)", promW.Code, promW.Body.String())
	}
}

func TestPolicyHandler_TestAccess_HappyPath(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy", validCreateDraftBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("seed: %d body=%s", w.Code, w.Body.String())
	}
	var created models.Policy
	decodeJSON(t, w, &created)

	taW := doJSON(t, r, http.MethodPost, "/workspace/policy/test-access", map[string]string{
		"workspace_id":         created.WorkspaceID,
		"policy_id":            created.ID,
		"user_id":              "01H000000000000000USER0001",
		"resource_external_id": "host-001",
	})
	if taW.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", taW.Code, taW.Body.String())
	}
	var result access.TestAccessResult
	decodeJSON(t, taW, &result)
	// no team / resource seeded → user is not in scope, allowed=false
	if result.Allowed {
		t.Fatalf("Allowed = true; want false (no team/resource seeded)")
	}
}

func TestPolicyHandler_TestAccess_MissingFieldsReturns400(t *testing.T) {
	r, _ := newPolicyEngine(t)
	w := doJSON(t, r, http.MethodPost, "/workspace/policy/test-access",
		map[string]string{"workspace_id": "ws"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}
