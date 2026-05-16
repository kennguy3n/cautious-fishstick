package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// newPAMAssetEngine wires a router with only the PAMAssetService
// dependency bound. Rate limiting is disabled so the tests can
// hammer the router in a loop without tripping the per-workspace
// quota.
func newPAMAssetEngine(t *testing.T) (http.Handler, *pam.PAMAssetService) {
	t.Helper()
	db := newTestDB(t)
	svc := pam.NewPAMAssetService(db)
	r := Router(Dependencies{PAMAssetService: svc, DisableRateLimiter: true})
	return r, svc
}

func validCreateAssetBody() map[string]interface{} {
	return map[string]interface{}{
		"workspace_id": "ws-1",
		"name":         "prod-db",
		"protocol":     "ssh",
		"host":         "10.0.0.1",
		"port":         22,
		"criticality":  "high",
	}
}

func TestPAMAssetHandler_CreateAsset_HappyPath(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	w := doJSON(t, r, http.MethodPost, "/pam/assets", validCreateAssetBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got models.PAMAsset
	decodeJSON(t, w, &got)
	if got.ID == "" {
		t.Fatal("returned asset has empty ID")
	}
	if got.Name != "prod-db" {
		t.Fatalf("name = %q; want prod-db", got.Name)
	}
	if got.Status != "active" {
		t.Fatalf("status = %q; want active", got.Status)
	}
}

func TestPAMAssetHandler_CreateAsset_ValidationFailureReturns400(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	body := validCreateAssetBody()
	body["protocol"] = "ftp" // invalid protocol
	w := doJSON(t, r, http.MethodPost, "/pam/assets", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMAssetHandler_CreateAsset_MissingWorkspaceReturns400(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	body := validCreateAssetBody()
	delete(body, "workspace_id")
	w := doJSON(t, r, http.MethodPost, "/pam/assets", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPAMAssetHandler_ListAssets_HappyPath(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	if w := doJSON(t, r, http.MethodPost, "/pam/assets", validCreateAssetBody()); w.Code != http.StatusCreated {
		t.Fatalf("seed: %d", w.Code)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/assets?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.PAMAsset
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("assets = %d; want 1", len(got))
	}
}

func TestPAMAssetHandler_ListAssets_MissingWorkspaceReturns400(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	w := doJSON(t, r, http.MethodGet, "/pam/assets", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestPAMAssetHandler_GetAsset_HappyPath(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/assets/"+asset.ID+"?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got models.PAMAsset
	decodeJSON(t, w, &got)
	if got.ID != asset.ID {
		t.Fatalf("id = %q; want %q", got.ID, asset.ID)
	}
}

func TestPAMAssetHandler_GetAsset_NotFoundReturns404(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	w := doJSON(t, r, http.MethodGet, "/pam/assets/nope?workspace_id=ws-1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestPAMAssetHandler_UpdateAsset_HappyPath(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	newName := "renamed"
	body := map[string]interface{}{
		"workspace_id": "ws-1",
		"name":         newName,
	}
	w := doJSON(t, r, http.MethodPut, "/pam/assets/"+asset.ID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got models.PAMAsset
	decodeJSON(t, w, &got)
	if got.Name != newName {
		t.Fatalf("name = %q; want %q", got.Name, newName)
	}
}

func TestPAMAssetHandler_DeleteAsset_HappyPath(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodDelete, "/pam/assets/"+asset.ID+"?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	// Verify soft-delete: GetAsset returns the row with status=archived.
	got, err := svc.GetAsset(context.Background(), "ws-1", asset.ID)
	if err != nil {
		t.Fatalf("post-delete read: %v", err)
	}
	if got.Status != "archived" {
		t.Fatalf("status = %q; want archived", got.Status)
	}
}

func TestPAMAssetHandler_CreateAccount_HappyPath(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id": "ws-1",
		"username":     "root",
		"account_type": "shared",
		"is_default":   true,
	}
	w := doJSON(t, r, http.MethodPost, "/pam/assets/"+asset.ID+"/accounts", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got models.PAMAccount
	decodeJSON(t, w, &got)
	if got.Username != "root" {
		t.Fatalf("username = %q; want root", got.Username)
	}
}

// TestPAMAssetHandler_CreateAccount_MissingWorkspaceReturns400 covers
// the workspace_id requirement that closes the cross-tenant account
// creation gap (Devin Review finding on PR #95).
func TestPAMAssetHandler_CreateAccount_MissingWorkspaceReturns400(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"username":     "root",
		"account_type": "shared",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/assets/"+asset.ID+"/accounts", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

// TestPAMAssetHandler_CreateAccount_CrossWorkspaceReturns404 asserts
// the workspace-scoped lookup at the service layer prevents a
// caller from one workspace from creating an account on an asset
// owned by another workspace even when the asset ULID is known.
func TestPAMAssetHandler_CreateAccount_CrossWorkspaceReturns404(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := map[string]interface{}{
		"workspace_id": "ws-other",
		"username":     "root",
		"account_type": "shared",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/assets/"+asset.ID+"/accounts", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestPAMAssetHandler_CreateAccount_OnMissingAssetReturns404(t *testing.T) {
	r, _ := newPAMAssetEngine(t)
	body := map[string]interface{}{
		"workspace_id": "ws-1",
		"username":     "root",
		"account_type": "shared",
	}
	w := doJSON(t, r, http.MethodPost, "/pam/assets/nope/accounts", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}

func TestPAMAssetHandler_ListAccounts_HappyPath(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.CreateAccount(context.Background(), "ws-1", asset.ID, pam.CreateAccountInput{
		Username: "alice", AccountType: "personal",
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/assets/"+asset.ID+"/accounts?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.PAMAccount
	decodeJSON(t, w, &got)
	if len(got) != 1 {
		t.Fatalf("accounts = %d; want 1", len(got))
	}
}

func TestPAMAssetHandler_ListAccounts_MissingWorkspaceReturns400(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/assets/"+asset.ID+"/accounts", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMAssetHandler_ListAccounts_CrossWorkspaceReturns404(t *testing.T) {
	r, svc := newPAMAssetEngine(t)
	asset, err := svc.CreateAsset(context.Background(), "ws-1", pam.CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.CreateAccount(context.Background(), "ws-1", asset.ID, pam.CreateAccountInput{
		Username: "alice", AccountType: "personal",
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	w := doJSON(t, r, http.MethodGet, "/pam/assets/"+asset.ID+"/accounts?workspace_id=ws-other", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s; want 404", w.Code, w.Body.String())
	}
}
