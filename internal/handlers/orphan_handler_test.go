package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// fakeOrphanService implements OrphanReconcilerReader for handler tests.
type fakeOrphanService struct {
	rows         []models.AccessOrphanAccount
	dryRunRows   []models.AccessOrphanAccount
	listCalls    atomic.Int64
	reconCalls   atomic.Int64
	dryRunCalls  atomic.Int64
	revokeCalls  atomic.Int64
	dismissCalls atomic.Int64
	ackCalls     atomic.Int64
	revokeErr    error
	dismissErr   error
	ackErr       error
	reconErr     error
	dryRunErr    error
}

func (f *fakeOrphanService) ListOrphans(_ context.Context, workspaceID, status string) ([]models.AccessOrphanAccount, error) {
	f.listCalls.Add(1)
	out := make([]models.AccessOrphanAccount, 0, len(f.rows))
	for _, r := range f.rows {
		if r.WorkspaceID != workspaceID {
			continue
		}
		if status != "" && r.Status != status {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
func (f *fakeOrphanService) ReconcileWorkspace(_ context.Context, _ string) ([]models.AccessOrphanAccount, error) {
	f.reconCalls.Add(1)
	return f.rows, f.reconErr
}
func (f *fakeOrphanService) ReconcileWorkspaceDryRun(_ context.Context, _ string) ([]models.AccessOrphanAccount, error) {
	f.dryRunCalls.Add(1)
	if f.dryRunRows != nil {
		return f.dryRunRows, f.dryRunErr
	}
	return f.rows, f.dryRunErr
}
func (f *fakeOrphanService) RevokeOrphan(_ context.Context, _ string) error {
	f.revokeCalls.Add(1)
	return f.revokeErr
}
func (f *fakeOrphanService) DismissOrphan(_ context.Context, _ string) error {
	f.dismissCalls.Add(1)
	return f.dismissErr
}
func (f *fakeOrphanService) AcknowledgeOrphan(_ context.Context, _ string) error {
	f.ackCalls.Add(1)
	return f.ackErr
}

// TestOrphanHandler_List_FiltersByWorkspace asserts the list route
// returns only the rows matching the workspace_id query string,
// using the SN360 "unused_app_accounts" JSON envelope.
func TestOrphanHandler_List_FiltersByWorkspace(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeOrphanService{
		rows: []models.AccessOrphanAccount{
			{ID: "o1", WorkspaceID: "ws1", ConnectorID: "c1", UserExternalID: "u1", Status: models.OrphanStatusDetected, DetectedAt: now},
			{ID: "o2", WorkspaceID: "ws2", ConnectorID: "c2", UserExternalID: "u2", Status: models.OrphanStatusDetected, DetectedAt: now},
		},
	}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/access/orphans?workspace_id=ws1", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	var body struct {
		Rows []unusedAccountView `json:"unused_app_accounts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rows) != 1 || body.Rows[0].ID != "o1" {
		t.Errorf("rows = %+v; want one row with id=o1", body.Rows)
	}
}

// TestOrphanHandler_List_RequiresWorkspaceID asserts the missing
// query parameter case returns 400.
func TestOrphanHandler_List_RequiresWorkspaceID(t *testing.T) {
	fake := &fakeOrphanService{}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/access/orphans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

// TestOrphanHandler_Reconcile_TriggersWorkspace asserts the POST
// reconcile route calls ReconcileWorkspace.
func TestOrphanHandler_Reconcile_TriggersWorkspace(t *testing.T) {
	fake := &fakeOrphanService{}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"workspace_id":"ws1"}`)
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/reconcile", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if got := fake.reconCalls.Load(); got != 1 {
		t.Errorf("Reconcile calls = %d; want 1", got)
	}
}

// TestOrphanHandler_Reconcile_DryRun asserts dry_run=true routes
// to ReconcileWorkspaceDryRun and surfaces the dry_run flag on the
// response.
func TestOrphanHandler_Reconcile_DryRun(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeOrphanService{
		dryRunRows: []models.AccessOrphanAccount{
			{WorkspaceID: "ws1", ConnectorID: "c1", UserExternalID: "u-dry", Status: models.OrphanStatusDetected, DetectedAt: now},
		},
	}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"workspace_id":"ws1","dry_run":true}`)
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/reconcile", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if got := fake.dryRunCalls.Load(); got != 1 {
		t.Errorf("DryRun calls = %d; want 1", got)
	}
	if got := fake.reconCalls.Load(); got != 0 {
		t.Errorf("Reconcile (non-dry-run) calls = %d; want 0", got)
	}
	var body2 struct {
		Rows   []unusedAccountView `json:"unused_app_accounts"`
		DryRun bool                `json:"dry_run"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body2.DryRun {
		t.Errorf("response dry_run = false; want true")
	}
	if len(body2.Rows) != 1 || body2.Rows[0].AppUserID != "u-dry" {
		t.Errorf("rows = %+v; want one row with app_user_id=u-dry", body2.Rows)
	}
}

// TestOrphanHandler_Reconcile_PartialFailure_WetRun asserts that when
// the reconciler returns rows from successful connectors alongside an
// aggregated error from failed connectors (the round-9 best-effort
// contract — see docs/architecture.md §12), the handler surfaces
// the rows with HTTP 200 and exposes the aggregated error via the
// "partial_failure" field rather than discarding the partial set with
// a 500. Without this, operators relying on POST /access/orphans/
// reconcile would lose the set of orphans surfaced by every healthy
// connector whenever a single connector in the workspace flaked.
func TestOrphanHandler_Reconcile_PartialFailure_WetRun(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeOrphanService{
		rows: []models.AccessOrphanAccount{
			{ID: "o1", WorkspaceID: "ws1", ConnectorID: "google_workspace", UserExternalID: "u-good", Status: models.OrphanStatusDetected, DetectedAt: now},
		},
		reconErr: errors.New("connector slack: upstream 503"),
	}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"workspace_id":"ws1"}`)
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/reconcile", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200 (partial-failure rows must surface)", w.Code, w.Body.String())
	}
	var resp struct {
		Rows           []unusedAccountView `json:"unused_app_accounts"`
		DryRun         bool                `json:"dry_run"`
		PartialFailure string              `json:"partial_failure"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rows) != 1 || resp.Rows[0].ID != "o1" {
		t.Errorf("rows = %+v; want one row with id=o1", resp.Rows)
	}
	if resp.DryRun {
		t.Errorf("response dry_run = true; want false")
	}
	if !strings.Contains(resp.PartialFailure, "slack") {
		t.Errorf("partial_failure = %q; want it to surface the aggregated connector error", resp.PartialFailure)
	}
}

// TestOrphanHandler_Reconcile_PartialFailure_DryRun mirrors the
// wet-run partial-failure assertion for the dry-run path. Dry-run is
// the more impactful gap because the rows are not persisted anywhere
// — if the handler discarded them on error, the operator would lose
// the only copy of the preview from the connectors that succeeded.
func TestOrphanHandler_Reconcile_PartialFailure_DryRun(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeOrphanService{
		dryRunRows: []models.AccessOrphanAccount{
			{WorkspaceID: "ws1", ConnectorID: "google_workspace", UserExternalID: "u-dry-good", Status: models.OrphanStatusDetected, DetectedAt: now},
		},
		dryRunErr: errors.New("connector slack: upstream 503"),
	}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"workspace_id":"ws1","dry_run":true}`)
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/reconcile", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200 (dry-run preview must survive partial failure)", w.Code, w.Body.String())
	}
	var resp struct {
		Rows           []unusedAccountView `json:"unused_app_accounts"`
		DryRun         bool                `json:"dry_run"`
		PartialFailure string              `json:"partial_failure"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rows) != 1 || resp.Rows[0].AppUserID != "u-dry-good" {
		t.Errorf("rows = %+v; want one row with app_user_id=u-dry-good", resp.Rows)
	}
	if !resp.DryRun {
		t.Errorf("response dry_run = false; want true")
	}
	if !strings.Contains(resp.PartialFailure, "slack") {
		t.Errorf("partial_failure = %q; want it to surface the aggregated connector error", resp.PartialFailure)
	}
}

// TestOrphanHandler_Reconcile_TotalFailure_NoRows asserts the
// no-rows-and-error path still returns 500. This is the residual case
// where the partial-failure 200 contract does not apply because there
// is nothing useful to surface to the caller.
func TestOrphanHandler_Reconcile_TotalFailure_NoRows(t *testing.T) {
	fake := &fakeOrphanService{
		rows:     nil,
		reconErr: errors.New("connector google_workspace: upstream 503"),
	}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"workspace_id":"ws1"}`)
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/reconcile", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d (%s); want 500 when there are no rows to surface", w.Code, w.Body.String())
	}
}

// TestOrphanHandler_Revoke_ReturnsTerminalStatus asserts the revoke
// route returns the auto_revoked status enum on success.
func TestOrphanHandler_Revoke_ReturnsTerminalStatus(t *testing.T) {
	fake := &fakeOrphanService{}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/o1/revoke", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if got := fake.revokeCalls.Load(); got != 1 {
		t.Errorf("Revoke calls = %d; want 1", got)
	}
}

// TestOrphanHandler_Dismiss_ReturnsTerminalStatus asserts the
// dismiss route returns the dismissed status enum on success.
func TestOrphanHandler_Dismiss_ReturnsTerminalStatus(t *testing.T) {
	fake := &fakeOrphanService{}
	r := Router(Dependencies{OrphanReconciler: fake, DisableRateLimiter: true})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/access/orphans/o1/dismiss", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if got := fake.dismissCalls.Load(); got != 1 {
		t.Errorf("Dismiss calls = %d; want 1", got)
	}
}
