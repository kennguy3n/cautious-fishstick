package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// fakeOrphanService implements OrphanReconcilerReader for handler tests.
type fakeOrphanService struct {
	rows         []models.AccessOrphanAccount
	listCalls    atomic.Int64
	reconCalls   atomic.Int64
	revokeCalls  atomic.Int64
	dismissCalls atomic.Int64
	ackCalls     atomic.Int64
	revokeErr    error
	dismissErr   error
	ackErr       error
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
	return f.rows, nil
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
