package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestBatchStatus_HappyPath_MixedConnectorStates verifies the
// happy path: a request listing two existing connectors + one
// missing ID returns a 200 with one entry per ID in the original
// order and the missing one flagged not_found.
func TestBatchStatus_HappyPath_MixedConnectorStates(t *testing.T) {
	db := newConnectorHealthDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	for _, id := range []string{"01HBATCH1000000000000000", "01HBATCH2000000000000000"} {
		conn := &models.AccessConnector{
			ID:            id,
			WorkspaceID:   "01HBATCHWS00000000000000",
			Provider:      "okta",
			ConnectorType: "idp",
			Status:        models.StatusConnected,
		}
		if err := db.Create(conn).Error; err != nil {
			t.Fatalf("seed connector %s: %v", id, err)
		}
		state := &models.AccessSyncState{
			ID:          "ST" + id[2:24],
			ConnectorID: id,
			Kind:        models.SyncStateKindIdentity,
			DeltaLink:   "cur",
			UpdatedAt:   now,
		}
		if err := db.Create(state).Error; err != nil {
			t.Fatalf("seed sync state: %v", err)
		}
	}

	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})

	body := `{"connector_ids": ["01HBATCH1000000000000000","01HBATCHMISSING000000000","01HBATCH2000000000000000"]}`
	req := httptest.NewRequest(http.MethodPost, "/access/connectors/batch-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []BatchStatusEntry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Entries) != 3 {
		t.Fatalf("entries = %d; want 3", len(resp.Entries))
	}
	if resp.Entries[0].ConnectorID != "01HBATCH1000000000000000" || resp.Entries[0].Health == nil {
		t.Errorf("entry[0]: %+v", resp.Entries[0])
	}
	if !resp.Entries[1].NotFound {
		t.Errorf("entry[1].NotFound = false; want true (missing connector)")
	}
	if resp.Entries[2].ConnectorID != "01HBATCH2000000000000000" || resp.Entries[2].Health == nil {
		t.Errorf("entry[2]: %+v", resp.Entries[2])
	}
}

// TestBatchStatus_DedupesIDsPreservingOrder verifies duplicate IDs
// in the request body are deduped while keeping the caller's order.
func TestBatchStatus_DedupesIDsPreservingOrder(t *testing.T) {
	db := newConnectorHealthDB(t)
	conn := &models.AccessConnector{
		ID:            "01HBATCHDUP00000000000000",
		WorkspaceID:   "01HBATCHWS00000000000000",
		Provider:      "okta",
		ConnectorType: "idp",
		Status:        models.StatusConnected,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})

	body := `{"connector_ids": ["01HBATCHDUP00000000000000","01HBATCHDUP00000000000000",""]}`
	req := httptest.NewRequest(http.MethodPost, "/access/connectors/batch-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []BatchStatusEntry `json:"entries"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Entries) != 1 {
		t.Fatalf("entries = %d; want 1 (dedupe)", len(resp.Entries))
	}
}

// TestBatchStatus_RejectsEmptyArray is the validation failure path:
// an explicit empty connector_ids array must produce a 400 so
// the caller doesn't mistake "I sent nothing" for "everything is
// OK".
func TestBatchStatus_RejectsEmptyArray(t *testing.T) {
	db := newConnectorHealthDB(t)
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})

	body := `{"connector_ids": []}`
	req := httptest.NewRequest(http.MethodPost, "/access/connectors/batch-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d (%s); want 400", w.Code, w.Body.String())
	}
}

// TestBatchStatus_RejectsAllBlankIDs is the validation failure path
// for `["", "", ""]` — after deduping it's empty, which is a 400.
func TestBatchStatus_RejectsAllBlankIDs(t *testing.T) {
	db := newConnectorHealthDB(t)
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})

	body := `{"connector_ids": ["",""]}`
	req := httptest.NewRequest(http.MethodPost, "/access/connectors/batch-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d (%s); want 400", w.Code, w.Body.String())
	}
}

// TestBatchStatus_RejectsOversizedRequest verifies the per-request
// cap. 201 IDs (one past the max) must produce a 400 — the Admin
// UI must page rather than ship a 10k-item request.
func TestBatchStatus_RejectsOversizedRequest(t *testing.T) {
	db := newConnectorHealthDB(t)
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})

	ids := make([]string, maxBatchStatusIDs+1)
	for i := range ids {
		ids[i] = "01HBATCHX0000000000000000"
	}
	bodyBytes, _ := json.Marshal(map[string][]string{"connector_ids": ids})
	req := httptest.NewRequest(http.MethodPost, "/access/connectors/batch-status", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (oversize body)", w.Code)
	}
}

// TestBatchStatus_RejectsInvalidJSON is the failure path for a
// malformed JSON body — must produce 400, not 500.
func TestBatchStatus_RejectsInvalidJSON(t *testing.T) {
	db := newConnectorHealthDB(t)
	svc := NewConnectorHealthService(db)
	r := Router(Dependencies{ConnectorHealthReader: svc})

	body := `{"connector_ids": [`
	req := httptest.NewRequest(http.MethodPost, "/access/connectors/batch-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}
