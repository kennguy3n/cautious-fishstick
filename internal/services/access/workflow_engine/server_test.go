package workflow_engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func TestServer_Health(t *testing.T) {
	srv := NewServer(NewWorkflowExecutor(newTestDB(t), &recordingPerformer{}))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", rec.Code)
	}
	var resp healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q", resp.Status)
	}
}

func TestServer_HealthDraining(t *testing.T) {
	srv := NewServer(NewWorkflowExecutor(newTestDB(t), &recordingPerformer{}))
	srv.Shutdown()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503", rec.Code)
	}
}

func TestServer_ExecuteHappyPath(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW000000000HTTP01", []models.WorkflowStepDefinition{
		{Type: models.WorkflowStepAutoApprove},
	})
	srv := NewServer(NewWorkflowExecutor(db, &recordingPerformer{}))

	body, _ := json.Marshal(ExecuteRequest{WorkflowID: wf.ID, RequestID: "01HREQ000000000000000HTTP1"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/workflows/execute", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var got ExecutionResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Decision != StepApprove {
		t.Errorf("decision = %q", got.Decision)
	}
}

func TestServer_ExecuteWorkflowNotFound(t *testing.T) {
	srv := NewServer(NewWorkflowExecutor(newTestDB(t), &recordingPerformer{}))
	body, _ := json.Marshal(ExecuteRequest{WorkflowID: "01HMISSING0000000000HTTP02"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/workflows/execute", bytes.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

func TestServer_ExecuteRejectsGet(t *testing.T) {
	srv := NewServer(NewWorkflowExecutor(newTestDB(t), &recordingPerformer{}))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/workflows/execute", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rec.Code)
	}
}

func TestServer_ExecuteRejectsBadJSON(t *testing.T) {
	srv := NewServer(NewWorkflowExecutor(newTestDB(t), &recordingPerformer{}))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/workflows/execute", bytes.NewReader([]byte("{"))))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestServer_ExecuteRejectsMissingWorkflowID(t *testing.T) {
	srv := NewServer(NewWorkflowExecutor(newTestDB(t), &recordingPerformer{}))
	body, _ := json.Marshal(ExecuteRequest{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/workflows/execute", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestServer_UnknownStep422(t *testing.T) {
	db := newTestDB(t)
	wf := insertWorkflow(t, db, "01HWORKFLOW000000000HTTP03", []models.WorkflowStepDefinition{
		{Type: "psychic_handshake"},
	})
	srv := NewServer(NewWorkflowExecutor(db, &recordingPerformer{}))
	body, _ := json.Marshal(ExecuteRequest{WorkflowID: wf.ID})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/workflows/execute", bytes.NewReader(body)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", rec.Code)
	}
}
