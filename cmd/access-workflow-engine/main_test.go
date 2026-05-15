package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access/workflow_engine"
)

// stubApproveRequester is the minimal workflow_engine.ApproveRequester
// the smoke test needs. The handler under test never executes a
// workflow step so the call body is intentionally trivial.
type stubApproveRequester struct{}

func (stubApproveRequester) ApproveRequest(_ context.Context, _, _, _ string) error { return nil }

// TestAccessWorkflowEngineHandlerBoots is the build-smoke test for
// cmd/access-workflow-engine. The binary blank-imports all 200
// connectors so the registry is populated; the test asserts the
// imports compiled and the underlying workflow_engine HTTP handler
// exposes a /health endpoint matching the docker-compose
// healthcheck self-probe. We do NOT call main() (it would try to
// open a real DB and listen on :8082) — instead we construct the
// same handler graph the binary wires at startup.
func TestAccessWorkflowEngineHandlerBoots(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	performer := workflow_engine.NewServiceStepPerformer(db, stubApproveRequester{}, nil)
	executor := workflow_engine.NewWorkflowExecutor(db, performer)
	srv := workflow_engine.NewServer(executor)
	h := srv.Handler()
	if h == nil {
		t.Fatal("workflow_engine.NewServer().Handler() returned nil")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health status = %d; want 200", rec.Code)
	}
}

// TestAccessWorkflowEngineConnectorRegistryPopulated mirrors the
// ztna-api smoke: every blank import in the binary should populate
// the registry with exactly 200 connectors.
func TestAccessWorkflowEngineConnectorRegistryPopulated(t *testing.T) {
	if got, want := len(access.ListRegisteredProviders()), 200; got != want {
		t.Errorf("ListRegisteredProviders() count = %d; want %d", got, want)
	}
}
