package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
// ztna-api smoke: it asserts the binary's blank imports actually
// ran by checking the registry is non-empty. The exact-count guard
// is owned by internal/services/access/registry_count_test.go
// (TestRegistry_ExactConnectorCount) so duplicating the literal
// here would just be a second copy to keep in sync.
func TestAccessWorkflowEngineConnectorRegistryPopulated(t *testing.T) {
	if got := len(access.ListRegisteredProviders()); got == 0 {
		t.Errorf("ListRegisteredProviders() count = 0; want >0 (binary blank imports failed to populate registry)")
	}
}

// TestRunHealthcheck_OKWhenServerHealthy is the self-probe contract
// the docker-compose CMD relies on: when /health returns 200, the
// binary's runHealthcheck() must exit 0.
func TestRunHealthcheck_OKWhenServerHealthy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	t.Setenv("ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR", ":"+u.Port())

	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck() = %d; want 0 (server returned 200)", got)
	}
}

// TestRunHealthcheck_FailsOnNon200 asserts a regressed /health
// surfaces as exit 1 so docker-compose restarts the container.
func TestRunHealthcheck_FailsOnNon200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	t.Setenv("ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR", ":"+u.Port())

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d; want 1 (server returned 503)", got)
	}
}

// TestRunHealthcheck_FailsOnUnreachableServer asserts the binary
// reports exit 1 when no server is listening on the configured
// address — the third leg of the docker-compose healthcheck contract.
func TestRunHealthcheck_FailsOnUnreachableServer(t *testing.T) {
	t.Setenv("ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR", ":1")

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d; want 1 (server unreachable)", got)
	}
}
