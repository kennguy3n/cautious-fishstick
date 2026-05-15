package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// TestZtnaAPIRouterBoots is the build-smoke test for cmd/ztna-api:
// it verifies the binary's package imports compile (all 200
// connectors blank-import without panicking on init), the
// handlers.Router constructor returns a non-nil engine even with a
// zero Dependencies struct, and the /health endpoint surfaces a 200
// the docker-compose healthcheck self-probe relies on. The real
// main() function takes over a process-wide HTTP listener, which
// we deliberately do NOT exercise here.
func TestZtnaAPIRouterBoots(t *testing.T) {
	r := handlers.Router(handlers.Dependencies{})
	if r == nil {
		t.Fatal("handlers.Router returned nil engine")
	}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health status = %d; want 200", resp.StatusCode)
	}
}

// TestZtnaAPIConnectorRegistryPopulated asserts the binary's blank
// imports populate the access-connector registry. The exact-count
// guard lives in internal/services/access/registry_count_test.go
// (TestRegistry_ExactConnectorCount) so this smoke test only needs
// to prove the registry is non-empty — i.e. the binary's blank
// imports compiled and ran their init() functions.
func TestZtnaAPIConnectorRegistryPopulated(t *testing.T) {
	if got := len(access.ListRegisteredProviders()); got == 0 {
		t.Errorf("ListRegisteredProviders() count = 0; want >0 (binary blank imports failed to populate registry)")
	}
}
