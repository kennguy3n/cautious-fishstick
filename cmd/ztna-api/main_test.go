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
// imports populate the access-connector registry with the expected
// number of providers. If a future PR drops a blank import (or adds
// one without registering), this test fails loudly inside the binary
// build rather than at runtime in docker-compose.
func TestZtnaAPIConnectorRegistryPopulated(t *testing.T) {
	providers := access.ListRegisteredProviders()
	if got, want := len(providers), 200; got != want {
		t.Errorf("ListRegisteredProviders() count = %d; want %d", got, want)
	}
}
