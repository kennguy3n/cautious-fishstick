package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestRunHealthcheck_OKWhenServerHealthy starts a local httptest
// server that mimics ztna-api's /health endpoint, points the binary's
// ZTNA_API_LISTEN_ADDR at it, and asserts runHealthcheck returns 0.
// This is the contract docker-compose's `CMD /ztna-api --healthcheck`
// relies on.
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
	// Force the healthcheck to dial 127.0.0.1:<port> by setting the
	// listen address to the same `:port` form the prod binary uses.
	t.Setenv("ZTNA_API_LISTEN_ADDR", ":"+u.Port())

	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck() = %d; want 0 (server returned 200)", got)
	}
}

// TestRunHealthcheck_FailsOnNon200 asserts the self-probe surfaces a
// non-2xx /health response as exit 1 — the contract docker-compose
// requires so the container is restarted when the binary regresses.
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
	t.Setenv("ZTNA_API_LISTEN_ADDR", ":"+u.Port())

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d; want 1 (server returned 503)", got)
	}
}

// TestRunHealthcheck_FailsOnUnreachableServer exercises the
// connection-error path: nothing is listening on the configured port,
// so the self-probe must surface exit 1.
func TestRunHealthcheck_FailsOnUnreachableServer(t *testing.T) {
	// Port 1 is reserved and reliably refuses TCP — perfect for the
	// "unreachable server" branch without relying on a free-port
	// search loop.
	t.Setenv("ZTNA_API_LISTEN_ADDR", ":1")

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d; want 1 (server unreachable)", got)
	}
}
