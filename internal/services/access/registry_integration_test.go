package access_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	// Blank-import all three Phase 0 connectors so their init() functions
	// register them. Tests live in an _test package to mirror the way
	// production binaries (cmd/*) wire up the registry.
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/google_workspace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/microsoft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
)

func TestPhase0Connectors_AllRegister(t *testing.T) {
	for _, provider := range []string{"google_workspace", "microsoft", "okta"} {
		t.Run(provider, func(t *testing.T) {
			c, err := access.GetAccessConnector(provider)
			if err != nil {
				t.Fatalf("GetAccessConnector(%q): %v", provider, err)
			}
			if c == nil {
				t.Fatalf("GetAccessConnector(%q) returned nil", provider)
			}
		})
	}
}

func TestListRegisteredProviders_IncludesAllPhase0(t *testing.T) {
	got := access.ListRegisteredProviders()

	want := map[string]bool{
		"google_workspace": false,
		"microsoft":        false,
		"okta":             false,
	}
	for _, p := range got {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("ListRegisteredProviders() missing %q (got %v)", p, got)
		}
	}
}

func TestSwapConnector_AllowsMockInjection(t *testing.T) {
	mock := &access.MockAccessConnector{}
	access.SwapConnector(t, "microsoft", mock)

	got, err := access.GetAccessConnector("microsoft")
	if err != nil {
		t.Fatalf("GetAccessConnector after Swap: %v", err)
	}
	if got != mock {
		t.Fatalf("Swap did not install mock")
	}

	// Exercise the mock through the registry so we know the swap is real.
	if err := got.Validate(context.Background(), nil, nil); err != nil {
		t.Fatalf("mock Validate returned err: %v", err)
	}
	if mock.ValidateCalls != 1 {
		t.Fatalf("ValidateCalls = %d, want 1", mock.ValidateCalls)
	}
}
