package access_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	// Blank-import every Tier 1 connector so their init() functions
	// register them. Tests live in an _test package to mirror the way
	// production binaries (cmd/*) wire up the registry.
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/auth0"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/duo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_oidc"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_saml"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/google_workspace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/lastpass"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/microsoft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/onepassword"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ping_identity"
)

// tier1Providers is the canonical list of Tier 1 connector keys that Phase 1
// commits to landing. The list intentionally lives here (and not in the
// connector packages themselves) so adding a new connector forces an explicit
// registry-test diff.
var tier1Providers = []string{
	"auth0",
	"duo_security",
	"generic_oidc",
	"generic_saml",
	"google_workspace",
	"lastpass",
	"microsoft",
	"okta",
	"onepassword",
	"ping_identity",
}

func TestTier1Connectors_AllRegister(t *testing.T) {
	for _, provider := range tier1Providers {
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

func TestListRegisteredProviders_IncludesAllTier1(t *testing.T) {
	got := access.ListRegisteredProviders()

	want := make(map[string]bool, len(tier1Providers))
	for _, p := range tier1Providers {
		want[p] = false
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

func TestListRegisteredProviders_AtLeastTenTier1(t *testing.T) {
	got := access.ListRegisteredProviders()
	registered := make(map[string]struct{}, len(got))
	for _, p := range got {
		registered[p] = struct{}{}
	}
	for _, p := range tier1Providers {
		if _, ok := registered[p]; !ok {
			t.Errorf("Tier 1 provider %q not registered (got %v)", p, got)
		}
	}
	if len(registered) < len(tier1Providers) {
		t.Fatalf("registered providers = %d, want >= %d (Tier 1 set)", len(registered), len(tier1Providers))
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
