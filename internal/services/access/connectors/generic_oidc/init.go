package generic_oidc

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the Generic OIDC connector against the process-global registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
