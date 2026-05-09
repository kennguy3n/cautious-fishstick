package auth0

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the Auth0 connector against the process-global registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
