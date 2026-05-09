package okta

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the Okta connector against the process-global registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
