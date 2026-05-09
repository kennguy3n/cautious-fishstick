package onepassword

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the 1Password connector against the process-global registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
