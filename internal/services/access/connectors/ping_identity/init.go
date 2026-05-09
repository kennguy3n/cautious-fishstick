package ping_identity

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the Ping Identity (PingOne) connector against the
// process-global registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
