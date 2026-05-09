package google_workspace

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the Google Workspace connector against the process-global
// registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
