package microsoft

import "github.com/kennguy3n/cautious-fishstick/internal/services/access"

// init registers the Microsoft Entra ID connector against the process-global
// registry. Every binary that needs runtime access to this provider blank-
// imports this package.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
