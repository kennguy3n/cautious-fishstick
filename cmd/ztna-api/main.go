// Command ztna-api is the access platform's HTTP API binary. The Phase 0
// scaffold only logs startup and dumps the registered access connectors;
// real handler wiring lands in Phase 2.
package main

import (
	"log"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	// Blank-imports register each connector with the process-global
	// access registry via init() side-effects. Forgetting to import a
	// connector package here means GetAccessConnector(<provider>) at
	// runtime returns ErrConnectorNotFound — which is exactly what we
	// want as a loud error.
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

func main() {
	log.Printf("ztna-api: starting; registered access connectors: %v", access.ListRegisteredProviders())
}
