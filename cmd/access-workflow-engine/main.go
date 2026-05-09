// Command access-workflow-engine hosts the LangGraph workflow orchestrator
// that runs multi-step approval flows. The Phase 0 scaffold only logs
// startup; full orchestration lands in Phase 8.
package main

import (
	"log"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/asana"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/auth0"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/aws"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/azure"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/cloudflare"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/digitalocean"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/duo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gcp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_oidc"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_saml"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/google_workspace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/heroku"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/lastpass"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/microsoft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ms_teams"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/netlify"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/notion"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/onepassword"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ping_identity"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/slack"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/tailscale"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/vercel"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zoom"
)

func main() {
	log.Printf("access-workflow-engine: starting; registered access connectors: %v", access.ListRegisteredProviders())
}
