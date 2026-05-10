// Command ztna-api is the access platform's HTTP API binary. It boots
// a Gin HTTP server, exposes the access-platform endpoints described
// in docs/PROPOSAL.md §11, and blank-imports every Phase 0 connector
// so the process-global registry is populated.
//
// The binary is intentionally minimal: env-var-driven configuration
// (via internal/config), no DB connection in this scaffold (services
// are wired in only when ACCESS_DB_DSN is provided in a future phase),
// and a /health endpoint that is always available so Kubernetes
// probes are happy from second zero.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/kennguy3n/cautious-fishstick/internal/config"
	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	// Blank-imports register each connector with the process-global
	// access registry via init() side-effects. Forgetting to import a
	// connector package here means GetAccessConnector(<provider>) at
	// runtime returns ErrConnectorNotFound — which is exactly what we
	// want as a loud error.
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/airtable"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/asana"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/auth0"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/aws"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/azure"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/cloudflare"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/crowdstrike"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/digitalocean"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/duo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/figma"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/freshdesk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gcp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_oidc"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_saml"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/github"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gitlab"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/google_workspace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/helpscout"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/heroku"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hubspot"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/jira"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/lastpass"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/microsoft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/miro"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/monday"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ms_teams"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/netlify"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/notion"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/onepassword"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/pagerduty"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ping_identity"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/pipedrive"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/salesforce"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sentinelone"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sentry"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/slack"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/snyk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/tailscale"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/trello"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/vercel"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zendesk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zoho_crm"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zoom"
)

func main() {
	cfg := config.Load()
	log.Printf("ztna-api: starting; registered access connectors: %v", access.ListRegisteredProviders())
	if cfg.AIConfigured() {
		log.Printf("ztna-api: AI agent configured at %s", cfg.AIAgentBaseURL)
	} else {
		log.Printf("ztna-api: AI agent NOT configured; AI-driven endpoints will return 503")
	}

	deps := handlers.Dependencies{}
	if cfg.AIConfigured() {
		deps.AIService = aiclient.NewAIClient(cfg.AIAgentBaseURL, cfg.AIAgentAPIKey)
	}
	r := handlers.Router(deps)

	addr := os.Getenv("ZTNA_API_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("ztna-api: HTTP server listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("ztna-api: server exited: %v", err)
	}
}
