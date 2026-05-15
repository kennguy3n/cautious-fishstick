// Command ztna-api is the access platform's HTTP API binary. It boots
// a Gin HTTP server, exposes the access-platform endpoints described
// in docs/architecture.md §2, and blank-imports every Phase 0 connector
// so the process-global registry is populated.
//
// Production wiring: when ACCESS_DATABASE_URL is set the binary opens
// a GORM Postgres pool, runs every migration in internal/migrations,
// and constructs the full service set (policy, access-request,
// access-review, connector-management, connector-list, orphan-
// reconciler, JML). If ACCESS_DATABASE_URL is unset the binary still
// boots so dev `go run` works without provisioning Postgres — handlers
// that need a service simply return 503 until the DB is configured.
//
// Connector credential encryption: when ACCESS_CREDENTIAL_DEK is set
// to a base64 32-byte key the binary wires the production AES-GCM
// encryptor; when it is unset the binary falls back to
// PassthroughEncryptor with a loud boot-log warning. A set-but-
// malformed env var aborts boot rather than silently downgrade.
//
// Graceful shutdown: on SIGINT / SIGTERM the binary calls
// http.Server.Shutdown with a 10s timeout so in-flight requests
// finish before the process exits. Matches the worker's cron drain
// and the workflow engine's HTTP shutdown.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/config"
	"github.com/kennguy3n/cautious-fishstick/internal/handlers"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/database"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

	// Blank-imports register each connector with the process-global
	// access registry via init() side-effects. Forgetting to import a
	// connector package here means GetAccessConnector(<provider>) at
	// runtime returns ErrConnectorNotFound — which is exactly what we
	// want as a loud error.
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/activecampaign"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/airtable"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/alibaba"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/anthropic"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/anvyl"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/apollo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/appfolio"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/asana"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/auth0"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/aws"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/azure"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/bamboohr"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/basecamp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/beyondtrust"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/bigcommerce"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/billdotcom"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/bitsight"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/box"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/braze"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/brex"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/buffer"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/buildium"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/chargebee"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/checkpoint"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/circleci"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/clickup"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/clio"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/close"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/cloudflare"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/cloudsigma"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/constant_contact"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/copper"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/copyai"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/coupa"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/coursera"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/crisp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/crowdstrike"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/datadog"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/deel"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/digitalocean"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/discord"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/docker_hub"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/docusign"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/docusign_clm"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/drift"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/dropbox"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/duo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/egnyte"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/eventbrite"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/expensify"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/figma"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/forgerock"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/fortinet"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/freshbooks"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/freshdesk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/front"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/fullstory"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ga4"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gcp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gemini"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_oidc"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/generic_saml"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ghost"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/github"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gitlab"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gong"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/google_workspace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gorgias"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/grafana"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/gusto"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hackerone"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/heap"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hellosign"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/helpscout"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/heroku"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hibob"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hibp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hootsuite"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/hubspot"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ifttt"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/insightly"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/intercom"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ironclad"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/jasper"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/jfrog"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/jira"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/jotform"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/kareo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/keeper"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/klaviyo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/knowbe4"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/lastpass"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/launchdarkly"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/linkedin_learning"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/linode"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/liquidplanner"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/livechat"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/loom"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/magento"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/mailchimp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/make"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/malwarebytes"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/meraki"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/mezmo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/microsoft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/midjourney"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/miro"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/mistral"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/mixpanel"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/monday"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ms_teams"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/mycase"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/namely"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/navan"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/netlify"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/netskope"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/netsuite"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/new_relic"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/nordlayer"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/notion"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/okta"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/onepassword"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/openai"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ovhcloud"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/pagerduty"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/paloalto"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/pandadoc"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/pandadoc_clm"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/paychex"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/paypal"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/perimeter81"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/perplexity"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/personio"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ping_identity"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/pipedrive"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/plaid"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/practice_fusion"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/qualys"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/quickbooks"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/quip"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ramp"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/rapid7"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/recurly"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/ringcentral"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/rippling"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sage_intacct"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/salesforce"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/salesloft"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sap_concur"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/segment"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sendgrid"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sentinelone"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sentry"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/shopify"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/slack"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/slack_enterprise"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/smartsheet"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/snyk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sonarcloud"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sophos_central"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sophos_xg"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/splunk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sprout_social"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/square"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/squarespace"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/stripe"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/sumo_logic"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/surveymonkey"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/surveysparrow"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/tailscale"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/teamwork"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/tenable"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/terraform"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/travis_ci"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/trello"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/twilio"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/typeform"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/udemy_business"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/vercel"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/virustotal"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/vonage"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/vultr"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wasabi"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wave"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wazuh"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wix"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/woocommerce"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wordpress"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/workday"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wrike"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/wufoo"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/xero"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/yardi"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zapier"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zendesk"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zenefits"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zocdoc"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zoho_crm"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zoom"
	_ "github.com/kennguy3n/cautious-fishstick/internal/services/access/connectors/zscaler"
)

func main() {
	// `--healthcheck` is a self-probe mode used by the docker-compose
	// healthcheck command (the distroless runtime image has no curl).
	// It performs a quick HTTP GET against the local /health endpoint
	// and exits 0/1 based on the response.
	for _, arg := range os.Args[1:] {
		if arg == "--healthcheck" || arg == "-healthcheck" {
			os.Exit(runHealthcheck())
		}
	}

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

	// Open Postgres and wire the service layer when the DSN is
	// configured. The dev binary still boots with an empty deps set
	// when ACCESS_DATABASE_URL is unset so `go run ./cmd/ztna-api`
	// works without provisioning a database (handlers that need a
	// service short-circuit to 503 in that case — see
	// internal/handlers/router.go for the per-route nil-checks).
	if dsn := os.Getenv("ACCESS_DATABASE_URL"); dsn != "" {
		db, err := database.OpenPostgres(dsn)
		if err != nil {
			log.Fatalf("ztna-api: open postgres: %v", err)
		}
		if err := database.RunMigrations(db); err != nil {
			log.Fatalf("ztna-api: run migrations: %v", err)
		}
		log.Printf("ztna-api: postgres connected; migrations applied")

		encryptor := loadCredentialEncryptor("ztna-api")
		policySvc := access.NewPolicyService(db)
		requestSvc := access.NewAccessRequestService(db)
		provSvc := access.NewAccessProvisioningService(db)
		reviewSvc := access.NewAccessReviewService(db, provSvc)
		// ssoSvc is intentionally nil here — Keycloak broker
		// registration is wired in a follow-up once the SSO
		// federation service has a production constructor.
		connMgmtSvc := access.NewConnectorManagementService(db, encryptor, provSvc, nil)
		connListSvc := access.NewAccessConnectorListService(db)
		credLoader := access.NewConnectorCredentialsLoader(db, encryptor)
		orphanReconciler := access.NewOrphanReconciler(db, provSvc, credLoader)
		jmlSvc := access.NewJMLService(db, provSvc)
		grantQuerySvc := access.NewAccessGrantQueryService(db)

		deps.PolicyService = policySvc
		deps.AccessRequestService = requestSvc
		deps.AccessReviewService = reviewSvc
		deps.AccessGrantReader = &handlers.AccessGrantReaderAdapter{Inner: grantQuerySvc}
		deps.ConnectorManagementService = connMgmtSvc
		deps.ConnectorListReader = connListSvc
		deps.OrphanReconciler = orphanReconciler
		deps.JMLService = jmlSvc
	} else {
		log.Printf("ztna-api: ACCESS_DATABASE_URL unset; running without DB — handlers will return 503")
	}

	r := handlers.Router(deps)

	addr := os.Getenv("ZTNA_API_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("ztna-api: HTTP server listening on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("ztna-api: server exited: %v", err)
		}
		return
	case sig := <-signals:
		log.Printf("ztna-api: received %s; shutting down", sig)
	}

	// Bound the graceful shutdown so a wedged connection can't keep
	// the binary alive past the SIGTERM grace period Kubernetes
	// gives it. Matches the worker's shutdownDrainTimeout and the
	// workflow engine's HTTP server shutdown.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("ztna-api: graceful shutdown: %v", err)
	}
}

// loadCredentialEncryptor reads ACCESS_CREDENTIAL_DEK and returns
// the production AES-GCM encryptor when the env var is set to a
// valid base64 32-byte key. When the env var is unset the binary
// falls back to PassthroughEncryptor with a loud warning so the
// degraded posture is observable in the boot log. A set-but-
// malformed env var aborts boot via log.Fatalf so a typo cannot
// silently downgrade encryption to plaintext.
func loadCredentialEncryptor(binary string) access.CredentialEncryptor {
	enc, err := access.LoadAESGCMEncryptorFromEnv()
	if err != nil {
		log.Fatalf("%s: ACCESS_CREDENTIAL_DEK invalid: %v", binary, err)
	}
	if enc != nil {
		log.Printf("%s: connector credential encryption ENABLED (AES-256-GCM, static DEK)", binary)
		return enc
	}
	log.Printf("%s: WARNING ACCESS_CREDENTIAL_DEK unset; connector credentials will be stored as plaintext via PassthroughEncryptor \u2014 set ACCESS_CREDENTIAL_DEK to a base64 32-byte key before storing real provider secrets", binary)
	return access.PassthroughEncryptor{}
}

// runHealthcheck issues a short-timeout GET against the local
// /health endpoint and reports the exit code the docker-compose
// healthcheck should observe. The listen address is read from the
// same env var the main server uses so port overrides work
// transparently.
func runHealthcheck() int {
	addr := os.Getenv("ZTNA_API_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	port := addr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		port = addr[idx:]
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
