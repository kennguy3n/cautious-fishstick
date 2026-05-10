// Command access-workflow-engine hosts the LangGraph-style workflow
// orchestrator that runs multi-step approval flows. Phase 8 brings the
// service up to a real HTTP host (see internal/services/access/workflow_engine):
//
//	GET  /health                — liveness probe (200 ok / 503 draining)
//	POST /workflows/execute     — run a workflow against a request
//
// The engine listens on ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR (default
// :8082) and shuts down gracefully on SIGINT / SIGTERM. Database access
// is via the same gorm postgres URL the rest of the platform uses
// (DATABASE_URL); when DATABASE_URL is unset the binary falls back to a
// short-lived in-memory SQLite so smoke tests can boot without
// provisioning a database.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access/workflow_engine"
	"github.com/kennguy3n/cautious-fishstick/internal/services/notification"

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
	log.Printf("access-workflow-engine: starting; registered access connectors: %v", access.ListRegisteredProviders())

	db, dbDescription, err := openDatabase()
	if err != nil {
		log.Fatalf("access-workflow-engine: open db: %v", err)
	}
	log.Printf("access-workflow-engine: %s", dbDescription)

	requestSvc := access.NewAccessRequestService(db)
	notifSvc := notification.NewNotificationService()
	notifAdapter := access.NewNotificationServiceAdapter(notifSvc)
	performer := workflow_engine.NewServiceStepPerformer(db, requestSvc, notifAdapter)
	executor := workflow_engine.NewWorkflowExecutor(db, performer)
	srv := workflow_engine.NewServer(executor)

	addr := os.Getenv("ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR")
	if addr == "" {
		addr = ":8082"
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Phase 8 escalation cron — every minute scan pending approval
	// steps and emit Escalate calls for any past their timeout. The
	// production NotifyingEscalator writes a state-history row + fans
	// out a notification per escalation; on a notifier failure the
	// state-history row is still written (best-effort semantics).
	escalator := workflow_engine.NewNotifyingEscalator(db, notifAdapter)
	checkerCtx, cancelChecker := context.WithCancel(context.Background())
	go runEscalationChecker(checkerCtx, db, escalator)

	go func() {
		log.Printf("access-workflow-engine: HTTP server listening on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("access-workflow-engine: server exited: %v", err)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	log.Printf("access-workflow-engine: shutting down")
	srv.Shutdown()
	cancelChecker()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("access-workflow-engine: graceful shutdown: %v", err)
	}
}

// openDatabase returns a gorm DB. ACCESS_WORKFLOW_ENGINE_SQLITE_PATH is
// honoured when set so operators can persist workflow state to disk;
// otherwise an in-memory SQLite is opened so the binary can smoke-test
// without provisioning storage. Postgres support lives in
// internal/migrations and will be wired into the engine once the
// migration runner is hooked up to this binary in Phase 9. The returned
// description is logged at startup.
func openDatabase() (*gorm.DB, string, error) {
	dsn := os.Getenv("ACCESS_WORKFLOW_ENGINE_SQLITE_PATH")
	if dsn == "" {
		dsn = ":memory:"
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, "", err
	}
	if err := db.AutoMigrate(
		&models.AccessRequest{},
		&models.AccessWorkflow{},
		&models.AccessRequestStateHistory{},
		&models.AccessWorkflowStepHistory{},
	); err != nil {
		return nil, "", err
	}
	desc := "in-memory sqlite (workflows will not persist)"
	if dsn != ":memory:" {
		desc = "sqlite at " + dsn
	}
	return db, desc, nil
}

// runEscalationChecker polls every minute until ctx is cancelled. The
// initial delay keeps the cron from firing during startup boot tests.
func runEscalationChecker(ctx context.Context, db *gorm.DB, escalator workflow_engine.Escalator) {
	checker := workflow_engine.NewEscalationChecker(db, escalator, time.Now)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := checker.Run(ctx)
			if err != nil {
				log.Printf("access-workflow-engine: escalation check: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("access-workflow-engine: escalated %d pending request(s)", n)
			}
		}
	}
}
