// Command access-connector-worker runs the queue handlers that exercise the
// access connector framework (sync_identities, provision_access, ...) plus
// the periodic crons that drive the access platform: anomaly detection,
// credential expiry checks, grant-expiry enforcement, and orphan
// reconciliation.
//
// Production wiring: when ACCESS_DATABASE_URL is set the binary opens a
// GORM Postgres pool, runs every migration in internal/migrations,
// constructs the per-cron service dependencies (provisioning, credential
// loader, orphan reconciler) and launches the cron set on a context that
// cancels on SIGINT / SIGTERM. If ACCESS_DATABASE_URL is unset the binary
// still boots with an empty cron set so dev `go run` works without
// provisioning Postgres.
//
// Graceful shutdown: StartCronJobs returns a *sync.WaitGroup tracking
// every spawned cron goroutine; on SIGINT/SIGTERM main cancels the
// context and then bounds a wg.Wait drain by shutdownDrainTimeout so
// any in-flight tick (e.g. a partway-through upstream revoke) finishes
// before the process exits, while a wedged tick can't keep the binary
// alive indefinitely.
//
// Connector credential encryption: when ACCESS_CREDENTIAL_DEK is set
// to a base64 32-byte key the binary wires the production AES-GCM
// encryptor onto the credentials loader and the provisioning service;
// when it is unset the binary falls back to PassthroughEncryptor
// with a loud boot-log warning so a misconfigured env var doesn't
// silently downgrade storage to plaintext.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/config"
	"github.com/kennguy3n/cautious-fishstick/internal/cron"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/database"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
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

// CronJobs is the set of background workers the worker binary owns.
// Returned by WireCronJobs so cmd/* consumers (and tests) can launch
// each one on its own goroutine with the configured interval.
type CronJobs struct {
	Anomaly                 *cron.AnomalyScanner
	AnomalyInterval         time.Duration
	CredentialChecker       *cron.CredentialChecker
	CredentialCheckInterval time.Duration
	// GrantExpiryEnforcer revokes access_grants whose expires_at has
	// passed. Phase 11 (docs/overview.md §13). nil when the binary
	// boots without a provisioning service or credentials loader
	// wired (the early-scaffold path).
	GrantExpiryEnforcer *cron.GrantExpiryEnforcer
	GrantExpiryInterval time.Duration
	// GrantExpiryWarningInterval is the cadence at which the worker
	// runs the look-ahead "your access expires in N hours" sweep
	// (cron.GrantExpiryEnforcer.RunWarning). It defaults to the
	// same value as GrantExpiryInterval — the dedup pivot
	// (models.AccessGrant.LastWarnedAt) collapses repeated ticks
	// to a single notification per grant, so running the warning
	// sweep on the same cadence as the revoke sweep is safe and
	// keeps the operator config surface narrow. Phase 11 batch 6
	// round-7.
	GrantExpiryWarningInterval time.Duration
	// OrphanReconcilerScheduler walks every workspace and asks the
	// orphan reconciler to find upstream SaaS users with no IdP
	// pivot. Phase 11 (docs/overview.md §13.4). nil when the binary
	// boots without a reconciler wired.
	OrphanReconcilerScheduler *cron.OrphanReconcilerScheduler
	OrphanReconcileInterval   time.Duration
}

// WireCronJobs constructs the worker-binary cron set from the
// supplied dependencies. db, scanner, and notifier may be nil — in
// that case the corresponding cron is omitted (the binary still
// boots, just without that cron). cfg drives the per-cron
// intervals; zero values fall back to the package-level defaults.
//
// revoker / loader may be nil — when either is nil the Phase 11
// GrantExpiryEnforcer cron is omitted but the rest of the cron set
// still wires. The two are bundled because the enforcer cannot
// usefully run without both: revoke needs decrypted credentials
// loaded per-connector via the loader.
//
// grantExpiryNotifier and auditProducer are the Phase 11 batch 6
// hooks for the grant-expiry pipeline:
//   - grantExpiryNotifier surfaces "your access has been revoked"
//     and "your access expires in N hours" notifications to the
//     affected user (cron.GrantExpiryNotifier).
//   - auditProducer publishes access.grant.expiry SIEM events for
//     every revoke/warn outcome.
//
// Both may be nil — the enforcer falls back to its built-in
// "skipped" status for any unwired hook so SIEM consumers can
// still distinguish "we tried and it succeeded" from "we never
// tried" without a panic. Wiring is plumbed here rather than left
// to the caller so the wiring gap that hid these features in the
// scaffold cannot reappear (Phase 11 batch 6 round-7).
//
// The returned CronJobs is safe to consume from a single goroutine
// per cron — none of the workers share mutable state.
func WireCronJobs(
	db *gorm.DB,
	scanner cron.WorkspaceScanner,
	notifier cron.NotificationSender,
	revoker cron.GrantRevoker,
	loader cron.ConnectorCredentialsLoader,
	grantExpiryNotifier cron.GrantExpiryNotifier,
	auditProducer access.AuditProducer,
	orphanReconciler cron.WorkspaceOrphanReconciler,
	cfg config.Access,
) CronJobs {
	jobs := CronJobs{}
	if db != nil && scanner != nil {
		jobs.Anomaly = cron.NewAnomalyScanner(db, scanner)
		jobs.AnomalyInterval = cfg.AnomalyScanInterval
		if jobs.AnomalyInterval <= 0 {
			jobs.AnomalyInterval = config.DefaultAnomalyScanInterval
		}
	}
	if db != nil {
		jobs.CredentialChecker = cron.NewCredentialChecker(db, notifier, cfg.CredentialExpiryWarningDays)
		jobs.CredentialCheckInterval = cfg.CredentialCheckerInterval
		if jobs.CredentialCheckInterval <= 0 {
			jobs.CredentialCheckInterval = config.DefaultCredentialCheckerInterval
		}
	}
	if db != nil && revoker != nil && loader != nil {
		jobs.GrantExpiryEnforcer = cron.NewGrantExpiryEnforcer(db, revoker, loader, 0)
		// Apply the configured warning-window override here so the
		// ACCESS_GRANT_EXPIRY_WARNING_HOURS env var actually reaches
		// the enforcer in production. Without this call the
		// constructor's 24h default wins and operator overrides are
		// silently dropped. Phase 11 batch 6.
		jobs.GrantExpiryEnforcer.SetWarningHours(cfg.GrantExpiryWarningHours)
		// Phase 11 batch 6 round-7: wire the notifier and audit
		// producer onto the enforcer so the "your access expired"
		// notification + access.grant.expiry SIEM audit events
		// reach the right hooks in production. SetNotifier /
		// SetAuditProducer both tolerate nil (the enforcer falls
		// back to Status="skipped"), so the scaffold path where
		// both arguments are nil still boots without panicking.
		jobs.GrantExpiryEnforcer.SetNotifier(grantExpiryNotifier)
		jobs.GrantExpiryEnforcer.SetAuditProducer(auditProducer)
		jobs.GrantExpiryInterval = cfg.GrantExpiryCheckInterval
		if jobs.GrantExpiryInterval <= 0 {
			jobs.GrantExpiryInterval = config.DefaultGrantExpiryCheckInterval
		}
		// The look-ahead warning sweep runs on its own ticker so a
		// future operator can throttle it independently of the
		// revoke sweep. The default matches the revoke cadence —
		// the LastWarnedAt dedup pivot collapses duplicates per
		// grant so a 1h cadence is safe.
		jobs.GrantExpiryWarningInterval = jobs.GrantExpiryInterval
	}
	if db != nil && orphanReconciler != nil {
		jobs.OrphanReconcilerScheduler = cron.NewOrphanReconcilerScheduler(db, orphanReconciler)
		jobs.OrphanReconcileInterval = cfg.OrphanReconcileInterval
		if jobs.OrphanReconcileInterval <= 0 {
			jobs.OrphanReconcileInterval = config.DefaultOrphanReconcileInterval
		}
	}
	return jobs
}

// StartCronJobs launches every configured CronJobs entry on its
// own goroutine via runCron. Each goroutine ticks at the per-cron
// interval and stops when ctx is cancelled; per-tick errors are
// logged but never abort the loop.
//
// The helper is the single seam where new crons land into the
// runtime so future-non-scaffold main() does not have to remember
// to call runCron for each cron manually. Phase 11 batch 6 round-7
// added jobs.GrantExpiryWarningInterval + the RunWarning call site
// here so the look-ahead sweep is no longer dead code in the
// worker binary.
//
// The returned *sync.WaitGroup tracks every cron goroutine spawned
// here so the worker binary can bound a graceful-shutdown drain on
// it after ctx is cancelled — without this main() would return as
// soon as <-ctx.Done() unblocks, killing any tick that was mid-
// flight (e.g. an in-progress upstream revoke) and risking the
// upstream provider + the local DB drifting out of sync.
//
// Nil-safe: jobs entries that are nil are simply skipped, so the
// scaffold path that constructs an empty CronJobs is a no-op
// rather than a panic, and the WaitGroup returns with no
// outstanding counts so wg.Wait() is an immediate no-op too.
func StartCronJobs(ctx context.Context, jobs CronJobs) *sync.WaitGroup {
	var wg sync.WaitGroup
	spawn := func(name string, interval time.Duration, run func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCron(ctx, name, interval, run)
		}()
	}
	if jobs.Anomaly != nil {
		spawn("anomaly-scanner", jobs.AnomalyInterval, jobs.Anomaly.Run)
	}
	if jobs.CredentialChecker != nil {
		spawn("credential-checker", jobs.CredentialCheckInterval, jobs.CredentialChecker.Run)
	}
	if jobs.GrantExpiryEnforcer != nil {
		// The revoke sweep wraps Run so we can collapse the
		// (revoked int, err error) return into the err-only
		// contract runCron expects. The revoked count is already
		// surfaced via the audit pipeline so dropping it on the
		// floor here is fine.
		spawn("grant-expiry-enforcer", jobs.GrantExpiryInterval, func(ctx context.Context) error {
			_, err := jobs.GrantExpiryEnforcer.Run(ctx)
			return err
		})
		// The look-ahead warning sweep runs on its own ticker so
		// operators can tune the cadence independently. The
		// LastWarnedAt dedup pivot collapses duplicates across
		// repeated ticks so running both sweeps on the same
		// cadence is safe. Phase 11 batch 6 round-7.
		spawn("grant-expiry-warning", jobs.GrantExpiryWarningInterval, func(ctx context.Context) error {
			_, err := jobs.GrantExpiryEnforcer.RunWarning(ctx)
			return err
		})
	}
	if jobs.OrphanReconcilerScheduler != nil {
		spawn("orphan-reconciler", jobs.OrphanReconcileInterval, jobs.OrphanReconcilerScheduler.Run)
	}
	return &wg
}

// runCron drives the supplied job on a fixed-interval ticker until
// ctx is cancelled. Per-tick errors are logged but never abort the
// loop — operators rely on the worker staying up across transient
// failures.
func runCron(ctx context.Context, name string, interval time.Duration, run func(context.Context) error) {
	if interval <= 0 || run == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("access-connector-worker: %s: shutting down", name)
			return
		case <-ticker.C:
			if err := run(ctx); err != nil {
				log.Printf("access-connector-worker: %s: tick: %v", name, err)
			}
		}
	}
}

// BuildOrphanReconciler constructs the Phase 11 orphan reconciler
// and applies the configured per-connector throttle. The setter
// call is hoisted out of WireCronJobs so the concrete
// *access.OrphanReconciler is the pointer the throttle lands on —
// WireCronJobs only sees the narrower WorkspaceOrphanReconciler
// interface and cannot reach SetPerConnectorDelay. Returns nil
// when any required dependency is nil (the scaffold path) so
// callers can still hand the value straight to WireCronJobs,
// which simply omits the orphan cron in that case.
//
// The env-driven knob ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR
// (decoded into cfg.OrphanReconcileDelayPerConnector by
// internal/config/access.go) is applied here; without this call
// the constructor's 1s default would win and operator overrides
// would be silently dropped.
func BuildOrphanReconciler(
	db *gorm.DB,
	provisioningSvc *access.AccessProvisioningService,
	credLoader *access.ConnectorCredentialsLoader,
	cfg config.Access,
) *access.OrphanReconciler {
	if db == nil || provisioningSvc == nil || credLoader == nil {
		return nil
	}
	r := access.NewOrphanReconciler(db, provisioningSvc, credLoader)
	r.SetPerConnectorDelay(cfg.OrphanReconcileDelayPerConnector)
	return r
}

// BuildAuditProducer constructs the audit producer for the worker
// binary from the loaded config. The current release ships only the
// NoOpAuditProducer — Kafka delivery is not yet implemented and the
// log line at boot makes the degraded mode obvious to operators so
// SIEM ingestion is not silently dropped on the floor.
//
// TODO(kafka): wire a real KafkaAuditProducer that publishes
// ShieldnetLogEvent v1 envelopes through segmentio/kafka-go (or a
// thin sarama wrapper). The audit handler
// (internal/workers/handlers/access_audit.go) is already agnostic to
// which AuditProducer is plugged in, so the only outstanding work is
// adding the producer adapter and threading the broker list through
// here. Tracked alongside the Phase 10 audit hardening backlog.
func BuildAuditProducer(cfg config.Access) access.AuditProducer {
	if cfg.KafkaBrokers == "" {
		log.Printf("access-connector-worker: ACCESS_KAFKA_BROKERS unset; audit pipeline using NoOpAuditProducer (Kafka audit not yet implemented)")
		return &access.NoOpAuditProducer{}
	}
	log.Printf("access-connector-worker: ACCESS_KAFKA_BROKERS=%q but Kafka audit is not yet implemented; using NoOpAuditProducer (TODO: wire KafkaAuditProducer)", cfg.KafkaBrokers)
	return &access.NoOpAuditProducer{}
}

// BuildCredentialExpiryNotifier constructs the NotificationSender the
// CredentialChecker cron dispatches credential-expiry warnings
// through. The wiring is:
//
//	cron.CredentialChecker -> access.CredentialExpiryNotifierAdapter ->
//	*notification.NotificationService -> [slack | in-memory] notifiers
//
// The notifier set is assembled here so the cron stays decoupled
// from any specific channel. The in-memory notifier is always
// attached so the dispatch is observable in dev binaries without
// requiring a real channel.
//
// SMTP wiring deliberately remains out of scope at this layer: the
// EmailNotifier requires a workspace-aware EmailRecipientResolver
// (workspace_id -> []email_addresses) which is provided by the API
// binary's directory adapter, not by the worker. When the access
// platform grows a dedicated workspace-admin distribution list, the
// resolver wiring lands here in a follow-up PR.
func BuildCredentialExpiryNotifier(cfg config.Access) cron.NotificationSender {
	notifiers := []notification.Notifier{}
	// Slack channel is the canonical fan-out target for workspace-
	// admin credential alerts when a webhook URL is configured. The
	// notifier itself short-circuits to log-only mode when the URL
	// is blank, but we still gate the wiring at the env layer so
	// the worker log line above reports an accurate "configured"
	// state.
	if cfg.NotificationSlackWebhookURL != "" {
		notifiers = append(notifiers, notification.NewSlackNotifier(cfg.NotificationSlackWebhookURL, nil))
	}
	// Always include the in-memory notifier as a tracer — its
	// captured buffer is what dev binaries inspect when no real
	// channel is configured. The buffer is bounded by the lifetime
	// of the worker process, so it doesn't leak across restarts.
	notifiers = append(notifiers, &notification.InMemoryNotifier{})

	svc := notification.NewNotificationService(notifiers...)
	return access.NewCredentialExpiryNotifierAdapter(svc)
}

// shutdownDrainTimeout caps how long main() waits for in-flight cron
// ticks to finish after SIGINT/SIGTERM. Matches the workflow engine's
// HTTP-server graceful-shutdown timeout so the two binaries behave
// the same under signal-driven shutdown.
const shutdownDrainTimeout = 10 * time.Second

// loadCredentialEncryptor reads ACCESS_CREDENTIAL_DEK and returns the
// production AES-GCM encryptor when the env var is set to a valid
// base64 32-byte key. When the env var is unset the binary falls back
// to PassthroughEncryptor with a loud warning so the degraded posture
// is observable in the boot log. A set-but-malformed env var aborts
// boot via log.Fatalf so a typo cannot silently downgrade encryption
// to plaintext. The same helper lives in cmd/ztna-api/main.go; the
// two copies are intentional so each binary owns its boot-log
// surface and neither imports a shared cmd-level helper package.
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

func main() {
	log.Printf("access-connector-worker: starting; registered access connectors: %v", access.ListRegisteredProviders())

	cfg := config.Load()
	credNotifier := BuildCredentialExpiryNotifier(*cfg)
	auditProducer := BuildAuditProducer(*cfg)

	// Open Postgres and wire the per-cron service dependencies
	// when ACCESS_DATABASE_URL is set. Without a DB the cron set
	// stays empty (WireCronJobs short-circuits on nil db) so dev
	// `go run` works without provisioning a database.
	var (
		db         *gorm.DB
		provSvc    *access.AccessProvisioningService
		credLoader *access.ConnectorCredentialsLoader
		scanner    cron.WorkspaceScanner
	)
	if dsn := os.Getenv("ACCESS_DATABASE_URL"); dsn != "" {
		var err error
		db, err = database.OpenPostgres(dsn)
		if err != nil {
			log.Fatalf("access-connector-worker: open postgres: %v", err)
		}
		if err := database.RunMigrations(db); err != nil {
			log.Fatalf("access-connector-worker: run migrations: %v", err)
		}
		log.Printf("access-connector-worker: postgres connected; migrations applied")

		encryptor := loadCredentialEncryptor("access-connector-worker")
		provSvc = access.NewAccessProvisioningService(db)
		credLoader = access.NewConnectorCredentialsLoader(db, encryptor)
		// AnomalyDetectionService.ScanWorkspace satisfies
		// cron.WorkspaceScanner. The AI detector is nil here — the
		// service degrades gracefully to an empty observation list
		// per docs/overview.md §5.3 so the cron stays useful even
		// without the agent.
		scanner = access.NewAnomalyDetectionService(db, nil)
	} else {
		log.Printf("access-connector-worker: ACCESS_DATABASE_URL unset; running without DB — cron set will be empty")
	}

	orphanReconcilerImpl := BuildOrphanReconciler(db, provSvc, credLoader, *cfg)
	var orphanReconciler cron.WorkspaceOrphanReconciler
	if orphanReconcilerImpl != nil {
		orphanReconciler = orphanReconcilerImpl
	}
	// Phase 11 batch 6 round-7: the grant-expiry notifier hook is
	// not yet wired — no NotificationService method exists for the
	// grant-revoke fan-out today. Passing nil exercises the
	// SetNotifier(nil) branch in WireCronJobs; the enforcer falls
	// back to Status="skipped" so the wiring is observable in SIEM
	// without a panic.
	var grantExpiryNotifier cron.GrantExpiryNotifier

	// revoker is satisfied by *access.AccessProvisioningService via
	// its RevokeAccess method — the same one ConnectorManagementService
	// already calls during Disconnect. loader is the same credLoader
	// the orphan reconciler uses.
	var (
		revoker cron.GrantRevoker
		loader  cron.ConnectorCredentialsLoader
	)
	if provSvc != nil {
		revoker = provSvc
	}
	if credLoader != nil {
		loader = credLoader
	}

	jobs := WireCronJobs(db, scanner, credNotifier, revoker, loader, grantExpiryNotifier, auditProducer, orphanReconciler, *cfg)

	// T28 — connector health webhook dispatcher. The dispatcher
	// short-circuits to a no-op when the URL is unset so dev
	// binaries can run without external infrastructure; the boot
	// log records the effective state so operators can confirm at
	// a glance whether the channel is wired.
	healthWebhook := access.NewConnectorHealthWebhookDispatcher(access.ConnectorHealthWebhookConfig{
		WebhookURL: cfg.HealthWebhookURL,
	})
	log.Printf("access-connector-worker: audit pipeline topic=%q producer=%T", cfg.AuditLogTopic, auditProducer)
	log.Printf("access-connector-worker: credential expiry notifier wired (slack_configured=%t)",
		cfg.NotificationSlackWebhookURL != "",
	)
	log.Printf("access-connector-worker: health webhook dispatcher wired (configured=%t)",
		healthWebhook.Configured(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signals
		log.Printf("access-connector-worker: received %s; shutting down crons", sig)
		cancel()
	}()

	wg := StartCronJobs(ctx, jobs)
	log.Printf("access-connector-worker: cron set started; awaiting shutdown signal")
	<-ctx.Done()
	// Bound the shutdown drain so a wedged cron tick can't keep
	// the binary alive forever. shutdownDrainTimeout mirrors the
	// 10s grace period the workflow engine uses for its HTTP
	// server shutdown so the two binaries behave the same under
	// SIGINT.
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		log.Printf("access-connector-worker: shutdown complete")
	case <-time.After(shutdownDrainTimeout):
		log.Printf("access-connector-worker: shutdown drain timed out after %s; exiting with in-flight cron ticks still running", shutdownDrainTimeout)
	}
	_ = healthWebhook
}
