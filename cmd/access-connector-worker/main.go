// Command access-connector-worker runs the queue handlers that exercise the
// access connector framework (sync_identities, provision_access, ...) plus
// the periodic crons that drive the access platform: anomaly detection,
// credential expiry checks, and (Phase 5) campaign scheduling.
//
// The Phase 0 scaffold logs startup and the registered providers so the
// binary builds and serves as the blank-import host for connector init()
// side-effects. Phase 6 wiring exposes WireCronJobs as a pure function so
// the cron set is unit-testable without actually starting goroutines.
package main

import (
	"context"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/config"
	"github.com/kennguy3n/cautious-fishstick/internal/cron"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

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

// CronJobs is the set of background workers the worker binary owns.
// Returned by WireCronJobs so cmd/* consumers (and tests) can launch
// each one on its own goroutine with the configured interval.
type CronJobs struct {
	Anomaly                 *cron.AnomalyScanner
	AnomalyInterval         time.Duration
	CredentialChecker       *cron.CredentialChecker
	CredentialCheckInterval time.Duration
}

// WireCronJobs constructs the worker-binary cron set from the
// supplied dependencies. db, scanner, and notifier may be nil — in
// that case the corresponding cron is omitted (the binary still
// boots, just without that cron). cfg drives the per-cron
// intervals; zero values fall back to the package-level defaults.
//
// The returned CronJobs is safe to consume from a single goroutine
// per cron — none of the workers share mutable state.
func WireCronJobs(db *gorm.DB, scanner cron.WorkspaceScanner, notifier cron.NotificationSender, cfg config.Access) CronJobs {
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
	return jobs
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

func main() {
	log.Printf("access-connector-worker: starting; registered access connectors: %v", access.ListRegisteredProviders())

	// Phase 0 scaffold: the production binary will Load() the
	// config, open the DB pool, construct AnomalyDetectionService /
	// NotificationService, and wire the crons via WireCronJobs +
	// runCron. The current scaffold compiles WireCronJobs into the
	// binary so the set is exercised by `go build ./...` without
	// requiring a live DB.
	jobs := WireCronJobs(nil, nil, nil, config.Access{})
	_ = jobs
	_ = runCron
}
