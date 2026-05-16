// Package access_test — registry-count guard tests.
//
// These tests live in an _test package (not the access package
// itself) so they can blank-import every connector to populate the
// process-global registry. The point of these tests is to fail the
// build the moment a connector is added or removed without the
// matching docs update, so the assertion is on exact counts.
//
// The expected counts here MUST stay in sync with:
//
//   - README.md (connector count, optional-interface counts)
//   - docs/architecture.md §12 (Where things run) + §13
//   - docs/connectors.md §2 capability status
package access_test

import (
	"os"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"

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

// expectedConnectorCount is the canonical number of providers
// registered via init(). A future PR that adds or removes a
// connector MUST update this number AND the matching docs.
const expectedConnectorCount = 200

// expectedSessionRevokerCount is the canonical number of
// AccessConnector implementations that also satisfy SessionRevoker.
// docs/architecture.md §8 (kill-switch) calls this the Tier 1 set
// for the leaver flow.
const expectedSessionRevokerCount = 14

// expectedSSOEnforcementCheckerCount is the canonical number of
// AccessConnector implementations that also satisfy
// SSOEnforcementChecker. docs/architecture.md §13 (SSO-only
// enforcement verification) uses this set for the orphan
// reconciler's daily SSO-regression scan. The count grows when a
// connector adds a CheckSSOEnforcement implementation; the matching
// docs MUST be updated in the same PR. Group B T13/T14 bumped this
// to 14 by adding Dropbox + Zoom — keep this number aligned with
// README.md's connector list and the §2 entry in docs/connectors.md.
const expectedSSOEnforcementCheckerCount = 14

// TestRegistry_ExactConnectorCount fails when the connector count
// drifts from expectedConnectorCount. It is intentionally an
// equality check (not >=) so adding a connector forces a deliberate
// doc + count update.
func TestRegistry_ExactConnectorCount(t *testing.T) {
	got := len(access.ListRegisteredProviders())
	if got != expectedConnectorCount {
		t.Fatalf("ListRegisteredProviders() count = %d; want %d (update docs/architecture.md + docs/connectors.md + README.md)", got, expectedConnectorCount)
	}
}

// TestRegistry_SessionRevokerCount fails when the count of
// connectors implementing the SessionRevoker optional interface
// drifts. The expected value reflects the Phase 11 leaver-flow
// kill-switch coverage.
func TestRegistry_SessionRevokerCount(t *testing.T) {
	providers := access.ListRegisteredProviders()
	got := 0
	for _, p := range providers {
		c, err := access.GetAccessConnector(p)
		if err != nil || c == nil {
			continue
		}
		if _, ok := c.(access.SessionRevoker); ok {
			got++
		}
	}
	if got != expectedSessionRevokerCount {
		t.Fatalf("SessionRevoker implementations = %d; want %d (update docs + README.md count)", got, expectedSessionRevokerCount)
	}
}

// TestRegistry_SSOEnforcementCheckerCount fails when the count of
// connectors implementing the SSOEnforcementChecker optional
// interface drifts. The expected value reflects the Phase 11
// orphan-reconciler / connector-setup SSO regression scan.
func TestRegistry_SSOEnforcementCheckerCount(t *testing.T) {
	providers := access.ListRegisteredProviders()
	got := 0
	for _, p := range providers {
		c, err := access.GetAccessConnector(p)
		if err != nil || c == nil {
			continue
		}
		if _, ok := c.(access.SSOEnforcementChecker); ok {
			got++
		}
	}
	if got != expectedSSOEnforcementCheckerCount {
		t.Fatalf("SSOEnforcementChecker implementations = %d; want %d (update docs + README.md count)", got, expectedSSOEnforcementCheckerCount)
	}
}

// TestRegistry_NoOrphanDirectories asserts every directory under
// internal/services/access/connectors/ maps to a registered
// provider. The check protects against the failure mode where a
// connector package is added but its blank-import is missed from
// cmd/<binary>/main.go (or this test file), which silently drops
// the provider out of the registry without tripping
// TestRegistry_ExactConnectorCount (the count check only verifies
// 200 — not that the 200 are the expected 200).
//
// The mapping from directory name to provider name is the
// directory's ProviderName constant; nearly every package uses the
// same string for the directory and the registry key, but we still
// resolve via the directory's ProviderName-vs-registry lookup so
// renames don't quietly slip through.
func TestRegistry_NoOrphanDirectories(t *testing.T) {
	// directoryToProvider captures every directory whose
	// ProviderName constant differs from the directory name.
	// Production registers connectors by their ProviderName, so
	// the registry guard MUST translate via this map rather than
	// assume directory == provider. Add an entry here whenever a
	// new connector picks a divergent registry key.
	directoryToProvider := map[string]string{
		"duo": "duo_security",
	}
	const connectorsDir = "connectors"
	entries, err := os.ReadDir(connectorsDir)
	if err != nil {
		t.Fatalf("read connectors dir: %v", err)
	}
	registered := make(map[string]struct{}, expectedConnectorCount)
	for _, p := range access.ListRegisteredProviders() {
		registered[p] = struct{}{}
	}
	dirs := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirs++
		provider := e.Name()
		if alt, ok := directoryToProvider[provider]; ok {
			provider = alt
		}
		if _, ok := registered[provider]; !ok {
			t.Errorf("connectors/%s/ has no matching registry entry (forgot the blank-import in cmd/*/main.go or registry_count_test.go? or add to directoryToProvider above)", e.Name())
		}
	}
	if dirs != expectedConnectorCount {
		t.Errorf("connectors/ directory count = %d; want %d (mismatch with expectedConnectorCount)", dirs, expectedConnectorCount)
	}
}

// expectedSCIMProvisionerCount is the canonical number of
// AccessConnector implementations that also satisfy
// SCIMProvisioner. Bumping this requires landing the matching
// scim.go + scim_test.go inside the connector package AND
// refreshing docs/connectors.md §3 + README.md in the same PR.
const expectedSCIMProvisionerCount = 21

// expectedGroupSyncerCount is the canonical number of
// AccessConnector implementations that also satisfy GroupSyncer.
// Bumping this requires landing the matching groups.go +
// groups_test.go inside the connector package AND refreshing
// docs/connectors.md §4 + README.md in the same PR.
const expectedGroupSyncerCount = 14

// expectedIdentityDeltaSyncerCount is the canonical number of
// AccessConnector implementations that also satisfy
// IdentityDeltaSyncer (delta-sync hardening per docs/connectors.md
// §4). The actual count at HEAD is 3.
const expectedIdentityDeltaSyncerCount = 3

// expectedAccessAuditorCount is the canonical number of
// AccessConnector implementations that also satisfy AccessAuditor.
// docs/connectors.md §3 reports "audit logs across 198 (2 n/a)"; the
// actual count at HEAD is 198, matching the docs.
const expectedAccessAuditorCount = 198

// TestRegistry_SCIMProvisionerCount fails when the count of
// connectors implementing SCIMProvisioner drifts. Bumping this
// count requires updating the README + docs/connectors.md §3 in the
// same PR.
func TestRegistry_SCIMProvisionerCount(t *testing.T) {
	got := countImpls[access.SCIMProvisioner]()
	if got != expectedSCIMProvisionerCount {
		t.Fatalf("SCIMProvisioner implementations = %d; want %d (update docs/connectors.md §3 + README.md)", got, expectedSCIMProvisionerCount)
	}
}

// TestRegistry_GroupSyncerCount fails when the count of connectors
// implementing GroupSyncer drifts.
func TestRegistry_GroupSyncerCount(t *testing.T) {
	got := countImpls[access.GroupSyncer]()
	if got != expectedGroupSyncerCount {
		t.Fatalf("GroupSyncer implementations = %d; want %d (update docs/connectors.md §4)", got, expectedGroupSyncerCount)
	}
}

// TestRegistry_IdentityDeltaSyncerCount fails when the count of
// connectors implementing IdentityDeltaSyncer drifts.
func TestRegistry_IdentityDeltaSyncerCount(t *testing.T) {
	got := countImpls[access.IdentityDeltaSyncer]()
	if got != expectedIdentityDeltaSyncerCount {
		t.Fatalf("IdentityDeltaSyncer implementations = %d; want %d (update docs/connectors.md §4)", got, expectedIdentityDeltaSyncerCount)
	}
}

// TestRegistry_AccessAuditorCount fails when the count of
// connectors implementing AccessAuditor drifts.
func TestRegistry_AccessAuditorCount(t *testing.T) {
	got := countImpls[access.AccessAuditor]()
	if got != expectedAccessAuditorCount {
		t.Fatalf("AccessAuditor implementations = %d; want %d (update docs/connectors.md §3 + README.md)", got, expectedAccessAuditorCount)
	}
}

// countImpls returns the number of registered AccessConnectors
// whose concrete type satisfies the optional interface T. The
// generic shape keeps the per-interface tests above to a single
// line each so adding a new optional interface boils down to a
// new const + a new TestRegistry_<...>Count test.
func countImpls[T any]() int {
	n := 0
	for _, p := range access.ListRegisteredProviders() {
		c, err := access.GetAccessConnector(p)
		if err != nil || c == nil {
			continue
		}
		if _, ok := any(c).(T); ok {
			n++
		}
	}
	return n
}
