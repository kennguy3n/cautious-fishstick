# ShieldNet 360 Access Platform — Progress Tracker

Last updated: keep this file in sync as PRs land. The state here should agree with `git log`.

For the canonical phase definitions (and what "shipped" means), see `PHASES.md`. For the design contract see `PROPOSAL.md`.

Status: **In progress | ~55 %**. Phase 0 (contract, registry, credential manager, migration) is complete; Phase 1 Tier 1 is now feature-complete on the connector axis — all 10 Tier 1 connectors ship the minimum capabilities and are wired into the binaries via blank-import. Phase 1 stays 🟡 partial: the Admin UI and Keycloak SSO federation exit criteria are still unchecked. **Phase 2 is now 🟡 partial**: the four request-lifecycle tables, the request lifecycle FSM, the request / provisioning / workflow services (PR #4) AND the HTTP endpoint layer (`POST/GET /access/requests`, `POST /access/requests/:id/approve|deny|cancel`, `GET /access/grants`) have landed (PR #6); Admin UI / Mobile SDK / Desktop Extension exit criteria remain open. **Phase 3 is now 🟡 partial**: the `policies` / `teams` / `team_members` / `resources` tables, the Policy + Team + Resource models, `PolicyService`, `ImpactResolver`, `ConflictDetector` (PR #5) AND the HTTP endpoints (`POST /workspace/policy`, `GET /workspace/policy/drafts`, `GET /workspace/policy/:id`, `POST /workspace/policy/:id/simulate|promote`, `POST /workspace/policy/test-access`) have landed (PR #6); the Admin UI's policy simulator remains open. **Phase 4 is now 🟡 partial**: the A2A AI client (`internal/pkg/aiclient`), the env-driven access platform config (`internal/config`), the AI risk-scoring integration in `AccessRequestService.CreateRequest` and `PolicyService.Simulate`, and the `POST /access/explain` + `POST /access/suggest` endpoints have landed (PR #6); the AI agent service itself (Python) and the Admin UI's AI assistant remain open. **Phase 5 is now 🟡 partial**: the `access_reviews` / `access_review_decisions` tables, the matching models, `AccessReviewService` (`StartCampaign` / `SubmitDecision` / `CloseCampaign` / `AutoRevoke`) (PR #5), the HTTP endpoints (`POST /access/reviews`, `POST /access/reviews/:id/decisions|close|auto-revoke`), AND the Phase 5 scheduled-campaigns scaffold (`access_campaign_schedules` table + model + migration `005` + `internal/cron.CampaignScheduler`) have landed (PR #6); AI auto-certification and notification fan-out remain open. Most rows below remain `⏳ planned`.

| Status legend |  |
|---------------|--|
| ✅ shipped | The item is in `main` and exercised in production |
| 🟡 partial | Some criteria met; gaps tracked in §3 below |
| ⏳ planned | Not yet started |
| n/a | Not applicable to this provider |

---

## 1. Per-connector status

Capability columns (in **SN360 language**):

- `sync_identity` — pull users / groups / memberships into ZTNA Teams.
- `provision_access` — push grants out to the SaaS.
- `list_entitlements` — pull current permissions for an access check-up.
- `get_access_log` — pull sign-in / permission-change audit events into the audit pipeline.
- `sso_federation` — broker SAML / OIDC through Keycloak.

Path is the target directory under `internal/services/access/connectors/` once the connector lands.

### Tier 1 — Core Identity (1–10)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 1 | Microsoft Entra ID | IAM/SSO | `microsoft/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 2 | Google Workspace | IAM/SSO | `google_workspace/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 3 | Okta | IAM/SSO | `okta/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 4 | Auth0 | IAM/SSO | `auth0/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 5 | Generic SAML | IAM/SSO | `generic_saml/` | n/a | n/a | n/a | n/a | 🟡 | 🟡 |
| 6 | Generic OIDC | IAM/SSO | `generic_oidc/` | n/a | n/a | n/a | n/a | 🟡 | 🟡 |
| 7 | Duo Security | IAM/MFA | `duo/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 8 | 1Password | Secrets/Vault | `onepassword/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 9 | LastPass | Secrets/Vault | `lastpass/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 10 | Ping Identity | IAM/SSO | `ping_identity/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |

### Tier 2 — Cloud Infrastructure (11–25)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 11 | AWS IAM | Cloud Infra | `aws/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 12 | Azure RBAC | Cloud Infra | `azure/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 13 | GCP IAM | Cloud Infra | `gcp/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 14 | Cloudflare | Cloud Infra | `cloudflare/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 15 | Tailscale | Network | `tailscale/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 16 | DigitalOcean | Cloud Infra | `digitalocean/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 17 | Heroku | Cloud Infra | `heroku/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 18 | Vercel | Cloud Infra | `vercel/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 19 | Netlify | Cloud Infra | `netlify/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 20 | Vultr | Cloud Infra | `vultr/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 21 | Linode | Cloud Infra | `linode/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 22 | OVHcloud | Cloud Infra | `ovhcloud/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 23 | Alibaba Cloud | Cloud Infra | `alibaba/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 24 | CloudSigma | Cloud Infra | `cloudsigma/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 25 | Wasabi | Storage | `wasabi/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |

### Tier 3 — Business SaaS (26–80)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 26 | Slack | Collab | `slack/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 27 | MS Teams | Collab | `ms_teams/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 28 | Zoom | Collab | `zoom/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 29 | Notion | Productivity | `notion/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 30 | Asana | Productivity | `asana/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 31 | Monday.com | Productivity | `monday/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 32 | Figma | Design | `figma/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 33 | Miro | Whiteboard | `miro/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 34 | Trello | Productivity | `trello/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 35 | Airtable | Productivity | `airtable/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 36 | Smartsheet | Productivity | `smartsheet/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 37 | ClickUp | Productivity | `clickup/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 38 | Salesforce | CRM | `salesforce/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 39 | HubSpot | CRM | `hubspot/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 40 | Zoho CRM | CRM | `zoho_crm/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 41 | Pipedrive | CRM | `pipedrive/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 42 | Dropbox Business | Storage | `dropbox/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 43 | Box | Storage | `box/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 44 | Egnyte | Storage | `egnyte/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 45 | GitHub | DevOps | `github/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 46 | GitLab | DevOps | `gitlab/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 47 | Atlassian Jira | DevOps | `jira/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 48 | PagerDuty | DevOps | `pagerduty/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 49 | Sentry | DevOps | `sentry/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 50 | Terraform | DevOps | `terraform/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 51 | Docker Hub | DevOps | `docker_hub/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 52 | JFrog | DevOps | `jfrog/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 53 | SonarCloud | DevOps | `sonarcloud/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 54 | CircleCI | DevOps | `circleci/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 55 | Travis CI | DevOps | `travis_ci/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 56 | LaunchDarkly | DevOps | `launchdarkly/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 57 | Datadog | Observability | `datadog/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 58 | New Relic | Observability | `new_relic/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 59 | Splunk Cloud | Observability | `splunk/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 60 | Grafana | Observability | `grafana/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 61 | Mezmo | Observability | `mezmo/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 62 | Sumo Logic | Observability | `sumo_logic/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 63 | Zendesk | Support | `zendesk/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 64 | Freshdesk | Support | `freshdesk/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 65 | Help Scout | Support | `helpscout/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 66 | Front | Support | `front/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 67 | Intercom | Support | `intercom/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 68 | Drift | Marketing | `drift/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 69 | Crisp | Support | `crisp/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 70 | LiveChat | Support | `livechat/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 71 | Gorgias | Support | `gorgias/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 72 | Loom | Collab | `loom/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 73 | Discord | Collab | `discord/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 74 | Slack Enterprise | Collab | `slack_enterprise/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 75 | Basecamp | Productivity | `basecamp/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 76 | Quip | Productivity | `quip/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 77 | Wrike | Productivity | `wrike/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 78 | Teamwork | Productivity | `teamwork/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 79 | LiquidPlanner | Productivity | `liquidplanner/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 80 | KnowBe4 | Security Training | `knowbe4/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |

### Tier 4 — HR / Finance / Legal (81–130)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 81 | BambooHR | HR | `bamboohr/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 82 | Gusto | HR | `gusto/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 83 | Rippling | HR | `rippling/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 84 | Personio | HR | `personio/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 85 | Hibob | HR | `hibob/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 86 | Workday | HR | `workday/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 87 | Paychex | HR | `paychex/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 88 | Deel | HR | `deel/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 89 | Zenefits | HR | `zenefits/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 90 | Namely | HR | `namely/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 91 | QuickBooks Online | Finance | `quickbooks/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 92 | Xero | Finance | `xero/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 93 | Stripe | Finance | `stripe/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 94 | PayPal | Finance | `paypal/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 95 | Bill.com | Finance | `billdotcom/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 96 | Expensify | Finance | `expensify/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 97 | Sage Intacct | Finance | `sage_intacct/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 98 | FreshBooks | Finance | `freshbooks/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 99 | Wave | Finance | `wave/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 100 | Plaid | Finance | `plaid/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 101 | Brex | Finance | `brex/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 102 | Ramp | Finance | `ramp/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 103 | Clio | Legal | `clio/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 104 | Ironclad | Legal | `ironclad/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 105 | DocuSign | Legal | `docusign/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 106 | DocuSign CLM | Legal | `docusign_clm/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 107 | MyCase | Legal | `mycase/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 108 | PandaDoc | Legal | `pandadoc/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 109 | PandaDoc CLM | Legal | `pandadoc_clm/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 110 | HelloSign | Legal | `hellosign/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 111 | Gong | Sales | `gong/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 112 | Salesloft | Sales | `salesloft/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 113 | Apollo.io | Sales | `apollo/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 114 | Copper | Sales | `copper/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 115 | Insightly | Sales | `insightly/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 116 | Close | Sales | `close/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 117 | Mailchimp | Marketing | `mailchimp/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 118 | Klaviyo | Marketing | `klaviyo/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 119 | ActiveCampaign | Marketing | `activecampaign/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 120 | Constant Contact | Marketing | `constant_contact/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 121 | Braze | Marketing | `braze/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 122 | Mixpanel | Analytics | `mixpanel/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 123 | Segment | CDP | `segment/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 124 | Typeform | Marketing | `typeform/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 125 | SurveyMonkey | Marketing | `surveymonkey/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 126 | Eventbrite | Events | `eventbrite/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 127 | Navan | Travel | `navan/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 128 | SAP Concur | Supply | `sap_concur/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 129 | Coupa | Supply | `coupa/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 130 | Anvyl | Supply | `anvyl/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |

### Tier 5 — Vertical / Niche (131–200)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 131 | Cisco Meraki | Network | `meraki/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 132 | Fortinet | Network | `fortinet/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 133 | Zscaler | Network | `zscaler/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 134 | Check Point | Network | `checkpoint/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 135 | Palo Alto Prisma | Network | `paloalto/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 136 | NordLayer | Network | `nordlayer/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 137 | Perimeter 81 | Network | `perimeter81/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 138 | Netskope | Network | `netskope/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 139 | Sophos Central | Security | `sophos_central/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 140 | Sophos XG | Security | `sophos_xg/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 141 | CrowdStrike | Security | `crowdstrike/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 142 | SentinelOne | Security | `sentinelone/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 143 | Snyk | Security | `snyk/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 144 | HackerOne | Security | `hackerone/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 145 | HIBP | Security | `hibp/` | n/a | n/a | n/a | ⏳ | n/a | ⏳ |
| 146 | BitSight | Security | `bitsight/` | n/a | n/a | n/a | ⏳ | n/a | ⏳ |
| 147 | Tenable.io | Security | `tenable/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 148 | Qualys VMDR | Security | `qualys/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 149 | Rapid7 | Security | `rapid7/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 150 | VirusTotal | Security | `virustotal/` | n/a | n/a | n/a | ⏳ | n/a | ⏳ |
| 151 | Malwarebytes | Security | `malwarebytes/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 152 | ForgeRock | IAM | `forgerock/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 153 | BeyondTrust | IAM/PAM | `beyondtrust/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 154 | Keeper | Secrets/Vault | `keeper/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 155 | Wazuh | SIEM | `wazuh/` | n/a | n/a | n/a | ⏳ | n/a | ⏳ |
| 156 | OpenAI (ChatGPT) | GenAI | `openai/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 157 | Google Gemini | GenAI | `gemini/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 158 | Anthropic (Claude) | GenAI | `anthropic/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 159 | Perplexity AI | GenAI | `perplexity/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 160 | Mistral AI | GenAI | `mistral/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 161 | Midjourney | GenAI | `midjourney/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 162 | Jasper AI | GenAI | `jasper/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 163 | Copy.ai | GenAI | `copyai/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 164 | Practice Fusion | Health | `practice_fusion/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 165 | Kareo | Health | `kareo/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 166 | Zocdoc | Health | `zocdoc/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 167 | Yardi | Real Estate | `yardi/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 168 | Buildium | Real Estate | `buildium/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 169 | AppFolio | Real Estate | `appfolio/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 170 | NetSuite | ERP | `netsuite/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 171 | Coursera | Education | `coursera/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 172 | LinkedIn Learning | Training | `linkedin_learning/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 173 | Udemy Business | Training | `udemy_business/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 174 | Shopify | E-comm | `shopify/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 175 | WooCommerce | E-comm | `woocommerce/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 176 | BigCommerce | E-comm | `bigcommerce/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 177 | Magento | E-comm | `magento/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 178 | Square | E-comm | `square/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 179 | Recurly | E-comm | `recurly/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 180 | Chargebee | E-comm | `chargebee/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 181 | WordPress | Web | `wordpress/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 182 | Squarespace | Web | `squarespace/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 183 | Wix | Web | `wix/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 184 | Ghost | Web | `ghost/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 185 | SurveySparrow | Customer-Feedback | `surveysparrow/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 186 | Jotform | Customer-Feedback | `jotform/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 187 | Wufoo | Customer-Feedback | `wufoo/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 188 | Hootsuite | Social | `hootsuite/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 189 | Sprout Social | Social | `sprout_social/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 190 | Buffer | Social | `buffer/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 191 | Twilio | Comm | `twilio/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 192 | SendGrid | Comm | `sendgrid/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 193 | RingCentral | Comm | `ringcentral/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 194 | Vonage | Comm | `vonage/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 195 | Zapier | Utility | `zapier/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 196 | Make | Utility | `make/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 197 | IFTTT | Utility | `ifttt/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 198 | GA4 | Analytics | `ga4/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 199 | Heap | Analytics | `heap/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 200 | FullStory | Analytics | `fullstory/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |

---

## 2. Platform feature progress

| Feature | Status | Notes / target phase |
|---------|:------:|----------------------|
| Access Connector Framework | ✅ | Phase 0 — interface, registry, AES-GCM credential encryption (PR #2) |
| Access Request Workflow | 🟡 | Phase 2 — tables, state machine, request / provisioning / workflow services (PR #4); HTTP handlers `POST/GET /access/requests`, `POST /access/requests/:id/approve|deny|cancel`, `GET /access/grants` (PR #6); Admin UI / Mobile SDK / Desktop Extension still ⏳ |
| Policy Simulation Engine | 🟡 | Phase 3 — drafts, impact analysis, conflict detection, promotion, test-access (PR #5); HTTP handlers `POST /workspace/policy`, `GET /workspace/policy/drafts`, `GET /workspace/policy/:id`, `POST /workspace/policy/:id/simulate|promote`, `POST /workspace/policy/test-access` (PR #6); Admin UI policy simulator still ⏳ |
| AI Risk Assessment Agent | 🟡 | Phase 4 — Go-side A2A client + fallback (`internal/pkg/aiclient`), `AccessRequestService` and `PolicyService` integration with `risk_score` / `risk_factors` persisted on request rows + draft impact reports (PR #6); Python `access_risk_assessment` skill still ⏳ |
| AI Review Automation Agent | ⏳ | Phase 5 — `access_review_automation` skill |
| AI Setup Assistant Agent | ⏳ | Phase 4 — `connector_setup_assistant` skill |
| AI Anomaly Detection Agent | ⏳ | Phase 6 — `access_anomaly_detection` skill |
| AI Policy Recommendation Agent | 🟡 | Phase 4 — Go-side A2A client + `POST /access/explain` + `POST /access/suggest` HTTP handlers (PR #6); Python `policy_recommendation` skill still ⏳ |
| Access Review Campaigns | 🟡 | Phase 5 — tables, models, `StartCampaign` / `SubmitDecision` / `CloseCampaign` / `AutoRevoke` (PR #5); HTTP handlers `POST /access/reviews`, `POST /access/reviews/:id/decisions|close|auto-revoke` and `internal/cron.CampaignScheduler` driving `access_campaign_schedules` (PR #6); AI auto-certification and reviewer notification still ⏳ |
| JML Automation | ⏳ | Phase 6 — joiner / mover / leaver flows over SCIM |
| Outbound SCIM | ⏳ | Phase 6 — SCIM v2.0 push to SaaS |
| Workflow Orchestration | ⏳ | Phase 8 — LangGraph engine |
| iOS Access SDK | ⏳ | Phase 9 — Swift Package, REST only, no on-device inference |
| Android Access SDK | ⏳ | Phase 9 — Kotlin library, REST only, no on-device inference |
| Desktop Access Extension | ⏳ | Phase 9 — Electron IPC module, REST only, no on-device inference |
| Admin UI — Connector Marketplace | ⏳ | Phase 1 |
| Admin UI — Access Requests | ⏳ | Phase 2 |
| Admin UI — Policy Simulator | ⏳ | Phase 3 |
| Admin UI — Access Reviews | ⏳ | Phase 5 |
| Admin UI — AI Assistant | ⏳ | Phase 4 |

---

## 3. Open work items

These are explicit, sized, and ready to be picked up once Phase 0 lands. Each should land as its own PR with tests + a row update in §1 / §2.

### 3.1 AccessConnector contract & registry (Phase 0)

- **Why.** Nothing else can be built without the interface. The whole catalogue depends on it.
- **Scope.** `internal/services/access/types.go`, `factory.go`, AES-GCM reuse from `internal/pkg/credentials/manager.go`, `access_connectors` table + migration, registry-swap test pattern.
- **Out of scope.** Any actual connector implementation (Phase 1+).

### 3.2 Microsoft Entra ID connector (Phase 1)

- **Why.** Core Identity tier-1; primary lever for SSO + identity sync + audit.
- **Scope.** Reuse the existing Microsoft Graph integration from `shieldnet360-backend/internal/services/connectors/microsoft/`; map the SN360 `Connector` calls onto `AccessConnector`; add `ProvisionAccess` / `RevokeAccess` (currently absent in SN360 because that project is observation-only).
- **Out of scope.** Real-time push — push subscriptions are a Phase 7+ optimization.

### 3.3 Generic SAML connector (Phase 1)

- **Why.** A generic SAML broker covers ~60 % of enterprise SaaS that have no custom API.
- **Scope.** SP-initiated and IdP-initiated flows; metadata fetch via `GetSSOMetadata`; Keycloak IdP broker config templating.
- **Out of scope.** SCIM provisioning — the SAML connector federates only; provisioning is delegated to `generic_scim` (deferred).

### 3.4 Access request workflow (Phase 2)

- **Why.** End-user product surface; everything in mobile / desktop SDK depends on it.
- **Scope.** All four tables; state machine; self-service + manager workflows; admin UI; SDK API contracts.

### 3.5 Policy simulation engine (Phase 3 — remaining work)

- **What landed in PR #5.** `policies` table with `is_draft` + `draft_impact` columns; `teams` / `team_members` / `resources` stub tables; `PolicyService` with `CreateDraft` / `GetDraft` / `ListDrafts` / `GetPolicy` / `Simulate` / `Promote` / `TestAccess`; `ImpactResolver` with attribute-selector matching for teams and tag/external_id-selector matching for resources; `ConflictDetector` with redundant / contradictory classification against live policies. Drafts never create OpenZiti `ServicePolicy` until promotion (integration test enforces this).
- **Still open.** The four HTTP endpoints (`POST /policies/draft`, `POST /policies/{id}/simulate`, `POST /policies/{id}/promote`, `POST /policies/test-access`) are handler-layer work; the Admin UI's policy simulator (before/after diff, AI-narrated highlights, conflict surfacing) is a separate frontend deliverable.

### 3.6 Access review campaigns (Phase 5 — remaining work)

- **What landed in PR #5.** `access_reviews` and `access_review_decisions` tables; `AccessReview` + `AccessReviewDecision` models; `AccessReviewService` with `StartCampaign` (enrols matching active grants in a single transaction), `SubmitDecision` (commits decision row, then drives upstream `Revoke` for revoke decisions), `CloseCampaign` (auto-escalates pending decisions), and `AutoRevoke` (idempotent catch-up for revoke decisions whose upstream side-effect has not yet been executed).
- **Still open.** AI auto-certification (Phase 5 needs the `access_review_automation` skill to flip pending → certify based on usage signals); scheduled campaign templates (cron + workspace-scoped recurrence); reviewer notification fan-out (email / Slack / Mobile push); the Admin UI's campaign dashboard.

---

## 4. Recently shipped (changelog)

When you ship something from §3, move it here with the merge date and PR link. Newest first.

| Date | What | PR | Notes |
|------|------|----|-------|
| 2026-05-09 | Phase 2–5 — HTTP handler layer + AI A2A client + Phase 5 scheduled campaigns | #6 | Adds `internal/handlers` (Gin router, `helpers.go` with `GetStringParam`/`GetPtrStringQuery` per cross-cutting criteria, `errors.go` mapping service sentinels to HTTP status codes, policy / access-request / access-grant / access-review / AI handlers, and `/health`). Adds `internal/pkg/aiclient` (A2A client, `AssessRiskWithFallback` returning default risk_score=medium per PROPOSAL §5.3, `RiskAssessmentAdapter`). Adds `internal/config/access.go` reading `ACCESS_AI_AGENT_BASE_URL` / `ACCESS_AI_AGENT_API_KEY` / `ACCESS_WORKFLOW_ENGINE_BASE_URL` / `ACCESS_FULL_RESYNC_INTERVAL` (default 7d) / `ACCESS_REVIEW_DEFAULT_FREQUENCY` (default 90d) / `ACCESS_DRAFT_POLICY_STALE_AFTER` (default 14d). Wires AI risk scoring into `AccessRequestService.CreateRequest` (populates `risk_score` / `risk_factors`) and `PolicyService.Simulate` (stamps `risk_score` / `risk_factors` onto the impact report; failure leaves them empty rather than synthesising a default). Adds Phase 5 `access_campaign_schedules` table + model + migration `005` + `internal/cron.CampaignScheduler` that scans for due rows, calls `StartCampaign`, and bumps `next_run_at` by `frequency_days`. Wires `cmd/ztna-api/main.go` to `http.ListenAndServe` on `ZTNA_API_LISTEN_ADDR` (default `:8080`). |
| 2026-05-09 | Phase 3 + Phase 5 — policy simulation engine + access review campaigns (backend) | #5 | Adds migrations `003_create_policy_tables` (`policies`, `teams`, `team_members`, `resources`) and `004_create_access_review_tables` (`access_reviews`, `access_review_decisions`). Adds `Policy` / `Team` / `TeamMember` / `Resource` / `AccessReview` / `AccessReviewDecision` models. Adds `PolicyService` (`CreateDraft` / `GetDraft` / `ListDrafts` / `GetPolicy` / `Simulate` / `Promote` / `TestAccess`), `ImpactResolver` (attribute-selector matching for teams; tag / external_id matching for resources), `ConflictDetector` (redundant / contradictory classification against live policies), and `AccessReviewService` (`StartCampaign` / `SubmitDecision` / `CloseCampaign` / `AutoRevoke`). Drafts never create OpenZiti `ServicePolicy` until promotion (integration test). Admin UI for policy simulator + access review dashboard remains ⏳; HTTP endpoints for both phases (handler layer) are open follow-ups. |
| 2026-05-09 | Phase 2 — access request tables, state machine, request / provisioning / workflow services | #4 | Adds `access_requests`, `access_request_state_history`, `access_grants`, `access_workflows` tables and migration `002_create_access_request_tables`. Adds `request_state_machine.go` (pure FSM, mirrors `ztna-business-layer/internal/state_machine/`), `request_service.go` (`CreateRequest` / `ApproveRequest` / `DenyRequest` / `CancelRequest`), `provisioning_service.go` (connector-based `Provision` / `Revoke` with `provision_failed` retry path), and `workflow_service.go` (`ResolveWorkflow` + `ExecuteWorkflow` with auto-approve / manager-approval steps). Admin UI, Mobile SDK, Desktop Extension exit criteria remain ⏳. |
| 2026-05-09 | Phase 1 — remaining 7 Tier 1 connectors | #N | Auth0, Generic SAML, Generic OIDC, Duo Security, 1Password, LastPass, Ping Identity. Each ships `Validate` (pure-local) + `Connect` + `SyncIdentities`/`CountIdentities` (or no-op for SSO-only providers) + `GetSSOMetadata`/`GetCredentialsMetadata`. `ProvisionAccess` / `RevokeAccess` / `ListEntitlements` remain Phase 1 stubs. |
| 2026-05-09 | Phase 0 — contract, registry, credential manager, migration | #2 | Full Phase 0 exit criteria met. First 3 connectors (Microsoft, Google Workspace, Okta) with `Validate` + `Connect` + `SyncIdentities` |

---

## 5. Known regressions / debt

Use this section sparingly. If something belongs here for more than two sprints, promote it to §3.

| Area | Problem | Tracking |
|------|---------|----------|
| _empty_ | _greenfield project — no regressions yet_ | — |

---

## 6. How to update this file

1. When you start a phase item: leave `PROGRESS.md` alone; just open the PR.
2. When you ship: flip the row in §1 / §2 to ✅ (or 🟡 with notes), move the matching item from §3 → §4, and add the PR link.
3. When you discover a regression: add it to §5 with concrete acceptance for closing it.
4. Keep tone factual — this file is read by operators and reviewers, not customers.
