# ShieldNet 360 Access Platform — Progress Tracker

Last updated: keep this file in sync as PRs land. The state here should agree with `git log`.

For the canonical phase definitions (and what "shipped" means), see `PHASES.md`. For the design contract see `PROPOSAL.md`.

Status: **In progress | ~92 %**. Phase 0 (contract, registry, credential manager, migration) is complete; Phase 1 Tier 1 is now feature-complete on the connector axis — all 10 Tier 1 connectors ship the minimum capabilities and are wired into the binaries via blank-import. Phase 1 stays 🟡 partial: the Admin UI and Keycloak SSO federation exit criteria are still unchecked. **Phase 2 is now 🟡 partial**: the four request-lifecycle tables, the request lifecycle FSM, the request / provisioning / workflow services (PR #4) AND the HTTP endpoint layer (`POST/GET /access/requests`, `POST /access/requests/:id/approve|deny|cancel`, `GET /access/grants`) have landed (PR #6); Admin UI / Mobile SDK / Desktop Extension exit criteria remain open. **Phase 3 is now 🟡 partial**: the `policies` / `teams` / `team_members` / `resources` tables, the Policy + Team + Resource models, `PolicyService`, `ImpactResolver`, `ConflictDetector` (PR #5) AND the HTTP endpoints (`POST /workspace/policy`, `GET /workspace/policy/drafts`, `GET /workspace/policy/:id`, `POST /workspace/policy/:id/simulate|promote`, `POST /workspace/policy/test-access`) have landed (PR #6); the Admin UI's policy simulator remains open. **Phase 4 is now 🟡 partial**: the A2A AI client (`internal/pkg/aiclient`), the env-driven access platform config (`internal/config`), the AI risk-scoring integration in `AccessRequestService.CreateRequest` and `PolicyService.Simulate`, and the `POST /access/explain` + `POST /access/suggest` endpoints have landed (PR #6); the AI agent service itself (Python) and the Admin UI's AI assistant remain open. **Phase 5 is now 🟡 partial**: the `access_reviews` / `access_review_decisions` tables, the matching models, `AccessReviewService` (`StartCampaign` / `SubmitDecision` / `CloseCampaign` / `AutoRevoke`) (PR #5), the HTTP endpoints (`POST /access/reviews`, `POST /access/reviews/:id/decisions|close|auto-revoke`), AND the Phase 5 scheduled-campaigns scaffold (`access_campaign_schedules` table + model + migration `005` + `internal/cron.CampaignScheduler`) have landed (PR #6); the Phase 5 notification scaffold (`internal/services/notification.NotificationService`, `Notifier` interface, in-memory channel, fan-out from `StartCampaign`), the auto-certification rate metric + `GET /access/reviews/:id/metrics` endpoint, and the admin `PATCH /access/reviews/:id` toggle now ship in PR #7. AI auto-certification (the Python skill flipping pending → certify) and email / Slack channels remain open. **Phase 6 is now 🟡 partial**: the JML service (`internal/services/access.JMLService` with `ClassifyChange` / `HandleJoiner` / `HandleMover` / `HandleLeaver`), the SCIM inbound handler (`POST /scim/Users`, `PATCH /scim/Users/:id`, `DELETE /scim/Users/:id`), the outbound SCIM v2.0 client (`internal/services/access.SCIMClient` connectors compose), and the Go-side `access_anomaly_detection` stub (`AIClient.DetectAnomalies`, `DetectAnomaliesWithFallback`, `AnomalyDetectionService.ScanWorkspace`) have landed in PR #7. The Phase 6 admin UI surfaces and the real anomaly LLM remain open. **Phase 4 (Python agent)** is now 🟡 partial as well: the `cmd/access-ai-agent/` A2A skill server with all five Tier-1 stubs ships in PR #7. Most rows below remain `⏳ planned`.

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
| 1 | Microsoft Entra ID | IAM/SSO | `microsoft/` | 🟡 | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 |
| 2 | Google Workspace | IAM/SSO | `google_workspace/` | 🟡 | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 |
| 3 | Okta | IAM/SSO | `okta/` | 🟡 | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 |
| 4 | Auth0 | IAM/SSO | `auth0/` | 🟡 | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 |
| 5 | Generic SAML | IAM/SSO | `generic_saml/` | n/a | n/a | n/a | n/a | 🟡 | 🟡 |
| 6 | Generic OIDC | IAM/SSO | `generic_oidc/` | n/a | n/a | n/a | n/a | 🟡 | 🟡 |
| 7 | Duo Security | IAM/MFA | `duo/` | 🟡 | 🟡 | ⏳ | ⏳ | n/a | 🟡 |
| 8 | 1Password | Secrets/Vault | `onepassword/` | 🟡 | 🟡 | ⏳ | ⏳ | n/a | 🟡 |
| 9 | LastPass | Secrets/Vault | `lastpass/` | 🟡 | 🟡 | ⏳ | ⏳ | n/a | 🟡 |
| 10 | Ping Identity | IAM/SSO | `ping_identity/` | 🟡 | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 |

### Tier 2 — Cloud Infrastructure (11–25)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 11 | AWS IAM | Cloud Infra | `aws/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 12 | Azure RBAC | Cloud Infra | `azure/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 13 | GCP IAM | Cloud Infra | `gcp/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 14 | Cloudflare | Cloud Infra | `cloudflare/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 15 | Tailscale | Network | `tailscale/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 16 | DigitalOcean | Cloud Infra | `digitalocean/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 17 | Heroku | Cloud Infra | `heroku/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 18 | Vercel | Cloud Infra | `vercel/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 19 | Netlify | Cloud Infra | `netlify/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 20 | Vultr | Cloud Infra | `vultr/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 21 | Linode | Cloud Infra | `linode/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 22 | OVHcloud | Cloud Infra | `ovhcloud/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 23 | Alibaba Cloud | Cloud Infra | `alibaba/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 24 | CloudSigma | Cloud Infra | `cloudsigma/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 25 | Wasabi | Storage | `wasabi/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |

### Tier 3 — Business SaaS (26–80)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 26 | Slack | Collab | `slack/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 27 | MS Teams | Collab | `ms_teams/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 28 | Zoom | Collab | `zoom/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 29 | Notion | Productivity | `notion/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 30 | Asana | Productivity | `asana/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 31 | Monday.com | Productivity | `monday/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 32 | Figma | Design | `figma/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 33 | Miro | Whiteboard | `miro/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 34 | Trello | Productivity | `trello/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 35 | Airtable | Productivity | `airtable/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 36 | Smartsheet | Productivity | `smartsheet/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 37 | ClickUp | Productivity | `clickup/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 38 | Salesforce | CRM | `salesforce/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 39 | HubSpot | CRM | `hubspot/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 40 | Zoho CRM | CRM | `zoho_crm/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 41 | Pipedrive | CRM | `pipedrive/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 42 | Dropbox Business | Storage | `dropbox/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 43 | Box | Storage | `box/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 44 | Egnyte | Storage | `egnyte/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 45 | GitHub | DevOps | `github/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 46 | GitLab | DevOps | `gitlab/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 47 | Atlassian Jira | DevOps | `jira/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 48 | PagerDuty | DevOps | `pagerduty/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 49 | Sentry | DevOps | `sentry/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 50 | Terraform | DevOps | `terraform/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 51 | Docker Hub | DevOps | `docker_hub/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 52 | JFrog | DevOps | `jfrog/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 53 | SonarCloud | DevOps | `sonarcloud/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 54 | CircleCI | DevOps | `circleci/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 55 | Travis CI | DevOps | `travis_ci/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 56 | LaunchDarkly | DevOps | `launchdarkly/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 57 | Datadog | Observability | `datadog/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 58 | New Relic | Observability | `new_relic/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 59 | Splunk Cloud | Observability | `splunk/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 60 | Grafana | Observability | `grafana/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 61 | Mezmo | Observability | `mezmo/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 62 | Sumo Logic | Observability | `sumo_logic/` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| 63 | Zendesk | Support | `zendesk/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 64 | Freshdesk | Support | `freshdesk/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 65 | Help Scout | Support | `helpscout/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 66 | Front | Support | `front/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 67 | Intercom | Support | `intercom/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
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
| 81 | BambooHR | HR | `bamboohr/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 82 | Gusto | HR | `gusto/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 83 | Rippling | HR | `rippling/` | 🟡 | ⏳ | ⏳ | ⏳ | ⏳ | 🟡 |
| 84 | Personio | HR | `personio/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 85 | Hibob | HR | `hibob/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 86 | Workday | HR | `workday/` | 🟡 | ⏳ | ⏳ | ⏳ | 🟡 | 🟡 |
| 87 | Paychex | HR | `paychex/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 88 | Deel | HR | `deel/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 89 | Zenefits | HR | `zenefits/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 90 | Namely | HR | `namely/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 91 | QuickBooks Online | Finance | `quickbooks/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 92 | Xero | Finance | `xero/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 93 | Stripe | Finance | `stripe/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 94 | PayPal | Finance | `paypal/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 95 | Bill.com | Finance | `billdotcom/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 96 | Expensify | Finance | `expensify/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 97 | Sage Intacct | Finance | `sage_intacct/` | ⏳ | ⏳ | ⏳ | ⏳ | n/a | ⏳ |
| 98 | FreshBooks | Finance | `freshbooks/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 99 | Wave | Finance | `wave/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
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
| 141 | CrowdStrike | Security | `crowdstrike/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 142 | SentinelOne | Security | `sentinelone/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
| 143 | Snyk | Security | `snyk/` | 🟡 | ⏳ | ⏳ | ⏳ | n/a | 🟡 |
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
| AI Risk Assessment Agent | 🟡 | Phase 4 — Go-side A2A client + fallback (`internal/pkg/aiclient`), `AccessRequestService` and `PolicyService` integration with `risk_score` / `risk_factors` persisted on request rows + draft impact reports (PR #6); Python `access_risk_assessment` skill stub now ships under `cmd/access-ai-agent/skills/access_risk_assessment.py` (PR #7); LLM-backed scorer still ⏳ |
| AI Review Automation Agent | 🟡 | Phase 5 — Python `access_review_automation` stub (PR #7); Go-side `ReviewAutomator` + `applyAutoCertification` wiring into `AccessReviewService.StartCampaign` (PR #8); Admin UI surface still ⏳ |
| AI Setup Assistant Agent | 🟡 | Phase 4 — Python `connector_setup_assistant` stub under `cmd/access-ai-agent/skills/connector_setup_assistant.py` (PR #7); Admin-UI conversational surface still ⏳ |
| AI Anomaly Detection Agent | 🟡 | Phase 6 — Go-side `AnomalyDetectionService.ScanWorkspace` + Python stub (PR #7); `AnomalyScanner` cron job with per-workspace dispatch + config (PR #8); cross-grant baseline histogram still ⏳ |
| AI Policy Recommendation Agent | 🟡 | Phase 4 — Go-side A2A client + `POST /access/explain` + `POST /access/suggest` HTTP handlers (PR #6); Python `policy_recommendation` stub now ships under `cmd/access-ai-agent/skills/policy_recommendation.py` (PR #7); LLM-backed generator still ⏳ |
| Access Review Campaigns | 🟡 | Phase 5 — tables, models, services (PR #5/#6/#7); AI auto-certification wire-in via `ReviewAutomator` + `applyAutoCertification` (PR #8); email + Slack notification channels (PR #8); Admin UI dashboard still ⏳ |
| Notification System | 🟡 | Phase 5 — `NotificationService` + `Notifier` interface + in-memory channel (PR #7); `EmailNotifier` (SMTP) + `SlackNotifier` (webhook / Block Kit) (PR #8); push channel still ⏳ |
| JML Automation | 🟡 | Phase 6 — `JMLService` with `ClassifyChange` / `HandleJoiner` / `HandleMover` / `HandleLeaver` (PR #7); `OpenZitiClient` interface + `DisableIdentity` wire-in on leaver (PR #8); Admin UI still ⏳ |
| Outbound SCIM | 🟡 | Phase 6 — generic `SCIMClient` (PR #7); per-connector `SCIMProvisioner` composition for Okta + 1Password (PR #8); Microsoft Entra + Google Workspace + Auth0 + Duo + LastPass + Ping Identity composition (PR #9); all 10 Tier 1 connectors now ship outbound SCIM |
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

These are explicit, sized, and ready to be picked up. Phase 0 – Phase 5 platform scaffolding has all shipped (see §4 changelog). The remaining open work is mostly the Admin UI surfaces, the AI agent LLM-backed implementations, and the long tail of Tier 3 – Tier 5 connectors. Each item below should land as its own PR with tests + a row update in §1 / §2.

### 3.1 Admin UI surfaces (Phases 1–5)

- **Why.** The Go services and HTTP routes are in place, but end-users still need React surfaces in `ztna-frontend`.
- **Scope.** Connector Marketplace (Phase 1), Access Requests (Phase 2), Policy Simulator with before/after diff (Phase 3), Access Reviews dashboard (Phase 5), AI Assistant chat surface (Phase 4).
- **Out of scope.** Any backend changes — the REST API is final.

### 3.2 AI agent LLM-backed implementations (Phase 4 / Phase 6)

- **Why.** The Python A2A skill server ships stubs for `access_risk_assessment`, `access_review_automation`, `access_anomaly_detection`, `connector_setup_assistant`, and `policy_recommendation`, but each one currently returns deterministic synthetic data.
- **Scope.** Replace each stub with the real LLM-backed implementation; wire `aiclient` consumers to the new outputs; add evaluation harness in `cmd/access-ai-agent/tests/`.
- **Out of scope.** Local on-device inference — mobile / desktop clients remain REST-only.

### 3.3 Workflow Orchestration (Phase 8)

- **Why.** `cmd/access-workflow-engine/` is still a stub binary; LangGraph host + step types are not yet implemented.
- **Scope.** LangGraph runtime, durable step state, retry / DLQ, integration with `WorkflowService`.
- **Out of scope.** Cross-workspace federation (Phase 10+).

### 3.4 Mobile / Desktop SDKs (Phase 9)

- **Why.** Phase 9 deliverables; not yet started.
- **Scope.** Swift Package, Kotlin library, Electron extension. All REST-only — no on-device inference.
- **Out of scope.** Server-side AI changes.

### 3.5 Long-tail connectors (Phase 7 — remaining)

- **Why.** 117 of 200 providers remain `⏳` after the Phase 7 expansion shipped in PR #12.
- **Scope.** The remaining Tier 3 (Travis CI, Mezmo, Sumo Logic, Drift, Crisp, LiveChat, Gorgias, Loom, Discord, Slack Enterprise, Basecamp, Quip, Wrike, Teamwork, LiquidPlanner, KnowBe4), Tier 4 (Sage Intacct, Bill.com, Expensify, Plaid, Brex, Ramp, Clio, Ironclad, DocuSign, DocuSign CLM, MyCase, PandaDoc, PandaDoc CLM, HelloSign, Sales / Marketing / Analytics / Travel / Supply categories), and the entire Tier 5 catalogue.
- **Out of scope.** Any change to the `AccessConnector` contract — each new provider just plugs into the established template.

### 3.6 Access review campaigns (Phase 5 — remaining work)

- **What landed in PR #5.** `access_reviews` and `access_review_decisions` tables; `AccessReview` + `AccessReviewDecision` models; `AccessReviewService` with `StartCampaign` (enrols matching active grants in a single transaction), `SubmitDecision` (commits decision row, then drives upstream `Revoke` for revoke decisions), `CloseCampaign` (auto-escalates pending decisions), and `AutoRevoke` (idempotent catch-up for revoke decisions whose upstream side-effect has not yet been executed).
- **What landed in PR #7.** Auto-certification rate metric (`AccessReviewService.GetCampaignMetrics`) and HTTP surface (`GET /access/reviews/:id/metrics`); admin `PATCH /access/reviews/:id` toggle for `auto_certify_enabled` (rejects on closed / cancelled campaigns); Phase 5 notification scaffold (`internal/services/notification.NotificationService`, `Notifier` interface, in-memory channel) wired into `StartCampaign` via `ReviewNotifier` + `ReviewerResolver` adapters; failures are logged but never roll back the campaign.
- **Still open.** AI auto-certification (the Python `access_review_automation` skill stub ships in PR #7 but the Go-side wire-in that flips pending → certify based on usage signals is still ⏳); scheduled campaign templates beyond `access_campaign_schedules` (workspace-scoped recurrence with skip dates); email / Slack / Mobile push channels for the notification service; the Admin UI's campaign dashboard.

---

## 4. Recently shipped (changelog)

When you ship something from §3, move it here with the merge date and PR link. Newest first.

| Date | What | PR | Notes |
|------|------|----|-------|
| 2026-05-10 | Phase 7 expansion: Stripe fix + 19 Tier-3 / Tier-4 connectors | #12 | 20 tasks. **T1** (Stripe fix): the Stripe connector previously hit `/v1/team_members` (which is not a public REST endpoint) — it now syncs Stripe Connect connected accounts via `/v1/accounts` (Bearer secret_key + `starting_after` cursor + `has_more`) with `IdentityTypeServiceAccount`, and `charges_enabled` / `payouts_enabled` mapping to `restricted` vs `active` status; README project tree + ARCHITECTURE.md description updated to match. **T2** (Tier 3 Storage): `egnyte/` (`/pubapi/v2/users` with Bearer + offset/count pagination + SCIM-like `resources`/`totalResults`/`itemsPerPage`). **T3-T8** (Tier 3 DevOps): `terraform/` (Terraform Cloud `/api/v2/organizations/{org}/organization-memberships` with Bearer + `page[number]`/`page[size]` + JSON:API `data`/`included`), `docker_hub/` (`/v2/users/login` JWT exchange first, then `/v2/orgs/{org}/members` with `next` URL pagination), `jfrog/` (`/access/api/v2/users` with Bearer + offset/limit + `pagination.total`), `sonarcloud/` (`/api/organizations/search_members?organization={org}` with Bearer + `p`/`ps` 1-indexed page pagination), `circleci/` (`/api/v2/me/collaborations` with `Circle-Token` header — single-page, no pagination), `launchdarkly/` (`/api/v2/members` with raw Authorization API key + offset/limit + `totalCount`). **T9-T12** (Tier 3 Observability): `datadog/` (`/api/v2/users` with `DD-API-KEY` + `DD-APPLICATION-KEY` headers + `page[number]`/`page[size]` URL-encoded brackets + `meta.page.total_count` + Site config), `new_relic/` (NerdGraph POST `/graphql` with `API-Key` + cursor pagination via `nextCursor` on `users` connection inside `authenticationDomains`), `splunk/` (`/services/authentication/users?output_mode=json` with Bearer + `count`/`offset` + `paging.total` + `locked-out` status mapping), `grafana/` (`/api/org/users` with Bearer or Basic auth — single-page response). **T13-T14** (Tier 3 Support): `front/` (`/teammates` with Bearer + `_pagination.next` URL cursor + `is_blocked` status mapping), `intercom/` (`/admins` with Bearer — single-page response + `away_mode_enabled` mapping). **T15-T18** (Tier 4 HR): `paychex/` (`/companies/{id}/workers` with OAuth2 Bearer + offset/limit + `content.metadata.pagination.totalItems`), `deel/` (`/rest/v2/contracts` with Bearer + `page`/`page_size`; workers projected from contract.worker.{id,first_name,last_name,email} with dedupe), `zenefits/` (`/core/people` with Bearer + `next_url` link pagination on `data.next_url` envelope), `namely/` (`/api/v1/profiles` with Bearer + `page`/`per_page` + `meta.total_count` + subdomain-derived host). **T19-T20** (Tier 4 Finance): `paypal/` (OAuth2 client_credentials → `/v1/oauth2/token` Basic exchange, then `/v1/customer/partners/{partner_id}/merchant-integrations` with `page`/`page_size` + `total_items`; merchants modelled as `IdentityTypeServiceAccount`, `payments_receivable=false` ⇒ `restricted`), `wave/` (Wave Financial GraphQL POST `/graphql/public` with Bearer; `businesses(first, after)` connection with `pageInfo.endCursor`/`hasNextPage` cursor; `IdentityTypeServiceAccount` mapping + `isArchived`/`isActive` status). All 19 new connector packages register via `init()` and are blank-imported alphabetically into all three cmd binaries; each ships the canonical 7-test layout (`TestValidate_HappyPath`, `TestValidate_RejectsMissing`, `TestValidate_PureLocal`, `TestRegistryIntegration`, `TestSync_PaginatesUsers`, `TestConnect_Failure`, `TestGetCredentialsMetadata_RedactsToken`); `Validate` is pure-local (network swap test verifies); `ProvisionAccess`/`RevokeAccess`/`ListEntitlements` return `ErrNotImplemented`; `GetSSOMetadata` returns `nil, nil` (none of these providers expose SAML metadata). README + ARCHITECTURE.md + PHASES.md updated. Connector totals: **64 → 83 / 200**. Tier 3: 26/55 → 39/55. Tier 4: 10/50 → 16/50. |
| 2026-05-10 | Phase 7 batch: 20 Cloud-Infra-Tier-2 + Finance + HR + SaaS connectors | #11 | 20 tasks. **T1-T6** (remaining Tier 2 Cloud Infra — closes 15/15): `vultr/` (`/v2/users` with Bearer auth + cursor `meta.links.next`), `linode/` (`/v4/account/users` with page/page_size + total `pages`), `ovhcloud/` (`/1.0/me/identity/user` with OVH application-key/consumer-key/secret signature headers + endpoint switch eu/ca/us), `alibaba/` (RAM `ListUsers` with HMAC-SHA1 signed query + `Marker`/`IsTruncated`), `cloudsigma/` (`/api/2.0/profile/` HTTP Basic over per-region host — single-user identity), `wasabi/` (IAM-compatible `ListUsers` with AWS SigV4 reused from `aws/sigv4.go` + `Marker`/`IsTruncated`). **T7-T10** (Finance — closes 4/4): `quickbooks/` (`/v3/company/{realm}/query` with `SELECT * FROM Employee STARTPOSITION/MAXRESULTS` + OAuth2 bearer), `xero/` (`/api.xro/2.0/Users` with `Xero-Tenant-Id` header + offset pagination), `stripe/` (`/v1/team_members` with Bearer secret_key + `starting_after` cursor + `has_more`), `freshbooks/` (`/accounting/account/{account_id}/users/staffs` with page/per_page + Bearer access_token). **T11-T16** (HR — closes 6/6): `bamboohr/` (`/api/gateway.php/{subdomain}/v1/employees/directory` with `api_key:x` Basic auth + SAML metadata at `{subdomain}.bamboohr.com/saml/metadata`), `gusto/` (`/v1/companies/{company_id}/employees` with Bearer + page/per pagination), `rippling/` (`/platform/api/employees` with cursor `nextCursor`/`next` + `/platform/api/me` probe), `personio/` (OAuth2 client_credentials -> `/v1/auth` -> `/v1/company/employees` with offset/limit + Personio attribute-wrapped JSON unwrap helpers), `hibob/` (`/v1/people?showInactive=true` with `Basic {api_token}` — single-page result), `workday/` (`/ccx/api/v1/{tenant}/workers` with offset/limit + `total` field + Workday SAML metadata at `/{tenant}/saml2/metadata`). **T17-T20** (Tier 3 SaaS): `smartsheet/` (`/2.0/users` with Bearer + page/pageSize/totalPages), `clickup/` (`/api/v2/team/{team_id}/member` with raw API token in Authorization header), `dropbox/` (POST `/2/team/members/list_v2` then `/list/continue_v2` with `has_more`/`cursor` + Bearer + Dropbox Business SAML metadata), `box/` (`/2.0/users?user_type=all` with offset/limit + `total_count` + Bearer). All 20 packages registered via `init()` and blank-imported in `cmd/ztna-api/main.go`, `cmd/access-connector-worker/main.go`, `cmd/access-workflow-engine/main.go`. Each connector ships `connector_test.go` with `TestValidate_HappyPath`, `TestValidate_RejectsMissing`, `TestValidate_PureLocal` (swaps `http.DefaultTransport` to a roundtripper that fails on any network call to enforce zero-I/O Validate), `TestRegistryIntegration`, `TestSync_PaginatesUsers` (httptest.Server with at least two pages — never a real API), `TestConnect_Failure` (401 path), `TestGetCredentialsMetadata_RedactsToken` (4-leading + 4-trailing redaction). All `go build`, `go vet`, `go test -race -timeout=180s ./...`, and `pytest cmd/access-ai-agent/tests/` are green. |
| 2026-05-10 | Phase 7 final batch: 20 Tier-3 / Tier-5 connectors | #10 | 20 tasks. **T1-T9** (Productivity / Design / CRM): `monday/` (GraphQL `query { users { id name email } }` with page-number pagination), `figma/` (`/v1/teams/{team_id}/members` with `X-Figma-Token` header + cursor pagination), `miro/` (`/v2/orgs/{org_id}/members` with cursor pagination), `trello/` (`/1/organizations/{org_id}/members` with `key`/`token` query-string auth), `airtable/` (`/v0/meta/enterpriseAccount/{enterprise_id}/users` with offset pagination), `salesforce/` (SOQL `SELECT Id, Name, Email, IsActive FROM User` over `/services/data/v59.0/query` with nextRecordsUrl pagination + SAML metadata at `{instance_url}/identity/saml/metadata`), `hubspot/` (`/settings/v3/users` with `paging.next.after` cursor), `zoho_crm/` (`/crm/v5/users` with page/per_page pagination + `Zoho-oauthtoken` auth), `pipedrive/` (`/v1/users` with `api_token` query-string auth + `additional_data.pagination.next_start`). **T10-T17** (DevOps / Support): `github/` (`/orgs/{org}/members` with RFC 5988 Link-header pagination + GitHub Enterprise SAML metadata), `gitlab/` (`/api/v4/groups/{group_id}/members/all` with `X-Next-Page` header pagination + self-hosted `base_url` + GitLab group SAML metadata), `jira/` (Atlassian Cloud `/rest/api/3/users/search` over `api.atlassian.com/ex/jira/{cloud_id}` with `email:api_token` Basic auth + startAt/maxResults pagination + Atlassian Access SAML metadata at `{site_url}/admin/saml/metadata`), `pagerduty/` (`/users` with `Token token=...` auth + offset/limit + `more` flag), `sentry/` (`/api/0/organizations/{org_slug}/members/` with `Link rel="next"; results="true"` cursor pagination), `zendesk/` (`/api/v2/users.json` with `email/token:api_token` Basic auth + `next_page` URL pagination + SAML metadata at `https://{subdomain}.zendesk.com/access/saml/metadata`), `freshdesk/` (`/api/v2/agents` with `api_key:X` Basic auth + page-size-as-EOF pagination), `helpscout/` (`/v2/users` with bearer token + HAL `_embedded.users` + `page.totalPages` pagination). **T18-T20** (Security / Vertical): `crowdstrike/` (OAuth2 client_credentials at `/oauth2/token` then query-then-hydrate via `GET /user-management/queries/users/v1` + `POST /user-management/entities/users/GET/v1` with offset/limit), `sentinelone/` (`/web/api/v2.1/users` with `ApiToken` auth + `pagination.nextCursor`), `snyk/` (`/rest/orgs/{org_id}/members?version=2024-08-25` with `token` auth + `links.next` cursor + relative-URL rewrite). All 20 connectors register via `init()` and are blank-imported in `cmd/ztna-api/main.go`, `cmd/access-connector-worker/main.go`, `cmd/access-workflow-engine/main.go` (alphabetically sorted). Each carries `Validate` (pure-local, no I/O), `Connect` (network probe), `SyncIdentities` (internal pagination exhaustion — handler receives complete batches, never a cursor), `CountIdentities`, `GetCredentialsMetadata` with token redaction (4+4 chars), `ProvisionAccess` / `RevokeAccess` / `ListEntitlements` returning `ErrNotImplemented`. SSO-equipped providers (Salesforce, GitHub, GitLab, Jira, Zendesk) return SAML metadata via `GetSSOMetadata`; others return `nil, nil`. Each connector ships 7 test methods (`TestValidate_HappyPath`, `TestValidate_RejectsMissing`, `TestValidate_PureLocal`, `TestRegistryIntegration`, `TestSync_PaginatesUsers`, `TestConnect_Failure`, `TestGetCredentialsMetadata_RedactsToken`) using `httptest.Server` — never the real APIs. |
| 2026-05-09 | Phase 6 SCIM completion + Phase 7 Cloud-Infra & Collaboration connectors | #9 | 20 tasks. **T1-T6**: SCIM composition for Microsoft Entra, Google Workspace, Auth0, Duo, LastPass, Ping Identity (full 10 Tier-1 outbound SCIM coverage). **T7-T15**: 9 new Cloud Infra connectors — `aws/` (SigV4 IAM ListUsers/GetAccountSummary/ListAccessKeys), `azure/` (Microsoft Graph users + $count + app-secret expiry), `gcp/` (cloudresourcemanager getIamPolicy flatten), `cloudflare/`, `tailscale/`, `digitalocean/`, `heroku/`, `vercel/`, `netlify/`. **T16-T20**: 5 new Collaboration connectors — `slack/` (auth.test + users.list cursor pagination + Enterprise-Grid SAML), `ms_teams/` (client_credentials + /teams/{id}/members + Entra SAML), `zoom/` (Server-to-Server OAuth + /users page tokens), `notion/` (start_cursor pagination + bot vs person), `asana/` (workspace users with offset pagination). All 14 new connectors registered via `init()` in their package and blank-imported in `cmd/ztna-api/main.go`, `cmd/access-connector-worker/main.go`, `cmd/access-workflow-engine/main.go`. Each connector carries happy-path + failure-path connector_test.go covering Validate (pure-local, no I/O), Connect, SyncIdentities pagination, and GetCredentialsMetadata redaction. |
| 2026-05-09 | Phase 3-6 backend completion: auto-cert wire-in, notifications, OpenZiti disable, SCIM composition, cron jobs, sync state, access jobs, credential checker | #8 | 10 tasks. **T1**: `ReviewAutomator` + `applyAutoCertification` in `StartCampaign`. **T2**: Integration tests: drafts never create OpenZiti `ServicePolicy`. **T3**: `EmailNotifier` (SMTP). **T4**: `SlackNotifier` (webhook / Block Kit). **T5**: `OpenZitiClient.DisableIdentity` on leaver. **T6**: `SCIMProvisioner` for Okta + 1Password. **T7**: `AnomalyScanner` cron. **T8**: `access_sync_state` table + migration 006 + `SyncStateService`. **T9**: `access_jobs` table + migration 007 + worker handlers. **T10**: `CredentialChecker` cron. |
| 2026-05-09 | Phase 4–6 — Python A2A skill server + JML / inbound SCIM / outbound SCIM v2.0 / Go-side anomaly stub + notification scaffold + auto-certification rate metric | #7 | Adds `cmd/access-ai-agent/` with stdlib `http.server` A2A skill server hosting `access_risk_assessment`, `access_review_automation`, `access_anomaly_detection`, `connector_setup_assistant`, `policy_recommendation` plus a `Dockerfile`, `requirements.txt` (pytest only), and `tests/` (32 pytest cases). Adds `internal/services/access/jml_service.go` with `ClassifyChange` / `HandleJoiner` (assigns default Teams, bulk-creates approved access_requests, fans out provisioning) / `HandleMover` (atomic batch revoke + provision, no partial-access window per PROPOSAL §5.4) / `HandleLeaver` (enumerate active grants → bulk-revoke → remove team memberships). Adds `internal/handlers/scim_handler.go` wiring `POST /scim/Users` → Joiner, `PATCH /scim/Users/:id` → Mover, `DELETE /scim/Users/:id` → Leaver. Adds `internal/services/access/scim_provisioner.go` — generic SCIM v2.0 push with `PushSCIMUser` / `PushSCIMGroup` / `DeleteSCIMResource`, sentinel errors `ErrSCIMRemoteConflict` / `ErrSCIMRemoteNotFound` / `ErrSCIMRemoteUnauthorized` / `ErrSCIMRemoteServer` / `ErrSCIMConfigInvalid`, and idempotent 404-on-DELETE handling. Adds `internal/pkg/aiclient.AnomalyEvent`, `AIClient.DetectAnomalies`, `DetectAnomaliesWithFallback` (returns empty on AI unreachable per PROPOSAL §5.3), and `internal/services/access.AnomalyDetectionService.ScanWorkspace`. Adds `internal/services/notification` with `NotificationService.NotifyReviewersPending` / `NotifyRequester`, `Notifier` interface, `InMemoryNotifier` for dev / tests; failures never block lifecycle writes. Wires `AccessReviewService.StartCampaign` to fan out via `ReviewNotifier` + `ReviewerResolver` after commit. Adds `AccessReviewService.GetCampaignMetrics` returning total / pending / certified / auto-certified / revoked / escalated / auto_certification_rate plus `GET /access/reviews/:id/metrics` and `PATCH /access/reviews/:id` admin toggle for `auto_certify_enabled`. Fixes the silent risk-score UPDATE error on `AccessRequestService.CreateRequest` per PR #6 review comment #12 — failure is now logged via `log.Printf`; the request is never failed. |
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
