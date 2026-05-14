# ShieldNet 360 Access Platform — Progress Tracker

Status: **In progress | ~97%** — Phases 0, 6–9 shipped; Phases 1–5 backend complete (Admin UI remains); Phase 10 advanced caps shipped for 194 / 200 connectors (6 n/a), audit logs for 198 / 200 (2 n/a), and SSO federation for 104 / 200 (96 n/a — providers without native SSO metadata APIs). Phase 11 hybrid access model in final hardening: kill-switch audit trail, orphan reconciler hardening, grant-expiry notifications + warning sweep, and 14 `SessionRevoker` / 12 `SSOEnforcementChecker` connectors all shipped.

For canonical phase definitions see [`PHASES.md`](PHASES.md). For the design contract see [`PROPOSAL.md`](PROPOSAL.md). For the unified connector view see [`LISTCONNECTORS.md`](LISTCONNECTORS.md).

| Status legend |  |
|---------------|--|
| ✅ shipped | The item is in `main` and exercised in production |
| 🟡 partial | Some criteria met; gaps tracked in §3 |
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
| 1 | Microsoft Entra ID | IAM/SSO | `microsoft/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 2 | Google Workspace | IAM/SSO | `google_workspace/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3 | Okta | IAM/SSO | `okta/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 4 | Auth0 | IAM/SSO | `auth0/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 5 | Generic SAML | IAM/SSO | `generic_saml/` | n/a | n/a | n/a | n/a | ✅ | ✅ |
| 6 | Generic OIDC | IAM/SSO | `generic_oidc/` | n/a | n/a | n/a | n/a | ✅ | ✅ |
| 7 | Duo Security | IAM/MFA | `duo/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 8 | 1Password | Secrets/Vault | `onepassword/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 9 | LastPass | Secrets/Vault | `lastpass/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 10 | Ping Identity | IAM/SSO | `ping_identity/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Tier 2 — Cloud Infrastructure (11–25)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 11 | AWS IAM | Cloud Infra | `aws/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 12 | Azure RBAC | Cloud Infra | `azure/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 13 | GCP IAM | Cloud Infra | `gcp/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 14 | Cloudflare | Cloud Infra | `cloudflare/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 15 | Tailscale | Network | `tailscale/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 16 | DigitalOcean | Cloud Infra | `digitalocean/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 17 | Heroku | Cloud Infra | `heroku/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 18 | Vercel | Cloud Infra | `vercel/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 19 | Netlify | Cloud Infra | `netlify/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 20 | Vultr | Cloud Infra | `vultr/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 21 | Linode | Cloud Infra | `linode/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 22 | OVHcloud | Cloud Infra | `ovhcloud/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 23 | Alibaba Cloud | Cloud Infra | `alibaba/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 24 | CloudSigma | Cloud Infra | `cloudsigma/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 25 | Wasabi | Storage | `wasabi/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |

### Tier 3 — Business SaaS (26–80)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 26 | Slack | Collab | `slack/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 27 | MS Teams | Collab | `ms_teams/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 28 | Zoom | Collab | `zoom/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 29 | Notion | Productivity | `notion/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 30 | Asana | Productivity | `asana/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 31 | Monday.com | Productivity | `monday/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 32 | Figma | Design | `figma/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 33 | Miro | Whiteboard | `miro/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 34 | Trello | Productivity | `trello/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 35 | Airtable | Productivity | `airtable/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 36 | Smartsheet | Productivity | `smartsheet/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 37 | ClickUp | Productivity | `clickup/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 38 | Salesforce | CRM | `salesforce/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 39 | HubSpot | CRM | `hubspot/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 40 | Zoho CRM | CRM | `zoho_crm/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 41 | Pipedrive | CRM | `pipedrive/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 42 | Dropbox Business | Storage | `dropbox/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 43 | Box | Storage | `box/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 44 | Egnyte | Storage | `egnyte/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 45 | GitHub | DevOps | `github/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 46 | GitLab | DevOps | `gitlab/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 47 | Atlassian Jira | DevOps | `jira/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 48 | PagerDuty | DevOps | `pagerduty/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 49 | Sentry | DevOps | `sentry/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 50 | Terraform | DevOps | `terraform/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 51 | Docker Hub | DevOps | `docker_hub/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 52 | JFrog | DevOps | `jfrog/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 53 | SonarCloud | DevOps | `sonarcloud/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 54 | CircleCI | DevOps | `circleci/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 55 | Travis CI | DevOps | `travis_ci/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 56 | LaunchDarkly | DevOps | `launchdarkly/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 57 | Datadog | Observability | `datadog/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 58 | New Relic | Observability | `new_relic/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 59 | Splunk Cloud | Observability | `splunk/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 60 | Grafana | Observability | `grafana/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 61 | Mezmo | Observability | `mezmo/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 62 | Sumo Logic | Observability | `sumo_logic/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 63 | Zendesk | Support | `zendesk/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 64 | Freshdesk | Support | `freshdesk/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 65 | Help Scout | Support | `helpscout/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 66 | Front | Support | `front/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 67 | Intercom | Support | `intercom/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 68 | Drift | Marketing | `drift/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 69 | Crisp | Support | `crisp/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 70 | LiveChat | Support | `livechat/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 71 | Gorgias | Support | `gorgias/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 72 | Loom | Collab | `loom/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 73 | Discord | Collab | `discord/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 74 | Slack Enterprise | Collab | `slack_enterprise/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 75 | Basecamp | Productivity | `basecamp/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 76 | Quip | Productivity | `quip/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 77 | Wrike | Productivity | `wrike/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 78 | Teamwork | Productivity | `teamwork/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 79 | LiquidPlanner | Productivity | `liquidplanner/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 80 | KnowBe4 | Security Training | `knowbe4/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Tier 4 — HR / Finance / Legal (81–130)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 81 | BambooHR | HR | `bamboohr/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 82 | Gusto | HR | `gusto/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 83 | Rippling | HR | `rippling/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 84 | Personio | HR | `personio/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 85 | Hibob | HR | `hibob/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 86 | Workday | HR | `workday/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 87 | Paychex | HR | `paychex/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 88 | Deel | HR | `deel/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 89 | Zenefits | HR | `zenefits/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 90 | Namely | HR | `namely/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 91 | QuickBooks Online | Finance | `quickbooks/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 92 | Xero | Finance | `xero/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 93 | Stripe | Finance | `stripe/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 94 | PayPal | Finance | `paypal/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 95 | Bill.com | Finance | `billdotcom/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 96 | Expensify | Finance | `expensify/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 97 | Sage Intacct | Finance | `sage_intacct/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 98 | FreshBooks | Finance | `freshbooks/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 99 | Wave | Finance | `wave/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 100 | Plaid | Finance | `plaid/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 101 | Brex | Finance | `brex/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 102 | Ramp | Finance | `ramp/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 103 | Clio | Legal | `clio/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 104 | Ironclad | Legal | `ironclad/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 105 | DocuSign | Legal | `docusign/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 106 | DocuSign CLM | Legal | `docusign_clm/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 107 | MyCase | Legal | `mycase/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 108 | PandaDoc | Legal | `pandadoc/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 109 | PandaDoc CLM | Legal | `pandadoc_clm/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 110 | HelloSign | Legal | `hellosign/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 111 | Gong | Sales | `gong/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 112 | Salesloft | Sales | `salesloft/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 113 | Apollo.io | Sales | `apollo/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 114 | Copper | Sales | `copper/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 115 | Insightly | Sales | `insightly/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 116 | Close | Sales | `close/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 117 | Mailchimp | Marketing | `mailchimp/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 118 | Klaviyo | Marketing | `klaviyo/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 119 | ActiveCampaign | Marketing | `activecampaign/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 120 | Constant Contact | Marketing | `constant_contact/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 121 | Braze | Marketing | `braze/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 122 | Mixpanel | Analytics | `mixpanel/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 123 | Segment | CDP | `segment/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 124 | Typeform | Marketing | `typeform/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 125 | SurveyMonkey | Marketing | `surveymonkey/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 126 | Eventbrite | Events | `eventbrite/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 127 | Navan | Travel | `navan/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 128 | SAP Concur | Supply | `sap_concur/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 129 | Coupa | Supply | `coupa/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 130 | Anvyl | Supply | `anvyl/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Tier 5 — Vertical / Niche (131–200)

| # | Provider | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` | Status |
|---|----------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|:------:|
| 131 | Cisco Meraki | Network | `meraki/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 132 | Fortinet | Network | `fortinet/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 133 | Zscaler | Network | `zscaler/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 134 | Check Point | Network | `checkpoint/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 135 | Palo Alto Prisma | Network | `paloalto/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 136 | NordLayer | Network | `nordlayer/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 137 | Perimeter 81 | Network | `perimeter81/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 138 | Netskope | Network | `netskope/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 139 | Sophos Central | Security | `sophos_central/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 140 | Sophos XG | Security | `sophos_xg/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 141 | CrowdStrike | Security | `crowdstrike/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 142 | SentinelOne | Security | `sentinelone/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 143 | Snyk | Security | `snyk/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 144 | HackerOne | Security | `hackerone/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 145 | HIBP | Security | `hibp/` | n/a | n/a | n/a | ✅ | n/a | ✅ |
| 146 | BitSight | Security | `bitsight/` | n/a | n/a | n/a | ✅ | n/a | ✅ |
| 147 | Tenable.io | Security | `tenable/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 148 | Qualys VMDR | Security | `qualys/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 149 | Rapid7 | Security | `rapid7/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 150 | VirusTotal | Security | `virustotal/` | n/a | n/a | n/a | ✅ | n/a | ✅ |
| 151 | Malwarebytes | Security | `malwarebytes/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 152 | ForgeRock | IAM | `forgerock/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 153 | BeyondTrust | IAM/PAM | `beyondtrust/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 154 | Keeper | Secrets/Vault | `keeper/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 155 | Wazuh | SIEM | `wazuh/` | n/a | n/a | n/a | ✅ | n/a | ✅ |
| 156 | OpenAI (ChatGPT) | GenAI | `openai/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 157 | Google Gemini | GenAI | `gemini/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 158 | Anthropic (Claude) | GenAI | `anthropic/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 159 | Perplexity AI | GenAI | `perplexity/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 160 | Mistral AI | GenAI | `mistral/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 161 | Midjourney | GenAI | `midjourney/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 162 | Jasper AI | GenAI | `jasper/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 163 | Copy.ai | GenAI | `copyai/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 164 | Practice Fusion | Health | `practice_fusion/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 165 | Kareo | Health | `kareo/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 166 | Zocdoc | Health | `zocdoc/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 167 | Yardi | Real Estate | `yardi/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 168 | Buildium | Real Estate | `buildium/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 169 | AppFolio | Real Estate | `appfolio/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 170 | NetSuite | ERP | `netsuite/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 171 | Coursera | Education | `coursera/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 172 | LinkedIn Learning | Training | `linkedin_learning/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 173 | Udemy Business | Training | `udemy_business/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 174 | Shopify | E-comm | `shopify/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 175 | WooCommerce | E-comm | `woocommerce/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 176 | BigCommerce | E-comm | `bigcommerce/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 177 | Magento | E-comm | `magento/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 178 | Square | E-comm | `square/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 179 | Recurly | E-comm | `recurly/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 180 | Chargebee | E-comm | `chargebee/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 181 | WordPress | Web | `wordpress/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 182 | Squarespace | Web | `squarespace/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 183 | Wix | Web | `wix/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 184 | Ghost | Web | `ghost/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 185 | SurveySparrow | Customer-Feedback | `surveysparrow/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 186 | Jotform | Customer-Feedback | `jotform/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 187 | Wufoo | Customer-Feedback | `wufoo/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 188 | Hootsuite | Social | `hootsuite/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 189 | Sprout Social | Social | `sprout_social/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 190 | Buffer | Social | `buffer/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 191 | Twilio | Comm | `twilio/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 192 | SendGrid | Comm | `sendgrid/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 193 | RingCentral | Comm | `ringcentral/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 194 | Vonage | Comm | `vonage/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 195 | Zapier | Utility | `zapier/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 196 | Make | Utility | `make/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 197 | IFTTT | Utility | `ifttt/` | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |
| 198 | GA4 | Analytics | `ga4/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 199 | Heap | Analytics | `heap/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 200 | FullStory | Analytics | `fullstory/` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |


---

## 2. Platform feature progress

| Feature | Status | Notes |
|---------|:------:|-------|
| Access connector framework | ✅ | Phase 0. Connector interface, registry, AES-GCM credential encryption, and full connector management API (create / delete / rotate credentials / trigger sync). |
| Connector worker handlers | ✅ | Identity-sync handler with team/member upsert, manager-link resolution, and tombstone-safety threshold; entitlements handler with transactional persistence; AES-GCM credential decryption hook. |
| Real cron jobs | ✅ | Identity-sync scheduler, draft-policy staleness checker, and grant-expiry enforcer all run on configurable intervals. |
| Real SDK HTTP clients | ✅ | Phase 9. iOS `URLSessionAccessSDKClient` (Foundation-only), Android `OkHttpAccessSDKClient` (library-free JSON), Desktop `registerAccessIPC` + `registerAccessRenderer`. Sample iOS SwiftUI and Android Compose apps included. |
| Infrastructure — Docker | ✅ | Multi-stage Dockerfiles per Go service plus a full `docker-compose.yml` stack with real healthchecks. |
| Access request workflow | 🟡 | Phase 2. Tables, state machine, request / provisioning / workflow services, and the full HTTP handler layer shipped. Admin UI still pending. |
| Policy simulation engine | 🟡 | Phase 3. Drafts, impact analysis, conflict detection, promotion, and test-access all shipped. Admin UI simulator still pending. |
| AI risk assessment agent | 🟡 | Phase 4. Go-side A2A client with deterministic fallback wired into request and policy services; LLM-backed Python skill ships with a deterministic stub. Admin UI surface still pending. |
| AI review automation agent | 🟡 | Phase 5. `ReviewAutomator` auto-certifies low-risk grants during campaigns; LLM verdict with deterministic fallback. Admin UI surface still pending. |
| AI setup assistant agent | 🟡 | Phase 4. LLM-backed Python skill with broad secret filtering. Admin UI conversational surface still pending. |
| AI anomaly detection agent | ✅ | Phase 6. `AnomalyDetectionService.ScanWorkspace` plus cross-grant baseline, off-hours, geographic-outlier, and unused-high-privilege detectors. |
| AI policy recommendation agent | 🟡 | Phase 4. `POST /access/explain` and `POST /access/suggest` HTTP handlers backed by the LLM-augmented Python skill. |
| Access review campaigns | 🟡 | Phase 5. Tables, models, services, AI auto-certification, and email / Slack / WebPush notifiers all shipped. Admin UI dashboard still pending. |
| Notification system | 🟡 | Email (SMTP), Slack (webhook), WebPush, and in-memory channels ship with production wiring behind `NOTIFICATION_SMTP_HOST` / `NOTIFICATION_SLACK_WEBHOOK_URL` feature flags. |
| JML automation | ✅ | Phase 6. `JMLService` handles joiner / mover / leaver flows end-to-end, including OpenZiti identity disablement on leaver. |
| Outbound SCIM | ✅ | Phase 6. Generic SCIM v2.0 client with per-connector `SCIMProvisioner` composition across all 10 Tier-1 connectors. |
| Workflow orchestration | ✅ | Phase 8. LangGraph-style engine with linear and DAG runtimes, risk-based routing, escalation, retry / DLQ, durable step state, and four seeded workflow templates (new-hire, contractor, role-change, project-access). |
| Advanced connector capabilities | 🟡 | Phase 10. 194 / 200 connectors ship real `ProvisionAccess` / `RevokeAccess` / `ListEntitlements` (6 are `n/a` — audit-only or SSO-only). Every implementation is idempotent and covered by httptest-mocked happy + failure tests. |
| Access audit pipeline | ✅ | Phase 10. `AccessAuditor` interface plus Kafka producer ship the canonical `ShieldnetLogEvent v1` envelope to the `access_audit_logs` topic. 198 / 200 connectors covered (Generic SAML / Generic OIDC are SSO-only, `n/a`). |
| SSO federation service | 🟡 | Phase 1. `SSOFederationService` brokers SAML / OIDC through Keycloak for 104 / 200 connectors (the realistic ceiling — the rest have no native SSO metadata API). |
| Connector health endpoint | ✅ | Phase 7. `GET /access/connectors/:id/health` returns per-kind last-sync timestamps, credential expiry, and a `stale_audit` flag. Admin UI dashboard consumes this endpoint from `ztna-frontend`. |
| API hardening | ✅ | Per-workspace token-bucket rate limiting (`ZTNA_API_RATE_LIMIT_RPS`), JSON request validation middleware, credential-rotation alerts, batch connector status endpoint, and an audited OpenAPI 3.0 spec. |
| Admin UI surfaces | ⏳ | Phases 1–5 admin surfaces (Connector Marketplace, Access Requests, Policy Simulator, AI Assistant chat, Access Reviews dashboard) live in [`ztna-frontend`](https://github.com/uneycom/ztna-frontend). Backend REST API is final. |
| Hybrid access model (Phase 11) | ✅ | Per-connector `access_mode` (`tunnel` / `sso_only` / `api_only`) with auto-classification at Connect time and `PATCH` override. `PolicyService.Promote` propagates the mode so the ZTNA business layer can skip OpenZiti writes for SaaS-only rows. |
| Unused-app-account reconciler (Phase 11) | ✅ | `OrphanReconciler` cross-references upstream `SyncIdentities` against the IdP pivot, persists rows to `access_orphan_accounts`, and exposes `GET /access/orphans` + revoke / dismiss / acknowledge / reconcile endpoints. Cron runs daily inside `access-connector-worker`. |
| SSO-only enforcement verification (Phase 11) | 🟡 | `SSOEnforcementChecker` capability + 12 implementations (Salesforce, Google Workspace, Okta, Slack, GitHub, Microsoft, Auth0, Ping Identity, Zendesk, BambooHR, Workday, HubSpot). Surfaced through the connector health endpoint. |
| Session revocation (Phase 11) | 🟡 | `SessionRevoker` capability + 14 implementations (Okta, Google Workspace, Microsoft, Salesforce, Slack, Auth0, GitHub, Zoom, Zendesk, HubSpot, Dropbox, Jira/Atlassian, Notion, BambooHR). Invoked from the enhanced leaver flow. |
| Five-layer leaver kill switch (Phase 11) | ✅ | `JMLService.HandleLeaver` now revokes grants → removes memberships → disables Keycloak user → revokes upstream sessions → SCIM-deprovisions → disables OpenZiti identity. All steps best-effort and idempotent. |
| Kill-switch audit trail (Phase 11) | ✅ | Each kill-switch layer (`grant_revoke`, `team_remove`, `keycloak_disable`, `session_revoke`, `scim_deprovision`, `openziti_disable`) emits a `LeaverKillSwitchEvent` onto the same `ShieldnetLogEvent v1` Kafka envelope used by the audit pipeline. Wired via `JMLService.SetAuditProducer`. |
| Unused-app-account reconciler hardening (Phase 11) | ✅ | `OrphanReconciler` exposes a `DryRun` mode (`POST /access/orphans/reconcile` with `"dry_run": true`), a configurable per-connector throttle (`ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR`, default 1s), and structured `orphan_reconcile_summary` JSON log lines from `OrphanReconcilerScheduler` so operators can ingest stats per workspace. |
| Automatic grant expiry enforcement (Phase 11) | ✅ | `GrantExpiryEnforcer` cron ticks every `ACCESS_GRANT_EXPIRY_CHECK_INTERVAL` (default 1h) and replays the Phase 5 revoke path for every expired grant. |
| Grant expiry notifications + warning sweep (Phase 11) | ✅ | After each auto-revoke the enforcer fires `SendGrantRevokedNotification`; a separate `RunWarning` sweep emits `SendGrantExpiryWarning` for grants expiring within `ACCESS_GRANT_EXPIRY_WARNING_HOURS` (default 24h). Per-grant `GrantExpiryEvent` audit events are emitted via the same `AuditProducer` for both flows. |

---

## 3. Open work items

These are the genuinely open items. Everything else is in §4 changelog.

### 3.1 Admin UI surfaces (Phases 1–5)

- **Why.** Backend services and HTTP routes are in place; end-user surfaces still need React implementations in [`ztna-frontend`](https://github.com/uneycom/ztna-frontend).
- **Scope.** Five surfaces — Connector Marketplace (Phase 1), Access Requests (Phase 2), Policy Simulator with before/after diff (Phase 3), AI Assistant chat (Phase 4), Access Reviews dashboard (Phase 5).
- **Out of scope.** Any backend changes — the REST API is final.

### 3.2 Access review campaigns Admin UI

- **What's done.** Tables, models, `AccessReviewService`, AI auto-certification, scheduled campaigns with skip dates, all notification channels (email / Slack / WebPush), and production wiring behind feature flags.
- **What's open.** The Admin UI campaign dashboard with bulk approve / revoke and per-grant detail.

### 3.3 Phase 10 SSO federation

- **What's done.** `SSOFederationService` plus the `SSOMetadataFromConfig` operator-supplied metadata helper covers **104 / 200** connectors — every provider that exposes a native SAML or OIDC metadata endpoint.
- **What's open.** The remaining 96 connectors have no native SSO metadata API (e.g. Zoom, niche / vertical SaaS, audit-only providers) and return `ErrSSOFederationUnsupported`. This is the realistic ceiling; no further wires planned.

---

## 4. Recently shipped (changelog)

Newest first. Each entry is a 1–2 sentence summary; PR links carry the detail.

| Date | What | PR |
|------|------|----|
| 2026-05-14 | Phase 11 batch 6 — Hybrid Access Model hardening: 7 new `SessionRevoker` connectors (Zoom, Zendesk, HubSpot, Dropbox, Jira/Atlassian, Notion, BambooHR), 6 new `SSOEnforcementChecker` connectors (Auth0, Ping Identity, Zendesk, BambooHR, Workday, HubSpot), kill-switch audit trail emission, orphan reconciler dry-run + per-connector throttle + structured stats logging, grant-expiry notifications + warning sweep + audit events, plus full docs sync. | this PR |
| 2026-05-14 | Phase 11 — Hybrid Access Model: per-connector access_mode classification, unused-app-account reconciler, SSO-only enforcement verification, session revocation across top-7 connectors, five-layer leaver kill switch, automatic grant-expiry enforcement, plus full docs sync. | #77 |
| 2026-05-14 | API hardening + connector enhancements: rate limiting, request validation, credential rotation alerts, `GroupSyncer` for top-5 connectors, delta-sync hardening, health webhooks, batch status endpoint, OpenAPI audit. | #76 |
| 2026-05-14 | SDK publishing manifests + per-platform integration guides; Phase 9 closes at ✅ shipped. | #75 |
| 2026-05-14 | Post-PR-#67 documentation audit — promote audit-only Tier-5 connectors to ✅ and update overall progress. | #74 |
| 2026-05-13 | Real-implementation sprint — Connector Management API, real worker handler upgrades, three real cron jobs, real SDK HTTP clients, real integration tests, real Dockerfiles + docker-compose. | #67 |
| 2026-05-13 | Post-development documentation audit, README status block cleanup. | #65 |
| 2026-05-13 | Phase 4 SDK AI query satisfaction; Phase 6 promotion to ✅ shipped. | #65 |
| 2026-05-13 | Phase 2 SDK & extension API contracts; cross-cutting on-device-model CI guard. | #64 |
| 2026-05-12 | Phase 10 SSO federation batches 27–35 — closed at 185 wired brokers, the realistic ceiling. | #55–#63 |
| 2026-05-12 | Phase 10 Tier-5 advanced-capability sweep — 196 / 50 advanced caps closed via stub-tier expansion. | #51 |
| 2026-05-12 | Phase 10 audit-log sweep — closed at 200 / 200 connectors. | #40 |
| 2026-05-12 | Phase 10 advanced-capability top-50 closure — 50 / 50 done across five batches; final batch wired Rapid7 InsightVM. | #29 |
| 2026-05-11 | CP7 integration & API hardening — CI workflows, three new read endpoints, swagger regeneration, README CI badges. | #30 |
| 2026-05-11 | Phase 10 audit-log batch (10 connectors) + SSO federation batch + connector health endpoint + audit-pipeline integration tests. | #27 |
| 2026-05-11 | Phase 10 close-out for top-10 audit logging + Kafka audit pipeline + SSO federation. | #25 |
| 2026-05-10 | Phase 10 advanced-capability batches 1–4. | #21–#24 |
| 2026-05-10 | Phase 8 completion + Phase 5/6 wire-ins + AI agent LLM backing. | #20 |
| 2026-05-10 | Phase 7 closeout (200 / 200) + Phase 8 Workflow Orchestration scaffold. | #19 |
| 2026-05-10 | Phase 7 expansions — Tier 4 and Tier 5 batches close the catalogue. | #14–#18 |
| 2026-05-10 | Phase 7 Cloud Infrastructure and Collaboration / Productivity / DevOps batches. | #9–#13 |
| 2026-05-09 | Phase 3–6 backend completion: auto-cert wire-in, notifications, SCIM composition, cron jobs, sync state, access jobs, credential checker. | #8 |
| 2026-05-09 | Phase 4–6 — Python A2A skill server, JML, inbound/outbound SCIM v2.0, anomaly stub, notification scaffold. | #7 |
| 2026-05-09 | Phase 2–5 — HTTP handler layer, AI A2A client, Phase 5 scheduled campaigns. | #6 |
| 2026-05-09 | Phase 3 + Phase 5 — policy simulation engine, access review campaigns (backend). | #5 |
| 2026-05-09 | Phase 2 — access request tables, state machine, request / provisioning / workflow services. | #4 |
| 2026-05-09 | Phase 1 — remaining 7 Tier-1 connectors. | #3 |
| 2026-05-09 | Phase 0 — contract, registry, credential manager, migration. | #2 |

---

## 5. Known regressions / debt

Use this section sparingly. If something belongs here for more than two sprints, promote it to §3.

| Area | Problem | Tracking |
|------|---------|----------|
| Documentation drift | Per-cell tables in §1 and the statistics in [`LISTCONNECTORS.md`](LISTCONNECTORS.md) can lag reality after large batches land. Mitigated by CI drift checks (swagger, SN360 language) and the `scripts/sync_listconnectors.py` helper. | (closed) |

---

## 6. How to update this file

1. When you start a phase item: leave `PROGRESS.md` alone; just open the PR.
2. When you ship: flip the row in §1 / §2 to ✅ (or 🟡 with notes), move the matching item from §3 → §4, and add the PR link.
3. When you discover a regression: add it to §5 with concrete acceptance for closing it.
4. Keep tone factual — this file is read by operators and reviewers, not customers.
