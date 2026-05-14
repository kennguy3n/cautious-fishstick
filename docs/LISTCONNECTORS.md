# Connector Capability Index

> **Last updated:** 2026-05-14
> **Source of truth:** [`docs/PROGRESS.md`](./PROGRESS.md) §1 — when a capability flips in PROGRESS.md, mirror the change here.

## Legend

| Marker | Meaning |
|--------|---------|
| ✅ | Shipped — integration in place, covered by tests |
| 🟡 | Partial — only some of the capability is shipped |
| ⏳ | Planned — not yet implemented |
| n/a | Capability does not apply to this provider |

## Capability columns

- `sync_identity` — pull users / groups / memberships into ZTNA Teams.
- `provision_access` — push grants out to the provider.
- `list_entitlements` — pull current permissions for an access check-up.
- `get_access_log` — pull sign-in / permission-change audit events into the audit pipeline.
- `sso_federation` — broker SAML / OIDC through Keycloak.

## All 200 connectors

| # | Provider | Tier | Category | Path | `sync_identity` | `provision_access` | `list_entitlements` | `get_access_log` | `sso_federation` |
|---|----------|------|----------|------|:---------------:|:------------------:|:-------------------:|:----------------:|:----------------:|
| 1 | Microsoft Entra ID | T1 | IAM/SSO | `microsoft/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 2 | Google Workspace | T1 | IAM/SSO | `google_workspace/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3 | Okta | T1 | IAM/SSO | `okta/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 4 | Auth0 | T1 | IAM/SSO | `auth0/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 5 | Generic SAML | T1 | IAM/SSO | `generic_saml/` | n/a | n/a | n/a | n/a | ✅ |
| 6 | Generic OIDC | T1 | IAM/SSO | `generic_oidc/` | n/a | n/a | n/a | n/a | ✅ |
| 7 | Duo Security | T1 | IAM/MFA | `duo/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 8 | 1Password | T1 | Secrets/Vault | `onepassword/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 9 | LastPass | T1 | Secrets/Vault | `lastpass/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 10 | Ping Identity | T1 | IAM/SSO | `ping_identity/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 11 | AWS IAM | T2 | Cloud Infra | `aws/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 12 | Azure RBAC | T2 | Cloud Infra | `azure/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 13 | GCP IAM | T2 | Cloud Infra | `gcp/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 14 | Cloudflare | T2 | Cloud Infra | `cloudflare/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 15 | Tailscale | T2 | Network | `tailscale/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 16 | DigitalOcean | T2 | Cloud Infra | `digitalocean/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 17 | Heroku | T2 | Cloud Infra | `heroku/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 18 | Vercel | T2 | Cloud Infra | `vercel/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 19 | Netlify | T2 | Cloud Infra | `netlify/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 20 | Vultr | T2 | Cloud Infra | `vultr/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 21 | Linode | T2 | Cloud Infra | `linode/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 22 | OVHcloud | T2 | Cloud Infra | `ovhcloud/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 23 | Alibaba Cloud | T2 | Cloud Infra | `alibaba/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 24 | CloudSigma | T2 | Cloud Infra | `cloudsigma/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 25 | Wasabi | T2 | Storage | `wasabi/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 26 | Slack | T3 | Collab | `slack/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 27 | MS Teams | T3 | Collab | `ms_teams/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 28 | Zoom | T3 | Collab | `zoom/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 29 | Notion | T3 | Productivity | `notion/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 30 | Asana | T3 | Productivity | `asana/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 31 | Monday.com | T3 | Productivity | `monday/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 32 | Figma | T3 | Design | `figma/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 33 | Miro | T3 | Whiteboard | `miro/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 34 | Trello | T3 | Productivity | `trello/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 35 | Airtable | T3 | Productivity | `airtable/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 36 | Smartsheet | T3 | Productivity | `smartsheet/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 37 | ClickUp | T3 | Productivity | `clickup/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 38 | Salesforce | T3 | CRM | `salesforce/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 39 | HubSpot | T3 | CRM | `hubspot/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 40 | Zoho CRM | T3 | CRM | `zoho_crm/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 41 | Pipedrive | T3 | CRM | `pipedrive/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 42 | Dropbox Business | T3 | Storage | `dropbox/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 43 | Box | T3 | Storage | `box/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 44 | Egnyte | T3 | Storage | `egnyte/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 45 | GitHub | T3 | DevOps | `github/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 46 | GitLab | T3 | DevOps | `gitlab/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 47 | Atlassian Jira | T3 | DevOps | `jira/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 48 | PagerDuty | T3 | DevOps | `pagerduty/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 49 | Sentry | T3 | DevOps | `sentry/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 50 | Terraform | T3 | DevOps | `terraform/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 51 | Docker Hub | T3 | DevOps | `docker_hub/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 52 | JFrog | T3 | DevOps | `jfrog/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 53 | SonarCloud | T3 | DevOps | `sonarcloud/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 54 | CircleCI | T3 | DevOps | `circleci/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 55 | Travis CI | T3 | DevOps | `travis_ci/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 56 | LaunchDarkly | T3 | DevOps | `launchdarkly/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 57 | Datadog | T3 | Observability | `datadog/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 58 | New Relic | T3 | Observability | `new_relic/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 59 | Splunk Cloud | T3 | Observability | `splunk/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 60 | Grafana | T3 | Observability | `grafana/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 61 | Mezmo | T3 | Observability | `mezmo/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 62 | Sumo Logic | T3 | Observability | `sumo_logic/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 63 | Zendesk | T3 | Support | `zendesk/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 64 | Freshdesk | T3 | Support | `freshdesk/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 65 | Help Scout | T3 | Support | `helpscout/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 66 | Front | T3 | Support | `front/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 67 | Intercom | T3 | Support | `intercom/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 68 | Drift | T3 | Marketing | `drift/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 69 | Crisp | T3 | Support | `crisp/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 70 | LiveChat | T3 | Support | `livechat/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 71 | Gorgias | T3 | Support | `gorgias/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 72 | Loom | T3 | Collab | `loom/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 73 | Discord | T3 | Collab | `discord/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 74 | Slack Enterprise | T3 | Collab | `slack_enterprise/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 75 | Basecamp | T3 | Productivity | `basecamp/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 76 | Quip | T3 | Productivity | `quip/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 77 | Wrike | T3 | Productivity | `wrike/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 78 | Teamwork | T3 | Productivity | `teamwork/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 79 | LiquidPlanner | T3 | Productivity | `liquidplanner/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 80 | KnowBe4 | T3 | Security Training | `knowbe4/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 81 | BambooHR | T4 | HR | `bamboohr/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 82 | Gusto | T4 | HR | `gusto/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 83 | Rippling | T4 | HR | `rippling/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 84 | Personio | T4 | HR | `personio/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 85 | Hibob | T4 | HR | `hibob/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 86 | Workday | T4 | HR | `workday/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 87 | Paychex | T4 | HR | `paychex/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 88 | Deel | T4 | HR | `deel/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 89 | Zenefits | T4 | HR | `zenefits/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 90 | Namely | T4 | HR | `namely/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 91 | QuickBooks Online | T4 | Finance | `quickbooks/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 92 | Xero | T4 | Finance | `xero/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 93 | Stripe | T4 | Finance | `stripe/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 94 | PayPal | T4 | Finance | `paypal/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 95 | Bill.com | T4 | Finance | `billdotcom/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 96 | Expensify | T4 | Finance | `expensify/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 97 | Sage Intacct | T4 | Finance | `sage_intacct/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 98 | FreshBooks | T4 | Finance | `freshbooks/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 99 | Wave | T4 | Finance | `wave/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 100 | Plaid | T4 | Finance | `plaid/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 101 | Brex | T4 | Finance | `brex/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 102 | Ramp | T4 | Finance | `ramp/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 103 | Clio | T4 | Legal | `clio/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 104 | Ironclad | T4 | Legal | `ironclad/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 105 | DocuSign | T4 | Legal | `docusign/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 106 | DocuSign CLM | T4 | Legal | `docusign_clm/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 107 | MyCase | T4 | Legal | `mycase/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 108 | PandaDoc | T4 | Legal | `pandadoc/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 109 | PandaDoc CLM | T4 | Legal | `pandadoc_clm/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 110 | HelloSign | T4 | Legal | `hellosign/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 111 | Gong | T4 | Sales | `gong/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 112 | Salesloft | T4 | Sales | `salesloft/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 113 | Apollo.io | T4 | Sales | `apollo/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 114 | Copper | T4 | Sales | `copper/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 115 | Insightly | T4 | Sales | `insightly/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 116 | Close | T4 | Sales | `close/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 117 | Mailchimp | T4 | Marketing | `mailchimp/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 118 | Klaviyo | T4 | Marketing | `klaviyo/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 119 | ActiveCampaign | T4 | Marketing | `activecampaign/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 120 | Constant Contact | T4 | Marketing | `constant_contact/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 121 | Braze | T4 | Marketing | `braze/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 122 | Mixpanel | T4 | Analytics | `mixpanel/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 123 | Segment | T4 | CDP | `segment/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 124 | Typeform | T4 | Marketing | `typeform/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 125 | SurveyMonkey | T4 | Marketing | `surveymonkey/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 126 | Eventbrite | T4 | Events | `eventbrite/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 127 | Navan | T4 | Travel | `navan/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 128 | SAP Concur | T4 | Supply | `sap_concur/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 129 | Coupa | T4 | Supply | `coupa/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 130 | Anvyl | T4 | Supply | `anvyl/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 131 | Cisco Meraki | T5 | Network | `meraki/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 132 | Fortinet | T5 | Network | `fortinet/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 133 | Zscaler | T5 | Network | `zscaler/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 134 | Check Point | T5 | Network | `checkpoint/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 135 | Palo Alto Prisma | T5 | Network | `paloalto/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 136 | NordLayer | T5 | Network | `nordlayer/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 137 | Perimeter 81 | T5 | Network | `perimeter81/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 138 | Netskope | T5 | Network | `netskope/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 139 | Sophos Central | T5 | Security | `sophos_central/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 140 | Sophos XG | T5 | Security | `sophos_xg/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 141 | CrowdStrike | T5 | Security | `crowdstrike/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 142 | SentinelOne | T5 | Security | `sentinelone/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 143 | Snyk | T5 | Security | `snyk/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 144 | HackerOne | T5 | Security | `hackerone/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 145 | HIBP | T5 | Security | `hibp/` | n/a | n/a | n/a | ✅ | n/a |
| 146 | BitSight | T5 | Security | `bitsight/` | n/a | n/a | n/a | ✅ | n/a |
| 147 | Tenable.io | T5 | Security | `tenable/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 148 | Qualys VMDR | T5 | Security | `qualys/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 149 | Rapid7 | T5 | Security | `rapid7/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 150 | VirusTotal | T5 | Security | `virustotal/` | n/a | n/a | n/a | ✅ | n/a |
| 151 | Malwarebytes | T5 | Security | `malwarebytes/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 152 | ForgeRock | T5 | IAM | `forgerock/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 153 | BeyondTrust | T5 | IAM/PAM | `beyondtrust/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 154 | Keeper | T5 | Secrets/Vault | `keeper/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 155 | Wazuh | T5 | SIEM | `wazuh/` | n/a | n/a | n/a | ✅ | n/a |
| 156 | OpenAI (ChatGPT) | T5 | GenAI | `openai/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 157 | Google Gemini | T5 | GenAI | `gemini/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 158 | Anthropic (Claude) | T5 | GenAI | `anthropic/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 159 | Perplexity AI | T5 | GenAI | `perplexity/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 160 | Mistral AI | T5 | GenAI | `mistral/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 161 | Midjourney | T5 | GenAI | `midjourney/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 162 | Jasper AI | T5 | GenAI | `jasper/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 163 | Copy.ai | T5 | GenAI | `copyai/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 164 | Practice Fusion | T5 | Health | `practice_fusion/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 165 | Kareo | T5 | Health | `kareo/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 166 | Zocdoc | T5 | Health | `zocdoc/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 167 | Yardi | T5 | Real Estate | `yardi/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 168 | Buildium | T5 | Real Estate | `buildium/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 169 | AppFolio | T5 | Real Estate | `appfolio/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 170 | NetSuite | T5 | ERP | `netsuite/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 171 | Coursera | T5 | Education | `coursera/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 172 | LinkedIn Learning | T5 | Training | `linkedin_learning/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 173 | Udemy Business | T5 | Training | `udemy_business/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 174 | Shopify | T5 | E-comm | `shopify/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 175 | WooCommerce | T5 | E-comm | `woocommerce/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 176 | BigCommerce | T5 | E-comm | `bigcommerce/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 177 | Magento | T5 | E-comm | `magento/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 178 | Square | T5 | E-comm | `square/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 179 | Recurly | T5 | E-comm | `recurly/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 180 | Chargebee | T5 | E-comm | `chargebee/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 181 | WordPress | T5 | Web | `wordpress/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 182 | Squarespace | T5 | Web | `squarespace/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 183 | Wix | T5 | Web | `wix/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 184 | Ghost | T5 | Web | `ghost/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 185 | SurveySparrow | T5 | Customer-Feedback | `surveysparrow/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 186 | Jotform | T5 | Customer-Feedback | `jotform/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 187 | Wufoo | T5 | Customer-Feedback | `wufoo/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 188 | Hootsuite | T5 | Social | `hootsuite/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 189 | Sprout Social | T5 | Social | `sprout_social/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 190 | Buffer | T5 | Social | `buffer/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 191 | Twilio | T5 | Comm | `twilio/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 192 | SendGrid | T5 | Comm | `sendgrid/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 193 | RingCentral | T5 | Comm | `ringcentral/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 194 | Vonage | T5 | Comm | `vonage/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 195 | Zapier | T5 | Utility | `zapier/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 196 | Make | T5 | Utility | `make/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 197 | IFTTT | T5 | Utility | `ifttt/` | ✅ | ✅ | ✅ | ✅ | n/a |
| 198 | GA4 | T5 | Analytics | `ga4/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 199 | Heap | T5 | Analytics | `heap/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 200 | FullStory | T5 | Analytics | `fullstory/` | ✅ | ✅ | ✅ | ✅ | ✅ |

## Summary statistics

| Capability | Shipped (✅) | Not applicable (n/a) | Effective coverage |
|------------|:-----------:|:--------------------:|:------------------:|
| `sync_identity` | 194 | 6 | 200 / 200 |
| `provision_access` | 194 | 6 | 200 / 200 |
| `list_entitlements` | 194 | 6 | 200 / 200 |
| `get_access_log` | 198 | 2 | 200 / 200 |
| `sso_federation` | 104 | 96 | 200 / 200 |

`n/a` entries reflect providers where the capability does not exist by design (Generic SAML / Generic OIDC have no identity API; HIBP, BitSight, VirusTotal, Wazuh are audit-only; many niche providers have no native SSO metadata endpoint). The effective coverage column reflects connectors where the capability is either shipped or doesn't apply.

For the per-feature platform status table see [`PROGRESS.md`](./PROGRESS.md) §2. For phase-level milestones see [`PHASES.md`](./PHASES.md).
