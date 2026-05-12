# ShieldNet 360 Access Platform

[![CI](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/ci.yml) [![Python CI](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/python-ci.yml/badge.svg)](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/python-ci.yml)

> **Status:** Phase 0 shipped; Phase 7 ✅ shipped (200 / 200 connectors); Phase 8 ✅ shipped end-to-end including LangGraph DAG runtime (`WorkflowStepDefinition.Next` / `Join` + `executeDAG` topological walk with goroutine-parallel branches, Kahn cycle / out-of-range / self-loop validation, per-branch outcomes recorded in `access_workflow_step_history`); Phase 10 advanced capabilities **118 / 50 ✅** done across sixteen batches (batch 15: 11 Tier-2 Cloud Infrastructure connectors with provider-native role / team / policy / ACL APIs; batch 16: 6 Tier-4 SaaS connectors — Stripe Connect capabilities, Copper users, Insightly Permissions, Close role_assignment, Mailchimp list members, Klaviyo list profiles) (50/50 top-50 closed; batch 6 PR #32 adds Zoho CRM / Pipedrive / Terraform Cloud / Docker Hub / JFrog / LaunchDarkly beyond the top-50; batch 7 adds Travis CI / Mezmo / Drift), Phase 10 audit-log capability **200 / 200 ✅** (50/50 of top-50 connector audit-log target ✅ + batch-5 expansion to 10 Tier-2/3/4/5 connectors via PR #31 + batch-6 expansion PR #32 to 10 Tier-2 / Tier-3 connectors: Terraform Cloud, Docker Hub, JFrog, LaunchDarkly, New Relic, Splunk Cloud, Heroku, SonarCloud, CircleCI, Pipedrive + batch-7 expansion to 10 Tier-2 Cloud Infrastructure connectors: Tailscale, DigitalOcean, Vercel, Netlify, Vultr, Linode, OVHcloud, Alibaba Cloud, CloudSigma, Wasabi) via new `AccessAuditor` interface + Kafka `access_audit_logs` pipeline (partition-keyed cursors, legacy bare-RFC3339 cursor migration, integration-tested in `internal/workers/handlers/access_audit_integration_test.go`); **Phase 7 connector-health backend** `GET /access/connectors/:id/health` ships in PR #29 (joins `access_connectors` + `access_sync_state`, returns per-kind last-sync, credential-expiry, and a `stale_audit` flag at the 24h threshold); Phase 1 SSO federation exit criterion ✅ via Keycloak broker (PR #21: Microsoft, Google Workspace, Okta, Auth0, Duo, 1Password, LastPass, Ping Identity, AWS, Azure, GCP — 11; PR #22: Slack, GitHub, GitLab, Jira, Salesforce, Cloudflare, Zoom, PagerDuty, Sentry, Datadog, Zendesk, HubSpot, Dropbox, CrowdStrike, Snyk, Notion — 16; PR #23: MS Teams, BambooHR — 2; PR #24: Asana, Monday.com, Figma, Miro, Trello, Airtable, Smartsheet, ClickUp, Box, Egnyte, Freshdesk, Help Scout, Front, Intercom, SentinelOne, Workday, NetSuite, QuickBooks Online, DocuSign, Tenable — 20; PR #31: AWS IAM SAML, Azure Entra OIDC / SAML, GCP Workforce Pool OIDC — 3; **PR #32 batch 5: SAP Concur SAML, Coupa SAML, LinkedIn Learning SAML, Udemy Business SAML, RingCentral OIDC — 5 via new `access.SSOMetadataFromConfig` helper; batch 6: HubSpot SAML, Notion SAML, Box SAML, PagerDuty SAML, Sentry SAML — 5 more via the same helper, bringing 35 wired SSO brokers; batch 8: JFrog SAML, LaunchDarkly SAML, New Relic SAML, Splunk Cloud SAML, Sumo Logic SAML — 5 more, bringing 40 wired SSO brokers; batch 9 (PR #35): Datadog SAML, Freshdesk SAML, Front SAML, Asana SAML, Monday.com SAML — 5 more, bringing 45 wired SSO brokers; batch 10 (PR #36): Figma SAML, Miro SAML, Airtable SAML, Smartsheet SAML, ClickUp SAML — 5 more, bringing 50 wired SSO brokers; batch 11 (PR #37): Zoho CRM SAML, Egnyte SAML, KnowBe4 SAML, Docker Hub SAML, Terraform Cloud SAML — 5 more, bringing 55 wired SSO brokers; batch 12 (PR #38): Crisp SAML, Shopify SAML, NetSuite SAML, Coursera SAML — 4 net new (Slack Enterprise SAML already wired in batch 9), bringing 60 wired SSO brokers; batch 13 (PR #39): DocuSign SAML, DocuSign CLM SAML, Google Gemini OIDC, Gusto SAML, Hibob SAML — 5 net new, bringing 65 wired SSO brokers; **batch 14 (PR #40): Hootsuite SAML, Sprout Social SAML, Buffer SAML, Magento SAML, Square SAML — 5 net new, bringing 70 wired SSO brokers; **batch 16 (this PR): Twilio SAML, Sendgrid SAML, Vonage SAML, Shopify SAML (re-verified), WordPress SAML — 5 net new, bringing 75 wired SSO brokers**), plus PR #23 wires the Phase 5 EmailNotifier + SlackNotifier into `cmd/access-workflow-engine/main.go` behind the `NOTIFICATION_SMTP_HOST` / `NOTIFICATION_SLACK_WEBHOOK_URL` env-var feature flags and adds the `branch_index` column on `access_workflow_step_history`; Phases 1–6 partial. **All 200 / 200 connectors are in `main`** (Tier 1 10/10, Tier 2 25/25, Tier 3 55/55, Tier 4 50/50, Tier 5 70/70 — the final 17 Tier-5 providers Ghost, SurveySparrow, Jotform, Wufoo, Hootsuite, Sprout Social, Buffer, Twilio, SendGrid, RingCentral, Vonage, Zapier, Make, IFTTT, GA4, Heap, FullStory closed out in PR #19). **Phase 8** brings the workflow engine online: `cmd/access-workflow-engine` is now a real HTTP host (`GET /health`, `POST /workflows/execute` on `:8082`) backed by a `WorkflowExecutor` (step types `auto_approve`, `manager_approval`, `security_review`, `multi_level`), a `RiskRouter` (low → self_service / auto_approve, medium → manager_approval, high or `sensitive_resource` tag → security_review) wired into `WorkflowService.ResolveWorkflowWithRisk`, an `EscalationChecker` cron that emits `Escalator.Escalate(from, to)` calls when an approval step's `timeout_hours` has elapsed, plus the PR #20 closeout (`RealStepPerformer`, `NotifyingEscalator`, default workflow templates seeded via migration `008`, durable step state in `access_workflow_step_history` migration `009`, and `RetryPolicy` exponential backoff). **AI agent skills** (`access_risk_assessment`, `access_review_automation`, `access_anomaly_detection`, `policy_recommendation`, `connector_setup_assistant`) are LLM-backed via the shared `skills.llm` dispatcher with deterministic-stub fallback (PR #20). The `AccessConnector` contract, process-global registry, AES-GCM credential manager, `access_connectors` migration, and **all 10 Tier 1 connectors** are in `main`. **Phase 2** lands the request-lifecycle tables, the request state machine, and the request / provisioning / workflow services PLUS the HTTP handler layer for access requests and grants. **Phase 3** lands the `policies` / `teams` / `team_members` / `resources` tables, `PolicyService`, `ImpactResolver`, `ConflictDetector` PLUS the HTTP handler layer for policy drafts, simulate, promote, and test-access. **Phase 4 (partial)** lands the Go-side A2A AI client (`internal/pkg/aiclient`), env-driven access platform config (`internal/config`), AI risk-scoring integration in `AccessRequestService.CreateRequest` and `PolicyService.Simulate`, and `POST /access/explain` + `POST /access/suggest` endpoints — and the Python AI agent itself (`cmd/access-ai-agent/`) now ships with stub skills for `access_risk_assessment`, `access_review_automation`, `access_anomaly_detection`, `connector_setup_assistant`, and `policy_recommendation`. **Phase 5** lands the `access_reviews` / `access_review_decisions` / `access_campaign_schedules` tables, `AccessReviewService`, the Phase 5 HTTP handler layer, the `internal/cron.CampaignScheduler` driving recurring campaigns, AND now the auto-certification rate metric (`GET /access/reviews/:id/metrics`), the admin `PATCH /access/reviews/:id` toggle for `auto_certify_enabled`, and the notification-fan-out scaffold (`internal/services/notification`, `Notifier` interface, in-memory channel) wired into `StartCampaign`. **Phase 6 (partial)** lands the JML service (`internal/services/access.JMLService` with `ClassifyChange` / `HandleJoiner` / `HandleMover` / `HandleLeaver`), the SCIM inbound handler (`POST /scim/Users`, `PATCH /scim/Users/:id`, `DELETE /scim/Users/:id`), the outbound SCIM v2.0 client (`SCIMClient.PushSCIMUser` / `PushSCIMGroup` / `DeleteSCIMResource`), and the Go-side anomaly detection stub (`AnomalyDetectionService.ScanWorkspace` + `DetectAnomaliesWithFallback`). All 10 Tier-1 connectors now compose the generic outbound `SCIMClient` (Microsoft Entra, Google Workspace, Okta, Auth0, Duo, 1Password, LastPass, Ping Identity, plus the SAML / OIDC brokers). **Phase 7 (partial)** lands the full Cloud Infrastructure tier (15/15: `aws/`, `azure/`, `gcp/`, `cloudflare/`, `tailscale/`, `digitalocean/`, `heroku/`, `vercel/`, `netlify/`, `vultr/`, `linode/`, `ovhcloud/`, `alibaba/`, `cloudsigma/`, `wasabi/`), all 10 Collaboration connectors (`slack/`, `ms_teams/`, `zoom/`, `notion/`, `asana/`, `monday/`, `figma/`, `miro/`, `trello/`, `airtable/`), 4 SaaS Productivity / Storage connectors (`smartsheet/`, `clickup/`, `dropbox/`, `box/`), all 4 CRM connectors (`salesforce/`, `hubspot/`, `zoho_crm/`, `pipedrive/`), all 5 DevOps connectors (`github/`, `gitlab/`, `jira/`, `pagerduty/`, `sentry/`), all 3 Support connectors (`zendesk/`, `freshdesk/`, `helpscout/`), the first 3 Security / Vertical connectors (`crowdstrike/`, `sentinelone/`, `snyk/`), all 6 HR connectors (`bamboohr/`, `gusto/`, `rippling/`, `personio/`, `hibob/`, `workday/`), and 4 Finance connectors (`quickbooks/`, `xero/`, `stripe/`, `freshbooks/`); the Phase 7 expansion now also adds 1 Storage connector (`egnyte/`), 7 DevOps connectors (`terraform/`, `docker_hub/`, `jfrog/`, `sonarcloud/`, `circleci/`, `launchdarkly/`, `travis_ci/`), 6 Observability connectors (`datadog/`, `new_relic/`, `splunk/`, `grafana/`, `mezmo/`, `sumo_logic/`), 5 Support connectors (`front/`, `intercom/`, `crisp/`, `livechat/`, `gorgias/`), 1 Marketing/Support connector (`drift/`), 3 Collab connectors (`loom/`, `discord/`, `slack_enterprise/`), 5 Productivity connectors (`basecamp/`, `quip/`, `wrike/`, `teamwork/`, `liquidplanner/`), 1 Security Training connector (`knowbe4/`), 4 HR connectors (`paychex/`, `deel/`, `zenefits/`, `namely/`), 2 Finance connectors (`paypal/`, `wave/`), 2 Sales connectors (`gong/`, `salesloft/`), and 2 Marketing connectors (`mailchimp/`, `klaviyo/`); each ships pure-local `Validate`, `Connect`, paginated `SyncIdentities` (internal pagination exhaustion), `CountIdentities`, and `GetCredentialsMetadata` with token redaction. The Phase 7 batch B (PR #15) adds 20 Tier-4 connectors across Sales / Marketing / Finance / Supply / Travel: `apollo/`, `copper/`, `insightly/`, `close/`, `activecampaign/`, `constant_contact/`, `braze/`, `mixpanel/`, `segment/`, `typeform/`, `surveymonkey/`, `eventbrite/`, `navan/`, `sap_concur/`, `coupa/`, `anvyl/`, `billdotcom/`, `expensify/`, `sage_intacct/`, `plaid/`. The Phase 7 Tier-4 closeout + first Tier-5 Network Security batch (PR #16) adds 20 more connectors: 10 Tier-4 (`brex/`, `ramp/`, `clio/`, `ironclad/`, `docusign/`, `docusign_clm/`, `mycase/`, `pandadoc/`, `pandadoc_clm/`, `hellosign/`) closing Tier 4 at 50/50, and the first 10 Tier-5 Network Security connectors (`meraki/`, `fortinet/`, `zscaler/`, `checkpoint/`, `paloalto/`, `nordlayer/`, `perimeter81/`, `netskope/`, `sophos_central/`, `sophos_xg/`) bringing Tier 5 to 13/70. The Phase 7 Tier-5 Security / IAM / GenAI batch (PR #17) adds another 20 Tier-5 connectors (`hackerone/`, `hibp/`, `bitsight/`, `tenable/`, `qualys/`, `rapid7/`, `virustotal/`, `malwarebytes/`, `forgerock/`, `beyondtrust/`, `keeper/`, `wazuh/`, `openai/`, `gemini/`, `anthropic/`, `perplexity/`, `mistral/`, `midjourney/`, `jasper/`, `copyai/`) bringing Tier 5 to 33/70. The Phase 7 Tier-5 Health / Real Estate / ERP / Education / E-commerce / Web batch (PR #18) adds 20 more Tier-5 connectors (`practice_fusion/`, `kareo/`, `zocdoc/`, `yardi/`, `buildium/`, `appfolio/`, `netsuite/`, `coursera/`, `linkedin_learning/`, `udemy_business/`, `shopify/`, `woocommerce/`, `bigcommerce/`, `magento/`, `square/`, `recurly/`, `chargebee/`, `wordpress/`, `squarespace/`, `wix/`) bringing Tier 5 to 53/70 \u2014 audit-only providers (`hibp/`, `bitsight/`, `virustotal/`, `wazuh/`) ship `Validate`/`Connect` only and return an empty batch from `SyncIdentities`; the rest implement paginated identity sync with the canonical 7-test suite. Tier 3 is now 55/55 complete; Tier 4 is now 50/50 complete; total registered connectors at 183/200. SSO-equipped providers (Salesforce, GitHub, GitLab, Jira, Zendesk, BambooHR, Workday, Dropbox Business) additionally return a SAML metadata URL via `GetSSOMetadata`. Admin UI, Mobile SDK, Desktop Extension, AI auto-certification wire-in, email / Slack channels, real LLM-backed agent skills, the remaining Phase 7 Tier-4 / Tier-5 categories, and the Phase 1 Admin UI / Keycloak federation exit criteria remain open. See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the per-connector matrix and [`docs/PHASES.md`](docs/PHASES.md) for per-phase exit criteria.

The ShieldNet 360 Access Platform is the access management product within the SN360 ecosystem. It is a multi-tenant platform that lets small and medium-sized businesses connect, manage, and secure access to **200+ cloud platforms, SaaS applications, and identity systems** from a single control plane.

The platform is designed for companies with little or no in-house IT/security headcount. Founders, operations leads, and people-managers can run access end-to-end without writing policy DSLs, decoding SAML metadata, or hand-rolling SCIM payloads.

---

## Quick start

Requirements: Go 1.25+.

```bash
# Pull dependencies
go mod download

# Build every package and binary
go build ./...

# Run the full test suite (with the race detector)
go test -race -timeout=180s ./...

# Start the HTTP API on :8080 (override via ZTNA_API_LISTEN_ADDR).
# Set ACCESS_AI_AGENT_BASE_URL + ACCESS_AI_AGENT_API_KEY to enable
# AI risk scoring; leaving them empty turns AI off and AI-driven
# routes return 503 (the request workflow falls back to medium per
# PROPOSAL §5.3).
go run ./cmd/ztna-api
go run ./cmd/access-connector-worker
go run ./cmd/access-workflow-engine
```

Each binary blank-imports the connector packages so their `init()` functions register against the access-platform registry; if you add a new connector, also add it to the blank-import list of every `cmd/*/main.go` that needs it.

---

## How to run tests

The repo ships two test suites, both wired into CI (`.github/workflows/ci.yml` for Go and `.github/workflows/python-ci.yml` for the AI agent):

```bash
# Go suite: every handler, service, cron, worker, and connector test.
# The -race flag catches data races; 180s is the per-package timeout.
go test -race -timeout=180s ./...

# Go static checks
go vet ./...

# Swagger spec drift check (fails if docs/swagger.{json,yaml} or
# internal/handlers/swagger.{json,yaml} have drifted from the
# canonical regeneration target).
bash scripts/generate-swagger.sh --check

# SN360 user-facing language check (PROPOSAL §8 product register).
bash scripts/check_sn360_language.sh

# Python suite: AI agent skills and HTTP layer.
cd cmd/access-ai-agent
pip install -r requirements.txt
python -m pytest tests/ -v
```

CI runs the Go pipeline on every push and PR; the Python pipeline runs only when `cmd/access-ai-agent/**` or its workflow file changes (so PRs that don't touch the AI agent skip the Python build).

---

## Project structure

```
cautious-fishstick/
├── cmd/
│   ├── ztna-api/                  # HTTP API binary (Gin server on ZTNA_API_LISTEN_ADDR, default :8080)
│   ├── access-connector-worker/   # Queue worker (Phase 0 stub)
│   ├── access-workflow-engine/    # Phase 8 LangGraph-style orchestrator host: HTTP server on :8082, GET /health, POST /workflows/execute, WorkflowExecutor (auto_approve / manager_approval / security_review / multi_level), RiskRouter, EscalationChecker cron
│   └── access-ai-agent/           # Phase 4 Python A2A skill server (Tier-1 stubs)
│       ├── main.py                # stdlib http.server hosting POST /a2a/invoke + GET /healthz
│       ├── skills/                # access_risk_assessment, access_review_automation, access_anomaly_detection, connector_setup_assistant, policy_recommendation
│       ├── requirements.txt       # pytest only — runtime is stdlib
│       ├── Dockerfile             # python:3.12-slim runtime
│       └── tests/                 # pytest happy-path + error-path per skill + dispatcher e2e
├── internal/
│   ├── config/                                 # Phase 4 env-driven access platform config (ACCESS_AI_AGENT_*, ACCESS_FULL_RESYNC_INTERVAL, ...)
│   ├── cron/                                   # Phase 5 background workers
│   │   └── campaign_scheduler.go               # CampaignScheduler — starts due AccessReview campaigns
│   ├── handlers/                               # Gin HTTP handler layer (Phase 2–6)
│   │   ├── router.go                           # Router + Dependencies (DI for services)
│   │   ├── helpers.go                          # GetStringParam / GetPtrStringQuery (no direct c.Param/c.Query)
│   │   ├── errors.go                           # service-error → HTTP-status mapping
│   │   ├── access_request_handler.go           # POST/GET /access/requests, GET /access/requests/:id (detail + state-history audit trail), approve|deny|cancel
│   │   ├── access_grant_handler.go             # GET /access/grants (filtered by user_id / connector_id), GET /access/grants/:id/entitlements (live app-permission lookup via connector ListEntitlements)
│   │   ├── connector_list_handler.go           # GET /access/connectors (per-workspace catalogue with last-sync timestamps and registry-derived capability flags)
│   │   ├── access_review_handler.go            # POST /access/reviews, :id/decisions|close|auto-revoke, GET :id/metrics, PATCH :id
│   │   ├── policy_handler.go                   # POST /workspace/policy + drafts / simulate / promote / test-access
│   │   ├── scim_handler.go                     # Phase 6 inbound SCIM v2.0 — POST/PATCH/DELETE /scim/Users routed into JMLService
│   │   ├── connector_health_handler.go         # Phase 7 GET /access/connectors/:id/health — joins access_connectors + access_sync_state, returns last_sync_times + credential_expired_time + stale_audit flag (24h threshold)
│   │   └── ai_handler.go                       # POST /access/explain + /access/suggest (A2A pass-through)
│   ├── pkg/aiclient/                           # Phase 4 / Phase 6 A2A AI client
│   │   ├── client.go                           # POST {baseURL}/a2a/invoke with X-API-Key + DetectAnomalies
│   │   └── fallback.go                         # AssessRiskWithFallback + DetectAnomaliesWithFallback + Risk / Anomaly adapters
│   ├── services/access/
│   │   ├── types.go                       # AccessConnector + record types
│   │   ├── optional_interfaces.go         # IdentityDeltaSyncer / GroupSyncer / SCIMProvisioner / ...
│   │   ├── factory.go                     # Process-global registry
│   │   ├── testing.go                     # MockAccessConnector + SwapConnector test helper
│   │   ├── request_state_machine.go       # Phase 2 request lifecycle FSM (pure logic)
│   │   ├── request_service.go             # AccessRequestService — Create / Approve / Deny / Cancel + AI risk scoring
│   │   ├── provisioning_service.go        # AccessProvisioningService — Provision / Revoke
│   │   ├── grant_query_service.go         # Read-only ListActiveGrants for /access/grants
│   │   ├── workflow_service.go            # WorkflowService — ResolveWorkflow / ExecuteWorkflow
│   │   ├── policy_service.go              # Phase 3 PolicyService — CreateDraft / Simulate / Promote / TestAccess + AI risk scoring
│   │   ├── impact_resolver.go             # Phase 3 ImpactResolver — selector → affected teams / members / resources
│   │   ├── conflict_detector.go           # Phase 3 ConflictDetector — redundant / contradictory classification
│   │   ├── review_service.go              # Phase 5 AccessReviewService — StartCampaign / SubmitDecision / CloseCampaign / AutoRevoke / GetCampaignMetrics / SetAutoCertifyEnabled
│   │   ├── notification_adapter.go        # Phase 5 ReviewNotifier adapter wrapping notification.NotificationService
│   │   ├── jml_service.go                 # Phase 6 JMLService — ClassifyChange / HandleJoiner / HandleMover / HandleLeaver
│   │   ├── scim_provisioner.go            # Phase 6 SCIMClient — generic SCIM v2.0 push (PushSCIMUser / PushSCIMGroup / DeleteSCIMResource)
│   │   ├── sso_federation_service.go      # Phase 1 SSOFederationService — KeycloakClient interface + HTTPKeycloakClient + Configure() mapping SSOMetadata to Keycloak SAML / OIDC IdP brokers
│   │   ├── audit_producer.go              # Phase 10 AuditProducer interface — KafkaAuditProducer (ShieldnetLogEvent v1 → access_audit_logs topic) + NoOpAuditProducer for dev/test
│   │   ├── idempotency.go                 # Phase 10 idempotency helpers (IsIdempotentProvisionStatus / IsIdempotentRevokeStatus) for advanced-capability connectors
│   │   ├── anomaly_service.go             # Phase 6 AnomalyDetectionService — ScanWorkspace through AnomalyDetector
│   │   └── connectors/
│   │       ├── microsoft/         # Entra ID — Validate, Connect, Sync, GroupSync, Delta
│   │       ├── google_workspace/  # Admin SDK Directory — Validate, Connect, Sync, GroupSync
│   │       ├── okta/              # Okta API — Validate, Connect, Sync, Delta via system log
│   │       ├── auth0/             # Auth0 Management API — Validate, Connect, Sync, Delta via logs API
│   │       ├── generic_saml/      # SAML IdP metadata broker — Validate, Connect, GetSSOMetadata (SSO-only)
│   │       ├── generic_oidc/      # OIDC discovery broker — Validate, Connect, GetSSOMetadata (SSO-only)
│   │       ├── duo/               # Duo Admin API — Validate, Connect (HMAC-SHA1), Sync, SCIM
│   │       ├── onepassword/       # 1Password SCIM v2 — Validate, Connect, Sync, SCIM
│   │       ├── lastpass/          # LastPass Enterprise API — Validate, Connect, Sync, SCIM
│   │       ├── ping_identity/     # PingOne v1 (NA/EU/AP) — Validate, Connect, Sync, SCIM
│   │       ├── aws/               # AWS IAM (SigV4) — Validate, Connect, Sync, Count, Metadata
│   │       ├── azure/             # Azure RBAC (Microsoft Graph + OAuth2) — Validate, Connect, Sync, Count
│   │       ├── gcp/               # GCP IAM (cloudresourcemanager getIamPolicy) — Validate, Connect, Sync
│   │       ├── cloudflare/        # Cloudflare Account Members — Validate, Connect, Sync
│   │       ├── tailscale/         # Tailscale Tailnet Users — Validate, Connect, Sync
│   │       ├── digitalocean/      # DigitalOcean Team Members — Validate, Connect, Sync
│   │       ├── heroku/            # Heroku Team Members — Validate, Connect, Sync
│   │       ├── vercel/            # Vercel Team Members — Validate, Connect, Sync
│   │       ├── netlify/           # Netlify Account Members — Validate, Connect, Sync
│   │       ├── vultr/             # Vultr /v2/users (cursor) — Validate, Connect, Sync
│   │       ├── linode/            # Linode /v4/account/users (page/page_size) — Validate, Connect, Sync
│   │       ├── ovhcloud/          # OVHcloud /1.0/me/identity/user (OVH signature) — Validate, Connect, Sync
│   │       ├── alibaba/           # Alibaba RAM ListUsers (HMAC-SHA1 + Marker) — Validate, Connect, Sync
│   │       ├── cloudsigma/        # CloudSigma /api/2.0/profile/ (per-region Basic) — Validate, Connect, Sync
│   │       ├── wasabi/            # Wasabi IAM-compatible ListUsers (SigV4) — Validate, Connect, Sync
│   │       ├── slack/             # Slack users.list (cursor) + Enterprise-Grid SAML — Validate, Connect, Sync
│   │       ├── ms_teams/          # Graph /teams/{id}/members + Entra SAML — Validate, Connect, Sync
│   │       ├── zoom/              # Zoom Server-to-Server OAuth + /users — Validate, Connect, Sync
│   │       ├── notion/            # Notion /v1/users (start_cursor) — Validate, Connect, Sync
│   │       ├── asana/             # Asana /workspaces/{gid}/users (offset) — Validate, Connect, Sync
│   │       ├── monday/            # Monday.com GraphQL users (page) — Validate, Connect, Sync
│   │       ├── figma/             # Figma /v1/teams/{team_id}/members (cursor) — Validate, Connect, Sync
│   │       ├── miro/              # Miro /v2/orgs/{org_id}/members (cursor) — Validate, Connect, Sync
│   │       ├── trello/            # Trello /1/organizations/{org_id}/members — Validate, Connect, Sync
│   │       ├── airtable/          # Airtable enterprise users (offset) — Validate, Connect, Sync
│   │       ├── smartsheet/        # Smartsheet /2.0/users (page/pageSize/totalPages) — Validate, Connect, Sync
│   │       ├── clickup/           # ClickUp /api/v2/team/{team_id}/member — Validate, Connect, Sync
│   │       ├── dropbox/           # Dropbox Business POST /2/team/members/list_v2 + SAML — Validate, Connect, Sync
│   │       ├── box/               # Box /2.0/users (offset/limit + total_count) — Validate, Connect, Sync
│   │       ├── salesforce/        # Salesforce SOQL User + SAML metadata — Validate, Connect, Sync
│   │       ├── hubspot/           # HubSpot /settings/v3/users (after-cursor) — Validate, Connect, Sync
│   │       ├── zoho_crm/          # Zoho CRM /crm/v5/users (page/per_page) — Validate, Connect, Sync
│   │       ├── pipedrive/         # Pipedrive /v1/users (next_start) — Validate, Connect, Sync
│   │       ├── github/            # GitHub /orgs/{org}/members (Link header) + Enterprise SAML — Validate, Connect, Sync
│   │       ├── gitlab/            # GitLab /api/v4/groups/{id}/members/all + group SAML — Validate, Connect, Sync
│   │       ├── jira/              # Atlassian Jira /rest/api/3/users/search + Atlassian SAML — Validate, Connect, Sync
│   │       ├── pagerduty/         # PagerDuty /users (offset/limit + more) — Validate, Connect, Sync
│   │       ├── sentry/            # Sentry /api/0/organizations/{slug}/members/ (Link rel=next results=true) — Validate, Connect, Sync
│   │       ├── zendesk/           # Zendesk /api/v2/users.json (next_page) + SAML metadata — Validate, Connect, Sync
│   │       ├── freshdesk/         # Freshdesk /api/v2/agents (page) — Validate, Connect, Sync
│   │       ├── helpscout/         # Help Scout /v2/users (HAL totalPages) — Validate, Connect, Sync
│   │       ├── crowdstrike/       # CrowdStrike Falcon OAuth2 + query-then-hydrate — Validate, Connect, Sync
│   │       ├── sentinelone/       # SentinelOne /web/api/v2.1/users (nextCursor) — Validate, Connect, Sync
│   │       ├── snyk/              # Snyk /rest/orgs/{org_id}/members (links.next) — Validate, Connect, Sync
│   │       ├── bamboohr/          # BambooHR /v1/employees/directory + SAML metadata — Validate, Connect, Sync
│   │       ├── gusto/             # Gusto /v1/companies/{company_id}/employees (page/per) — Validate, Connect, Sync
│   │       ├── rippling/          # Rippling /platform/api/employees (cursor) — Validate, Connect, Sync
│   │       ├── personio/          # Personio OAuth2 /v1/auth + /v1/company/employees (offset) — Validate, Connect, Sync
│   │       ├── hibob/             # Hibob /v1/people?showInactive=true — Validate, Connect, Sync
│   │       ├── workday/           # Workday /ccx/api/v1/{tenant}/workers (offset/total) + SAML — Validate, Connect, Sync
│   │       ├── quickbooks/        # QuickBooks Online /v3/company/{realm}/query Employee — Validate, Connect, Sync
│   │       ├── xero/              # Xero /api.xro/2.0/Users (offset + Xero-Tenant-Id) — Validate, Connect, Sync
│   │       ├── stripe/            # Stripe Connect /v1/accounts (starting_after cursor) — Validate, Connect, Sync
│   │       ├── freshbooks/        # FreshBooks /accounting/account/{id}/users/staffs (page/per_page) — Validate, Connect, Sync
│   │       ├── circleci/          # CircleCI /api/v2/me/collaborations (single-page, Circle-Token) — Validate, Connect, Sync
│   │       ├── datadog/           # Datadog /api/v2/users (page[number]/page[size] + DD-API-KEY/APPLICATION-KEY) — Validate, Connect, Sync
│   │       ├── deel/              # Deel /rest/v2/contracts (page/page_size; workers projected from contracts) — Validate, Connect, Sync
│   │       ├── docker_hub/        # Docker Hub /v2/orgs/{org}/members (JWT login + next URL) — Validate, Connect, Sync
│   │       ├── egnyte/            # Egnyte /pubapi/v2/users (offset/count + bearer) — Validate, Connect, Sync
│   │       ├── front/             # Front /teammates (_pagination.next + bearer) — Validate, Connect, Sync
│   │       ├── grafana/           # Grafana /api/org/users (single-page; bearer or Basic) — Validate, Connect, Sync
│   │       ├── intercom/          # Intercom /admins (single-page + bearer) — Validate, Connect, Sync
│   │       ├── jfrog/             # JFrog /access/api/v2/users (offset/limit + bearer) — Validate, Connect, Sync
│   │       ├── launchdarkly/      # LaunchDarkly /api/v2/members (offset/limit + bearer) — Validate, Connect, Sync
│   │       ├── namely/            # Namely /api/v1/profiles (page/per_page + bearer) — Validate, Connect, Sync
│   │       ├── new_relic/         # New Relic NerdGraph /graphql users{nextCursor} — Validate, Connect, Sync
│   │       ├── paychex/           # Paychex /companies/{id}/workers (offset/limit + OAuth2 bearer) — Validate, Connect, Sync
│   │       ├── paypal/            # PayPal /v1/customer/partners/{id}/merchant-integrations (OAuth2 client_credentials) — Validate, Connect, Sync
│   │       ├── sonarcloud/        # SonarCloud /api/organizations/search_members (p/ps + bearer) — Validate, Connect, Sync
│   │       ├── splunk/            # Splunk /services/authentication/users (count/offset + bearer) — Validate, Connect, Sync
│   │       ├── terraform/         # Terraform Cloud /api/v2/organizations/{org}/organization-memberships (page[number]) — Validate, Connect, Sync
│   │       ├── wave/              # Wave Financial GraphQL businesses (cursor + bearer) — Validate, Connect, Sync
│   │       ├── zenefits/          # Zenefits /core/people (next_url + bearer) — Validate, Connect, Sync
│   │       ├── activecampaign/    # ActiveCampaign /api/3/users (Api-Token header + offset/limit + DNS-label account subdomain) — Validate, Connect, Sync
│   │       ├── anvyl/             # Anvyl /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── apollo/            # Apollo.io /v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── basecamp/          # Basecamp /people.json (OAuth2 bearer + numeric account_id) — Validate, Connect, Sync
│   │       ├── billdotcom/        # Bill.com /v3/orgs/{org_id}/users (devKey + sessionId headers + start/max + URL-path-escape) — Validate, Connect, Sync
│   │       ├── braze/             # Braze SCIM /scim/v2/Users (bearer + startIndex/count + cluster allow-list) — Validate, Connect, Sync
│   │       ├── close/             # Close /api/v1/user/ (HTTP Basic api_key: + _skip/_limit + has_more) — Validate, Connect, Sync
│   │       ├── constant_contact/  # Constant Contact /v3/account/users (OAuth2 bearer + offset/limit + login_enabled) — Validate, Connect, Sync
│   │       ├── copper/            # Copper /developer_api/v1/users (X-PW-AccessToken + X-PW-Application + X-PW-UserEmail + page_number/page_size) — Validate, Connect, Sync
│   │       ├── coupa/             # Coupa /api/users (X-COUPA-API-KEY header + offset/limit + DNS-label instance subdomain) — Validate, Connect, Sync
│   │       ├── crisp/             # Crisp /v1/website/{website_id}/operators/list (HTTP Basic identifier:key) — Validate, Connect, Sync
│   │       ├── discord/           # Discord /api/v10/guilds/{guild_id}/members (Bot token + after snowflake cursor) — Validate, Connect, Sync
│   │       ├── drift/             # Drift /v1/users/list (OAuth2 bearer; single-page) — Validate, Connect, Sync
│   │       ├── eventbrite/        # Eventbrite /v3/organizations/{id}/members/ (bearer + continuation cursor + has_more_items + URL-path-escape) — Validate, Connect, Sync
│   │       ├── expensify/         # Expensify /Integration-Server/ExpensifyIntegrations (form-encoded requestJobDescription JSON with partner credentials) — Validate, Connect, Sync
│   │       ├── gong/              # Gong /v2/users (HTTP Basic access_key:secret_key + records.cursor) — Validate, Connect, Sync
│   │       ├── gorgias/           # Gorgias /api/users (HTTP Basic email:api_key + page/per_page + X-Gorgias-Account) — Validate, Connect, Sync
│   │       ├── insightly/         # Insightly /v3.1/Users (HTTP Basic api_key: + skip/top + DNS-label pod) — Validate, Connect, Sync
│   │       ├── klaviyo/           # Klaviyo /api/accounts/ (Klaviyo-API-Key + JSON:API page[cursor]) — Validate, Connect, Sync
│   │       ├── knowbe4/           # KnowBe4 /v1/users (bearer + page/per_page + region host routing) — Validate, Connect, Sync
│   │       ├── liquidplanner/     # LiquidPlanner /api/v1/workspaces/{workspace_id}/members (bearer; single-page) — Validate, Connect, Sync
│   │       ├── livechat/          # LiveChat /v3.5/agents (PAT bearer + page/page_size) — Validate, Connect, Sync
│   │       ├── loom/              # Loom /v1/members (bearer + next_cursor pagination) — Validate, Connect, Sync
│   │       ├── mailchimp/         # Mailchimp /3.0/lists/{list_id}/members (HTTP Basic anystring:api_key + offset/count + datacenter routing) — Validate, Connect, Sync
│   │       ├── mezmo/             # Mezmo /v1/config/members (servicekey {key} auth; single-page) — Validate, Connect, Sync
│   │       ├── mixpanel/          # Mixpanel /api/app/me/organizations/{id}/members (HTTP Basic service-account user:secret + URL-path-escape) — Validate, Connect, Sync
│   │       ├── navan/             # Navan /api/v1/users (bearer + page/size 0-indexed + status normalize) — Validate, Connect, Sync
│   │       ├── plaid/             # Plaid /team/list (POST + client_id/secret JSON body + sandbox/development/production routing) — Validate, Connect, Sync
│   │       ├── quip/              # Quip /1/users/contacts (bearer; single-page) — Validate, Connect, Sync
│   │       ├── sage_intacct/      # Sage Intacct /ia/xml/xmlgw.phtml (POST XML with sender + user credentials + readByQuery + offset pagination) — Validate, Connect, Sync
│   │       ├── salesloft/         # Salesloft /v2/users (bearer + page/per_page + metadata.paging.next_page) — Validate, Connect, Sync
│   │       ├── sap_concur/        # SAP Concur /api/v3.0/common/users (OAuth2 bearer + offset/limit + Active bool) — Validate, Connect, Sync
│   │       ├── segment/           # Segment /users (bearer + pagination.cursor/pagination.count + segment.v1 accept) — Validate, Connect, Sync
│   │       ├── slack_enterprise/  # Slack Enterprise SCIM /scim/v2/Users (bearer + startIndex/count) — Validate, Connect, Sync
│   │       ├── sumo_logic/        # Sumo Logic /api/v1/users (HTTP Basic + offset/limit + deployment host routing) — Validate, Connect, Sync
│   │       ├── surveymonkey/      # SurveyMonkey /v3/users (bearer + page/per_page + links.next continuation) — Validate, Connect, Sync
│   │       ├── teamwork/          # Teamwork /people.json (HTTP Basic api_key:xxx + page/pageSize) — Validate, Connect, Sync
│   │       ├── travis_ci/         # Travis CI /users (Authorization: token + offset/limit) — Validate, Connect, Sync
│   │       ├── typeform/          # Typeform /teams/members (bearer; single-page) — Validate, Connect, Sync
│   │       ├── wrike/             # Wrike /api/v4/contacts (bearer + nextPageToken cursor) — Validate, Connect, Sync
│   │       ├── anthropic/         # Anthropic /v1/organizations/members (x-api-key + page/per_page) — Validate, Connect, Sync
│   │       ├── beyondtrust/       # BeyondTrust /api/v1/users (bearer + offset/limit) — Validate, Connect, Sync
│   │       ├── bitsight/          # BitSight /ratings/v2/portfolio/users (audit-only — Authorization: Token; SyncIdentities returns empty) — Validate, Connect, Metadata
│   │       ├── copyai/            # Copy.ai /api/v1/workspace/members (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── forgerock/         # ForgeRock /openidm/managed/user (bearer + _queryFilter=true + _pageSize / _pagedResultsCookie + DNS-label endpoint) — Validate, Connect, Sync
│   │       ├── gemini/            # Google Gemini /v1/projects/{project}/users (OAuth2 bearer + GCP project_id rules + page/per_page) — Validate, Connect, Sync
│   │       ├── hackerone/         # HackerOne /v1/organizations/{org_id}/members (bearer + page/per_page + URL-path-escape) — Validate, Connect, Sync
│   │       ├── hibp/              # HIBP /api/v3/subscription/status (audit-only — hibp-api-key header; SyncIdentities returns empty) — Validate, Connect, Metadata
│   │       ├── jasper/            # Jasper AI /v1/team/members (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── keeper/            # Keeper /api/rest/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── malwarebytes/      # Malwarebytes /api/v2/accounts/{account_id}/users (bearer + page/per_page + URL-path-escape) — Validate, Connect, Sync
│   │       ├── midjourney/        # Midjourney /api/v1/members (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── mistral/           # Mistral AI /v1/organization/members (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── openai/            # OpenAI /v1/organization/users (bearer + limit/after cursor + has_more/last_id) — Validate, Connect, Sync
│   │       ├── perplexity/        # Perplexity /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── qualys/            # Qualys VMDR /api/2.0/fo/user/ (HTTP Basic + X-Requested-With + XML USER_LIST_OUTPUT + id_min cursor + platform allow-list us1/us2/us3/us4/eu1/eu2/in1/ae1/uk1/ca1/au1 OR validated base_url) — Validate, Connect, Sync
│   │       ├── rapid7/            # Rapid7 InsightVM /api/3/users (HTTP Basic + page/size + page.totalPages + DNS-label endpoint) — Validate, Connect, Sync
│   │       ├── tenable/           # Tenable.io /users (X-ApiKeys: accessKey=...;secretKey=... + offset/limit + enabled bool) — Validate, Connect, Sync
│   │       ├── virustotal/        # VirusTotal /api/v3/users/current (audit-only — x-apikey header; SyncIdentities returns empty) — Validate, Connect, Metadata
│   │       ├── wazuh/             # Wazuh /security/users (audit-only — bearer + DNS-label endpoint; SyncIdentities returns empty) — Validate, Connect, Metadata
│   │       ├── appfolio/          # AppFolio /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── bigcommerce/       # BigCommerce /stores/{store_hash}/v2/customers (X-Auth-Token + page/limit + URL-path-escape) — Validate, Connect, Sync
│   │       ├── buildium/          # Buildium /v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── chargebee/         # Chargebee /api/v2/customers (HTTP Basic api_key: + offset cursor + DNS-label site) — Validate, Connect, Sync
│   │       ├── coursera/          # Coursera /api/businesses.v1/{org}/users (bearer + page/per_page + URL-path-escape) — Validate, Connect, Sync
│   │       ├── kareo/             # Kareo /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── linkedin_learning/ # LinkedIn Learning admin /v2/learningActivityReports (bearer + page/start cursor) — Validate, Connect, Sync
│   │       ├── magento/           # Magento 2 /rest/V1/customers/search (bearer + searchCriteria pagination + total_count + https endpoint) — Validate, Connect, Sync
│   │       ├── netsuite/          # NetSuite SuiteTalk /record/v1/employee (bearer + offset/limit) — Validate, Connect, Sync
│   │       ├── practice_fusion/   # Practice Fusion /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── recurly/           # Recurly v3 /accounts (bearer + has_more/next cursor) — Validate, Connect, Sync
│   │       ├── shopify/           # Shopify /admin/api/2024-01/users.json (X-Shopify-Access-Token header + page_info cursor + DNS-label shop) — Validate, Connect, Sync
│   │       ├── square/            # Square /v2/team-members/search (bearer + cursor) — Validate, Connect, Sync
│   │       ├── squarespace/       # Squarespace /1.0/commerce/profile/members (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── udemy_business/    # Udemy Business /organizations/{org}/users (bearer + page/per_page + URL-path-escape) — Validate, Connect, Sync
│   │       ├── wix/               # Wix /members/v1/members (bearer + paging.offset/paging.limit) — Validate, Connect, Sync
│   │       ├── woocommerce/       # WooCommerce /wp-json/wc/v3/customers (HTTP Basic consumer_key:consumer_secret + page/per_page + https endpoint) — Validate, Connect, Sync
│   │       ├── wordpress/         # WordPress.com /rest/v1.1/sites/{site}/users (bearer + page/number + URL-path-escape) — Validate, Connect, Sync
│   │       ├── yardi/             # Yardi /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── zocdoc/            # Zocdoc /api/v1/providers (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── buffer/            # Buffer /1/user.json (bearer + single-page) — Validate, Connect, Sync
│   │       ├── fullstory/         # FullStory /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── ga4/               # Google Analytics 4 Admin /v1beta/accounts/{account}/userLinks (OAuth2 bearer + URL-path-escape + pageSize/pageToken) — Validate, Connect, Sync
│   │       ├── ghost/             # Ghost Admin /ghost/api/admin/users/ (bearer + page/limit) — Validate, Connect, Sync
│   │       ├── heap/              # Heap /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── hootsuite/         # Hootsuite /v1/me/organizations/{org}/members (OAuth2 bearer + URL-path-escape + cursor) — Validate, Connect, Sync
│   │       ├── ifttt/             # IFTTT /v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── jotform/           # Jotform /user/sub-users (bearer + offset/limit) — Validate, Connect, Sync
│   │       ├── make/              # Make (Integromat) /api/v2/users (Authorization: Token … + pg[offset]/pg[limit]) — Validate, Connect, Sync
│   │       ├── ringcentral/       # RingCentral /restapi/v1.0/account/~/extension (bearer + page/perPage camelCase) — Validate, Connect, Sync
│   │       ├── sendgrid/          # SendGrid /v3/teammates (bearer + offset/limit) — Validate, Connect, Sync
│   │       ├── sprout_social/     # Sprout Social /v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── surveysparrow/     # SurveySparrow /v3/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── twilio/            # Twilio /2010-04-01/Accounts/{sid}/Users.json (HTTP Basic sid:auth_token + page/pageSize + URL-path-escape) — Validate, Connect, Sync
│   │       ├── vonage/            # Vonage /api/v1/users (bearer + page/per_page) — Validate, Connect, Sync
│   │       ├── wufoo/             # Wufoo /api/v3/users.json (HTTP Basic api_key + DNS-label subdomain) — Validate, Connect, Sync
│   │       └── zapier/            # Zapier /v1/team/members (bearer + page/per_page) — Validate, Connect, Sync
│   ├── services/access/workflow_engine/        # Phase 8 LangGraph-style orchestration package
│   │   ├── router.go                          # RiskRouter (low → self_service, medium → manager_approval, high or sensitive_resource tag → security_review)
│   │   ├── executor.go                        # WorkflowExecutor + ExecuteRequest / ExecutionResult + StepPerformer interface + ListFailedSteps DLQ
│   │   ├── steps.go                           # auto_approve / manager_approval / security_review / multi_level step bodies
│   │   ├── performer.go                       # RealStepPerformer (replaces NoOpPerformer) — drives AccessRequestService.ApproveRequest / MarkPending
│   │   ├── retry.go                           # RetryPolicy (3 attempts, exponential backoff 100ms → 200ms → 400ms cap 5s) + step-history DLQ writes
│   │   ├── escalation.go                      # EscalationChecker cron + Escalator interface (timeout_hours / escalation_target / multi_level Levels[])
│   │   ├── notification_escalator.go          # NotifyingEscalator (replaces loggingEscalator) — writes AccessRequestStateHistory + fans best-effort notifications
│   │   └── server.go                          # net/http server (GET /health, POST /workflows/execute) on :8082 (configurable via ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR)
│   ├── services/notification/             # Phase 5 NotificationService + Notifier interface + InMemoryNotifier
│   │   ├── service.go                     # NotifyReviewersPending / NotifyRequester (best-effort fan-out)
│   │   └── push_notifier.go               # WebPushNotifier — POSTs pushEnvelope JSON to PushSubscription endpoints (best-effort)
│   ├── pkg/credentials/                   # AES-GCM credential manager (KeyManager interface stub)
│   ├── models/                            # GORM models
│   │   ├── access_connector.go            # access_connectors
│   │   ├── access_request.go              # access_requests + state constants
│   │   ├── access_request_state_history.go# access_request_state_history (audit trail)
│   │   ├── access_grant.go                # access_grants
│   │   ├── access_workflow.go             # access_workflows + step-type constants
│   │   ├── policy.go                      # Phase 3 policies + action / draft helpers
│   │   ├── team.go                        # Phase 3 teams + team_members
│   │   ├── resource.go                    # Phase 3 resources
│   │   ├── access_review.go               # Phase 5 access_reviews + state constants
│   │   ├── access_review_decision.go      # Phase 5 access_review_decisions + decision constants
│   │   ├── access_campaign_schedule.go    # Phase 5 access_campaign_schedules (recurring check-ups + SkipDates)
│   │   ├── access_workflow_step_history.go# Phase 8 access_workflow_step_history (durable per-step audit log + DLQ)
│   │   └── push_subscription.go           # Phase 5 push_subscriptions (WebPush endpoint + p256dh / auth keys)
│   └── migrations/                        # GORM AutoMigrate migrations (no FK constraints)
│       ├── 001_create_access_connectors.go
│       ├── 002_create_access_request_tables.go
│       ├── 003_create_policy_tables.go
│       ├── 004_create_access_review_tables.go
│       ├── 005_create_access_campaign_schedules.go
│       ├── 008_seed_workflow_templates.go         # Phase 8 default templates: new_hire_onboarding / contractor_onboarding / role_change / project_access
│       ├── 009_create_workflow_step_history.go    # Phase 8 access_workflow_step_history table
│       └── 010_create_push_subscriptions.go       # Phase 5 push_subscriptions table
├── internal/workers/handlers/
│   ├── access_audit.go            # Phase 10 AccessAudit worker handler — loads partition-keyed cursor map from access_sync_state (kind=audit), invokes FetchAccessAuditLogs(ctx, cfg, secrets, sincePartitions, handler), publishes batches via AuditProducer, advances each cursor monotonically (JSON-encoded map; legacy bare-RFC3339 migrates transparently), soft-skips ErrAuditNotAvailable
│   └── access_audit_integration_test.go # End-to-end pipeline tests: cursor persistence across runs, independent multi-partition cursors (Microsoft directoryAudits + signIns), legacy bare-RFC3339 cursor migration
├── internal/handlers/
│   ├── swagger_handler.go         # OpenAPI 3.0 spec served at /swagger, /swagger.json, /swagger.yaml via //go:embed
│   └── swagger.{json,yaml}        # Embedded copies of docs/swagger.{json,yaml} (kept in sync by scripts/generate-swagger.sh)
├── scripts/
│   ├── generate-swagger.sh        # Regenerates docs/swagger.{json,yaml} (supports --check for CI drift detection)
│   └── check_sn360_language.sh    # SN360 product-language CI check (fails on forbidden terms like "ZTNA policy", "Entitlement", "Federated SSO" inside quoted strings under internal/handlers/ and docs/swagger.*); driven from go test via scripts/check_sn360_language_test.go
├── blog/                          # Public-facing release notes (12 posts: 00-introducing-shieldnet-access through 11-…)
├── .github/workflows/             # CI: ci.yml (Go build/vet/test -race/swagger --check/sn360-language) and python-ci.yml (cmd/access-ai-agent pytest)
└── docs/                          # Proposal, architecture, phases, progress, OpenAPI 3.0 spec (swagger.json + swagger.yaml)
```

---

## Core Capabilities

The platform exposes four user-facing capabilities. Each capability is documented in technical terms (for engineers) and in **SN360 language** (the simple wording used in the admin UI and end-user surfaces).

### 1. App Connections

> **SN360 language:** App connections.
> **Technical term:** Access connectors.

Connect company systems — cloud, SaaS, identity, HR, finance — through guided setup wizards. The platform ships with **200 providers** spanning IAM/SSO, Cloud Infrastructure, Collaboration, CRM, Finance, HR, DevOps, Security, and more. Each connection covers one or more of:

- Identity sync (pull users / groups into Teams).
- Access provisioning (push grants out to the SaaS app).
- Entitlement review (pull current permissions for a periodic check-up).
- SSO federation (broker SAML / OIDC through Keycloak).
- Access audit logs (pull sign-in events into the audit pipeline).

See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the per-provider capability matrix.

### 2. Access Lifecycle

> **SN360 language:** Access requests and access check-ups.
> **Technical term:** Joiner-Mover-Leaver (JML) automation, access certification.

Automated lifecycle for every grant: **Request → Review → Approve → Provision → Monitor → Review → Revoke**. The platform handles the full state machine and surfaces the right action (approve, deny, escalate) to the right person at the right time.

- Self-service requests with policy-based auto-approval.
- Manager and multi-level approval workflows.
- Periodic access check-ups with auto-certification of low-risk grants.
- SCIM-driven joiner / mover / leaver flows for full provisioning and deprovisioning.

### 3. Access Rules

> **SN360 language:** Access rules with safe-test mode.
> **Technical term:** Policy simulation and impact analysis.

Draft and test access rules before rolling them out. The platform resolves the affected Teams, members, and resources, flags conflicts with existing rules, and runs an AI risk assessment so admins know what a change will actually do before it goes live.

- Draft rules are stored separately and never reach the OpenZiti dataplane.
- "What-if" tester answers `Can user X access resource Y under this draft?`.
- One-click promotion from draft to live, generating the underlying ServicePolicy.

### 4. AI-Powered Intelligence

> **SN360 language:** AI assistant.
> **Technical term:** Server-side AI agents over A2A protocol; LangGraph workflow orchestration.

AI is **server-side only**. Mobile and desktop clients are thin extensions / SDKs / libraries that call the platform's REST APIs — they do **not** run any local model inference. Server-side agents cover:

- Risk assessment for new access requests and policy changes.
- Auto-certification of low-risk grants during access check-ups.
- Anomaly detection on active grants.
- Connector setup assistance (natural language → wizard answers).
- Policy recommendations from organizational structure and historical usage.

---

## Architecture Overview

```
Admin UI (React)              ┐
Mobile SDK (iOS / Android)    ├──REST──▶ ZTNA Business Layer (Go)
Desktop Extension (Electron)  ┘                  │
                                                 ├──▶ PostgreSQL (access_*, policies)
                                                 ├──▶ Redis (queue, staging, locks)
                                                 ├──▶ Keycloak (SSO federation)
                                                 ├──▶ OpenZiti (ServicePolicy)
                                                 ├──▶ Kafka (audit envelope)
                                                 └──▶ Access Connector Worker
                                                          │
                                                          └──▶ Access Connectors (200 providers)

ZTNA Business Layer ◀──A2A──▶ Access AI Agent Server (Python)
ZTNA Business Layer ◀──HTTP─▶ Access Workflow Engine (LangGraph)
```

Backend services extend the patterns in `ztna-business-layer`. The frontend extends `ztna-frontend`. AI agents extend `aisoc-ai-agents`. Workflow orchestration extends `aisoc-workflow-agents`. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for full diagrams.

---

## Connector Coverage

The platform targets **200 providers** across the categories below. The full per-provider list, with capability columns and status, lives in [`docs/PROGRESS.md`](docs/PROGRESS.md). The catalogue itself is adapted from `shieldnet360-backend/docs/connectors/LISTCONNECTORS.md` with access-specific columns (identity sync, access provisioning, entitlement review, access audit, SSO federation) instead of security-monitoring columns.

| Tier | Category | Count | Implemented | Examples |
|------|----------|-------|:-----------:|----------|
| 1 | Core Identity / SSO | 10 | 10 / 10 | Microsoft Entra ID, Google Workspace, Okta, Auth0, Generic SAML, Generic OIDC, Duo Security, 1Password, LastPass, Ping Identity (all with outbound SCIM composition) |
| 2 | Cloud Infrastructure | 15 | 15 / 15 | **Implemented:** AWS IAM, Azure RBAC, GCP IAM, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify, Vultr, Linode, OVHcloud, Alibaba Cloud, CloudSigma, Wasabi |
| 3 | Business SaaS | 55 | 55 / 55 | **Implemented:** Slack, MS Teams, Zoom, Notion, Asana, Monday.com, Figma, Miro, Trello, Airtable, Smartsheet, ClickUp, Salesforce, HubSpot, Zoho CRM, Pipedrive, Dropbox Business, Box, GitHub, GitLab, Jira, PagerDuty, Sentry, Zendesk, Freshdesk, Help Scout, Egnyte, Terraform Cloud, Docker Hub, JFrog, SonarCloud, CircleCI, Travis CI, LaunchDarkly, Datadog, New Relic, Splunk Cloud, Grafana, Mezmo, Sumo Logic, Front, Intercom, Drift, Crisp, LiveChat, Gorgias, Loom, Discord, Slack Enterprise, Basecamp, Quip, Wrike, Teamwork, LiquidPlanner, KnowBe4. |
| 4 | HR / Finance / Legal / Sales / Marketing | 50 | 50 / 50 | **Implemented:** BambooHR, Gusto, Rippling, Personio, Hibob, Workday, QuickBooks, Xero, Stripe, FreshBooks, Paychex, Deel, Zenefits, Namely, PayPal, Wave, Gong, Salesloft, Mailchimp, Klaviyo, Apollo.io, Copper, Insightly, Close, ActiveCampaign, Constant Contact, Braze, Mixpanel, Segment, Typeform, SurveyMonkey, Eventbrite, Navan, SAP Concur, Coupa, Anvyl, Bill.com, Expensify, Sage Intacct, Plaid, Brex, Ramp, Clio, Ironclad, DocuSign, DocuSign CLM, MyCase, PandaDoc, PandaDoc CLM, HelloSign. *(Tier 4 closed in PR #16.)* |
| 5 | Vertical / Niche | 70 | **70 / 70** | **Implemented:** CrowdStrike, SentinelOne, Snyk, Cisco Meraki, Fortinet, Zscaler, Check Point, Palo Alto Prisma, NordLayer, Perimeter 81, Netskope, Sophos Central, Sophos XG, HackerOne, HIBP, BitSight, Tenable.io, Qualys VMDR, Rapid7, VirusTotal, Malwarebytes, ForgeRock, BeyondTrust, Keeper, Wazuh, OpenAI, Google Gemini, Anthropic, Perplexity, Mistral, Midjourney, Jasper, Copy.ai, Practice Fusion, Kareo, Zocdoc, Yardi, Buildium, AppFolio, NetSuite, Coursera, LinkedIn Learning, Udemy Business, Shopify, WooCommerce, BigCommerce, Magento, Square, Recurly, Chargebee, WordPress, Squarespace, Wix, Ghost, SurveySparrow, Jotform, Wufoo, Hootsuite, Sprout Social, Buffer, Twilio, SendGrid, RingCentral, Vonage, Zapier, Make, IFTTT, GA4, Heap, FullStory. *(Tier 5 Security / IAM / GenAI block landed in PR #17; Tier-5 Health / Real Estate / ERP / Education / E-commerce / Web batch landed in PR #18; the final Customer-Feedback / Social / Comm / Utility / Analytics batch — 17 connectors — closes Tier 5 in PR #19.)* |
| | **Total** | **200** | **200 / 200** | |

---

## Tech Stack

| Layer | Stack |
|-------|-------|
| Backend | Go 1.25+, Gin, sqlc, PostgreSQL, Redis, Kafka |
| Admin Frontend | React (Next.js 15+), TypeScript, Redux Toolkit, Radix UI, TailwindCSS |
| Mobile SDK — iOS | Swift Package — REST client, no on-device model inference |
| Mobile SDK — Android | Kotlin library — REST client, no on-device model inference |
| Desktop Extension | Electron + React — IPC module, no on-device model inference |
| AI Agents | Python (A2A protocol), extends `aisoc-ai-agents` |
| Workflow Engine | LangGraph + Go orchestrator, extends `aisoc-workflow-agents` |
| Identity Broker | Keycloak |
| Dataplane | OpenZiti (ServicePolicy management) |
| Infra | Kubernetes, ArgoCD |

The mobile and desktop clients are **integration SDKs / libraries / extensions** for existing main applications. They do not bundle, load, or run any AI model locally. Every AI capability flows through a REST call to the server-side agent.

---

## Documentation

| Document | What's in it |
|----------|--------------|
| [`docs/PROPOSAL.md`](docs/PROPOSAL.md) | Technical specification: AccessConnector contract, registry, credential management, lifecycle workflow engine, policy simulation engine, AI integration, SN360 language, schema, deployment, SDK contract, open questions. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture and data-flow diagrams (Mermaid): component map, connector setup, identity sync, access request lifecycle, policy simulation, access review campaigns, JML automation, AI agent integration, client SDK architecture, storage schema, where things run. |
| [`docs/PHASES.md`](docs/PHASES.md) | Phase-by-phase exit criteria from Phase 0 (contract & registry) through Phase 10 (full 200-connector catalogue). |
| [`docs/PROGRESS.md`](docs/PROGRESS.md) | Per-connector capability matrix and per-feature platform status. The source of truth for "what's shipped". |
| [`docs/LISTCONNECTORS.md`](docs/LISTCONNECTORS.md) | Unified single-table view of all 200 registered connectors — provider, category, tier, package path, and per-capability status indicators (`sync_identity`, `provision_access`, `list_entitlements`, `get_access_log`, `sso_federation`). Kept in lockstep with the per-tier tables in `PROGRESS.md` §1. |
| [`docs/swagger.json`](docs/swagger.json) / [`docs/swagger.yaml`](docs/swagger.yaml) | OpenAPI 3.0 spec for the HTTP API surface. Regenerated by `scripts/generate-swagger.sh` (supports `--check` for CI drift detection). Also served at `/swagger`, `/swagger.json`, `/swagger.yaml` by the running API server. |

---

## License

Proprietary. See [`LICENSE`](LICENSE) file. All rights reserved.
