# ShieldNet 360 Access Platform

> **Status:** Phase 0 shipped, Phases 1–7 partial. The `AccessConnector` contract, process-global registry, AES-GCM credential manager, `access_connectors` migration, and **all 10 Tier 1 connectors** are in `main`. **Phase 2** lands the request-lifecycle tables, the request state machine, and the request / provisioning / workflow services PLUS the HTTP handler layer for access requests and grants. **Phase 3** lands the `policies` / `teams` / `team_members` / `resources` tables, `PolicyService`, `ImpactResolver`, `ConflictDetector` PLUS the HTTP handler layer for policy drafts, simulate, promote, and test-access. **Phase 4 (partial)** lands the Go-side A2A AI client (`internal/pkg/aiclient`), env-driven access platform config (`internal/config`), AI risk-scoring integration in `AccessRequestService.CreateRequest` and `PolicyService.Simulate`, and `POST /access/explain` + `POST /access/suggest` endpoints — and the Python AI agent itself (`cmd/access-ai-agent/`) now ships with stub skills for `access_risk_assessment`, `access_review_automation`, `access_anomaly_detection`, `connector_setup_assistant`, and `policy_recommendation`. **Phase 5** lands the `access_reviews` / `access_review_decisions` / `access_campaign_schedules` tables, `AccessReviewService`, the Phase 5 HTTP handler layer, the `internal/cron.CampaignScheduler` driving recurring campaigns, AND now the auto-certification rate metric (`GET /access/reviews/:id/metrics`), the admin `PATCH /access/reviews/:id` toggle for `auto_certify_enabled`, and the notification-fan-out scaffold (`internal/services/notification`, `Notifier` interface, in-memory channel) wired into `StartCampaign`. **Phase 6 (partial)** lands the JML service (`internal/services/access.JMLService` with `ClassifyChange` / `HandleJoiner` / `HandleMover` / `HandleLeaver`), the SCIM inbound handler (`POST /scim/Users`, `PATCH /scim/Users/:id`, `DELETE /scim/Users/:id`), the outbound SCIM v2.0 client (`SCIMClient.PushSCIMUser` / `PushSCIMGroup` / `DeleteSCIMResource`), and the Go-side anomaly detection stub (`AnomalyDetectionService.ScanWorkspace` + `DetectAnomaliesWithFallback`). All 10 Tier-1 connectors now compose the generic outbound `SCIMClient` (Microsoft Entra, Google Workspace, Okta, Auth0, Duo, 1Password, LastPass, Ping Identity, plus the SAML / OIDC brokers). **Phase 7 (partial)** lands all 9 Cloud Infrastructure connectors (`aws/`, `azure/`, `gcp/`, `cloudflare/`, `tailscale/`, `digitalocean/`, `heroku/`, `vercel/`, `netlify/`) and the first 5 Collaboration connectors (`slack/`, `ms_teams/`, `zoom/`, `notion/`, `asana/`); each ships pure-local `Validate`, `Connect`, paginated `SyncIdentities`, and `GetCredentialsMetadata` with token redaction. Admin UI, Mobile SDK, Desktop Extension, AI auto-certification wire-in, email / Slack channels, real LLM-backed agent skills, the remaining Phase 7 Tier-2 / Tier-3 categories, and the Phase 1 Admin UI / Keycloak federation exit criteria remain open. See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the per-connector matrix and [`docs/PHASES.md`](docs/PHASES.md) for per-phase exit criteria.

The ShieldNet 360 Access Platform is the access management product within the SN360 ecosystem. It is a multi-tenant platform that lets small and medium-sized businesses connect, manage, and secure access to **200+ cloud platforms, SaaS applications, and identity systems** from a single control plane.

The platform is designed for companies with little or no in-house IT/security headcount. Founders, operations leads, and people-managers can run access end-to-end without writing policy DSLs, decoding SAML metadata, or hand-rolling SCIM payloads.

---

## Quick start

Requirements: Go 1.22+.

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

## Project structure

```
cautious-fishstick/
├── cmd/
│   ├── ztna-api/                  # HTTP API binary (Gin server on ZTNA_API_LISTEN_ADDR, default :8080)
│   ├── access-connector-worker/   # Queue worker (Phase 0 stub)
│   ├── access-workflow-engine/    # LangGraph orchestrator host (Phase 0 stub)
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
│   │   ├── access_request_handler.go           # POST/GET /access/requests, approve|deny|cancel
│   │   ├── access_grant_handler.go             # GET /access/grants (filtered by user_id / connector_id)
│   │   ├── access_review_handler.go            # POST /access/reviews, :id/decisions|close|auto-revoke, GET :id/metrics, PATCH :id
│   │   ├── policy_handler.go                   # POST /workspace/policy + drafts / simulate / promote / test-access
│   │   ├── scim_handler.go                     # Phase 6 inbound SCIM v2.0 — POST/PATCH/DELETE /scim/Users routed into JMLService
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
│   │       ├── slack/             # Slack users.list (cursor) + Enterprise-Grid SAML — Validate, Connect, Sync
│   │       ├── ms_teams/          # Graph /teams/{id}/members + Entra SAML — Validate, Connect, Sync
│   │       ├── zoom/              # Zoom Server-to-Server OAuth + /users — Validate, Connect, Sync
│   │       ├── notion/            # Notion /v1/users (start_cursor) — Validate, Connect, Sync
│   │       └── asana/             # Asana /workspaces/{gid}/users (offset) — Validate, Connect, Sync
│   ├── services/notification/             # Phase 5 NotificationService + Notifier interface + InMemoryNotifier
│   │   └── service.go                     # NotifyReviewersPending / NotifyRequester (best-effort fan-out)
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
│   │   └── access_campaign_schedule.go    # Phase 5 access_campaign_schedules (recurring check-ups)
│   └── migrations/                        # GORM AutoMigrate migrations (no FK constraints)
│       ├── 001_create_access_connectors.go
│       ├── 002_create_access_request_tables.go
│       ├── 003_create_policy_tables.go
│       ├── 004_create_access_review_tables.go
│       └── 005_create_access_campaign_schedules.go
└── docs/                          # Proposal, architecture, phases, progress
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
| 2 | Cloud Infrastructure | 15 | 9 / 15 | **Implemented:** AWS IAM, Azure RBAC, GCP IAM, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify. **Pending:** Vultr, Linode, OVHcloud, Alibaba Cloud, CloudSigma, Wasabi |
| 3 | Business SaaS | 55 | 5 / 55 | **Implemented:** Slack, MS Teams, Zoom, Notion, Asana. **Pending:** Salesforce, HubSpot, Monday, Figma, Miro, Trello, Airtable, Smartsheet, ClickUp, Dropbox Business, Box, GitHub, GitLab, Jira, PagerDuty, Sentry, Zendesk, Freshdesk, Help Scout, … |
| 4 | HR / Finance / Legal | 50 | 0 / 50 | BambooHR, Gusto, Rippling, Personio, Hibob, Workday, Paychex, Deel, Zenefits, Namely, QuickBooks, Xero, Stripe, FreshBooks, Wave, Sage Intacct, Bill.com, Expensify, Plaid, Brex, Ramp, Clio, Ironclad, DocuSign, DocuSign CLM, PandaDoc, HelloSign, MyCase, … |
| 5 | Vertical / Niche | 70 | 0 / 70 | Industry-specific tooling: real estate (Yardi, Buildium, AppFolio), healthcare (Practice Fusion, Kareo, Zocdoc), e-commerce (Shopify, WooCommerce, BigCommerce, Magento, Square), supply chain (NetSuite, SAP Concur, Coupa, Anvyl), training (LinkedIn Learning, Udemy Business, Coursera), analytics (GA4, Heap, FullStory), comms (Twilio, SendGrid, RingCentral, Vonage), automation (Zapier, Make, IFTTT), social (Hootsuite, Sprout Social, Buffer), … |
| | **Total** | **200** | **24 / 200** | |

---

## Tech Stack

| Layer | Stack |
|-------|-------|
| Backend | Go 1.22+, Gin, sqlc, PostgreSQL, Redis, Kafka |
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

---

## License

Proprietary. See [`LICENSE`](LICENSE) file. All rights reserved.
