# ShieldNet 360 Access Platform

[![CI](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/ci.yml) [![Python CI](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/python-ci.yml/badge.svg)](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/python-ci.yml)

> **Status:** ~97% complete. See [`docs/PROGRESS.md`](docs/PROGRESS.md) for details.
> - Phases 0, 6, 7, 8, 9, 11: shipped
> - Phases 1–5: backend complete, Admin UI pending (lives in `ztna-frontend`)
> - Phase 10: 200 / 200 connectors registered, advanced caps shipped across 194 (6 n/a), audit logs across 198 (2 n/a), SSO federation across 104 (96 n/a)
> - Phase 11: hybrid access model, 6-layer leaver kill switch, 14 `SessionRevoker` + 14 `SSOEnforcementChecker` connectors

The ShieldNet 360 Access Platform is a multi-tenant zero-trust access control plane. It lets small and medium-sized businesses connect, manage, and secure access to **200+ cloud platforms, SaaS applications, and identity systems** from a single product — without writing policy DSLs, decoding SAML metadata, or hand-rolling SCIM payloads.

---

## Quick start

Requirements: Go 1.25+.

```bash
go mod download
go build ./...
go test -race -timeout=180s ./...

# Run the three backend services locally.
go run ./cmd/ztna-api                   # HTTP API on :8080
go run ./cmd/access-connector-worker    # Queue worker
go run ./cmd/access-workflow-engine     # Workflow engine on :8082
```

Each binary blank-imports the connector packages so their `init()` functions register with the access-platform registry. To enable AI risk scoring, set `ACCESS_AI_AGENT_BASE_URL` and `ACCESS_AI_AGENT_API_KEY`; without them, AI-driven routes return 503 and the request workflow falls back to medium risk (see [PROPOSAL §5.3](docs/PROPOSAL.md)).

---

## How to run tests

```bash
# Go suite — handlers, services, crons, workers, connectors (race-enabled).
go test -race -timeout=180s ./...

# Static checks
go vet ./...

# Swagger drift check
bash scripts/generate-swagger.sh --check

# SN360 user-facing language check (PROPOSAL §8)
bash scripts/check_sn360_language.sh

# Python suite — AI agent skills and HTTP layer
cd cmd/access-ai-agent && pip install -r requirements.txt && python -m pytest tests/ -v
```

The Go pipeline runs on every push and PR. The Python pipeline runs only when `cmd/access-ai-agent/**` changes.

---

## How to run the platform

The repo ships a `docker-compose.yml` that brings up the full backend (Postgres, Redis, `ztna-api`, `access-connector-worker`, `access-workflow-engine`, `access-ai-agent`) with real healthchecks:

```bash
docker compose up --build --wait
```

Default ports: `ztna-api` on `:8080`, `access-workflow-engine` on `:8082`, `access-ai-agent` on `:8090`, Postgres `:5432`, Redis `:6379`. Tear down with `docker compose down -v`.

---

## Project structure

```
cautious-fishstick/
├── cmd/
│   ├── ztna-api/                  # HTTP API (Gin)
│   ├── access-connector-worker/   # Queue worker for sync / provision / revoke / audit jobs
│   ├── access-workflow-engine/    # LangGraph-style orchestration host
│   └── access-ai-agent/           # Python A2A skill server
├── internal/
│   ├── config/                    # Env-driven configuration
│   ├── cron/                      # Background schedulers (identity sync, campaigns, expiry…)
│   ├── handlers/                  # HTTP handler layer
│   ├── migrations/                # GORM migrations
│   ├── models/                    # Database models
│   ├── services/access/           # Core access service + connector framework
│   │   └── connectors/            # 200 provider packages (see docs/LISTCONNECTORS.md)
│   ├── services/notification/     # Email / Slack / WebPush notifiers
│   ├── workers/                   # Worker job handlers
│   └── pkg/                       # Internal libraries (aiclient, credentials, …)
├── sdk/
│   ├── ios/                       # Swift Package — REST client, no on-device inference
│   ├── android/                   # Kotlin library — REST client, no on-device inference
│   └── desktop/                   # Electron IPC module — REST client, no on-device inference
├── deploy/                        # Kubernetes manifests + Helm chart
├── docker/                        # Multi-stage Dockerfiles per Go service
├── scripts/                       # CI guards (swagger drift, SN360 language, model-file ban)
└── docs/                          # Proposal, architecture, phases, progress, OpenAPI spec
```

---

## Core capabilities

### App connections

Guided setup wizards for **200 providers** across IAM/SSO, cloud infrastructure, collaboration, CRM, finance, HR, DevOps, security, and more. Each connector covers some subset of identity sync, access provisioning, entitlement review, SSO federation, and access audit. See [`docs/LISTCONNECTORS.md`](docs/LISTCONNECTORS.md) for the per-provider capability matrix.

### Access lifecycle

Automated **Request → Review → Approve → Provision → Monitor → Review → Revoke** for every grant. Self-service requests with policy-based auto-approval, manager and multi-level workflows, periodic access reviews with auto-certification of low-risk grants, and SCIM-driven joiner / mover / leaver automation.

### Access rules with safe-test

Draft and simulate access rules before promotion. The platform resolves the affected teams, members, and resources, flags conflicts with existing rules, and runs an AI risk assessment. Drafts never reach the OpenZiti dataplane; promotion is one click and idempotent.

### AI-powered intelligence (server-side only)

Server-side AI agents over the A2A protocol provide:

- Risk assessment for new requests and policy changes
- Auto-certification of low-risk grants during reviews
- Anomaly detection on active grants
- Conversational connector setup and policy explanation
- Policy recommendations from org structure and historical usage

Mobile and desktop clients are thin REST / IPC clients — no on-device model inference, ever. Enforced by [`scripts/check_no_model_files.sh`](scripts/check_no_model_files.sh).

### Hybrid access model (Phase 11)

- **Per-connector access mode** — every connector is auto-classified as `tunnel` (private resource, OpenZiti dataplane), `sso_only` (federated through Keycloak), or `api_only` (direct SaaS REST). The platform skips the OpenZiti policy write for `sso_only` / `api_only` rows so a SaaS-heavy estate does not pay tunnel overhead it doesn't need.
- **Unused-app-account reconciler** — a daily cron cross-references upstream SaaS users against the IdP pivot and flags accounts the IdP no longer knows about. Operators triage them in the admin UI (revoke / dismiss / acknowledge).
- **SSO-only enforcement verification** — connectors that federate through Keycloak optionally implement `SSOEnforcementChecker`, so the health endpoint can surface "SSO-only mode is OFF" warnings the operator can fix without leaving the dashboard. **14 connectors** ship today: Salesforce, Google Workspace, Okta, Slack, GitHub, Microsoft, Auth0, Ping Identity, Zendesk, BambooHR, Workday, HubSpot, Dropbox, and Zoom.
- **Six-layer leaver kill switch** — a single off-boarding call now revokes grants, removes team memberships, disables the Keycloak user, revokes upstream sessions across every connector that supports it (`SessionRevoker` ships for **14 connectors**: Okta, Google Workspace, Microsoft, Salesforce, Slack, Auth0, GitHub, Zoom, Zendesk, HubSpot, Dropbox, Jira/Atlassian, Notion, BambooHR), SCIM-deprovisions everywhere it can, and disables the OpenZiti identity. Every layer is best-effort and idempotent, and every layer outcome is published as a `LeaverKillSwitchEvent` onto the same `ShieldnetLogEvent v1` Kafka envelope used by the rest of the audit pipeline.
- **Unused-app-account hardening** — the reconciler exposes a dry-run mode (`POST /access/orphans/reconcile` with `"dry_run": true`) so operators can preview detections without persisting, a configurable per-connector throttle (`ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR`, default `1s`) to protect upstream APIs, and structured `orphan_reconcile_summary` JSON log lines so log aggregators can ingest per-workspace stats without parsing free-form text.
- **Automatic grant expiry** — `GrantExpiryEnforcer` ticks every `ACCESS_GRANT_EXPIRY_CHECK_INTERVAL` (default 1h) and revokes expired grants through the same path the Phase 5 reviewer flow uses. On every successful revoke it fires `SendGrantRevokedNotification` so the affected user is told their access has expired; a separate `RunWarning` sweep emits `SendGrantExpiryWarning` for grants expiring within `ACCESS_GRANT_EXPIRY_WARNING_HOURS` (default `24h`) so users can request renewal before access goes dark. Every revoke / warning emits a `GrantExpiryEvent` audit envelope for downstream SIEM ingestion.

---

## Architecture overview

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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for full diagrams.

---

## Connector coverage

| Tier | Category | Count | Examples |
|------|----------|------:|----------|
| 1 | Core Identity / SSO | 10 | Microsoft Entra ID, Google Workspace, Okta, Auth0 |
| 2 | Cloud Infrastructure | 15 | AWS IAM, Azure RBAC, GCP IAM, Cloudflare |
| 3 | Business SaaS | 55 | Slack, GitHub, Jira, Salesforce |
| 4 | HR / Finance / Legal / Sales / Marketing | 50 | BambooHR, Workday, QuickBooks, Stripe |
| 5 | Vertical / Niche | 70 | CrowdStrike, SentinelOne, Cisco Meraki, OpenAI |
| | **Total** | **200** | |

The full per-provider list with capability columns lives in [`docs/LISTCONNECTORS.md`](docs/LISTCONNECTORS.md).

---

## Tech stack

| Layer | Stack |
|-------|-------|
| Backend | Go 1.25+, Gin, GORM, PostgreSQL, Redis, Kafka |
| Admin frontend | React (Next.js), TypeScript — in [`ztna-frontend`](https://github.com/uneycom/ztna-frontend) |
| Mobile SDK | Swift Package (iOS) + Kotlin library (Android) — REST clients |
| Desktop extension | Electron + TypeScript — IPC module |
| AI agents | Python (A2A protocol) |
| Workflow engine | LangGraph + Go orchestrator |
| Identity broker | Keycloak |
| Dataplane | OpenZiti |
| Infra | Kubernetes, ArgoCD |

---

## Documentation

| Document | What's in it |
|----------|--------------|
| [`docs/PROPOSAL.md`](docs/PROPOSAL.md) | Technical specification: connector contract, registry, lifecycle, policy simulation, AI integration, schema, deployment, SDK contract. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture and data-flow diagrams (Mermaid). |
| [`docs/PHASES.md`](docs/PHASES.md) | Phase-by-phase exit criteria from Phase 0 through Phase 10. |
| [`docs/PROGRESS.md`](docs/PROGRESS.md) | Per-connector capability matrix and per-feature platform status — source of truth for "what's shipped". |
| [`docs/LISTCONNECTORS.md`](docs/LISTCONNECTORS.md) | Unified single-table view of all 200 registered connectors. |
| [`docs/SDK_CONTRACTS.md`](docs/SDK_CONTRACTS.md) | Mobile SDK + Desktop Extension API contracts and integration guide. |
| [`docs/swagger.json`](docs/swagger.json) / [`docs/swagger.yaml`](docs/swagger.yaml) | OpenAPI 3.0 spec for the HTTP API. Served at `/swagger`, `/swagger.json`, `/swagger.yaml`. |

---

## License

Proprietary. See [`LICENSE`](LICENSE). All rights reserved.
