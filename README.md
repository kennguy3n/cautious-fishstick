# ShieldNet 360 Access Platform

[![CI](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/ci.yml)
[![Python CI](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/python-ci.yml/badge.svg)](https://github.com/kennguy3n/cautious-fishstick/actions/workflows/python-ci.yml)

A multi-tenant zero-trust access control plane for small and medium-sized businesses. Connect your IdP, cloud accounts, and SaaS apps in one place. Govern who can reach what with self-service requests, automated reviews, and AI-assisted risk decisions — without writing policy DSLs, decoding SAML metadata, or hand-rolling SCIM payloads.

The connector framework ships with **200 registered providers** spanning identity, cloud infrastructure, business SaaS, HR and finance, security, and verticals. See [`docs/connectors.md`](docs/connectors.md) for the full capability matrix.

---

## Quick start

Prerequisites: Go 1.25+, Docker (Compose v2), and Python 3.12+ for the AI sidecar.

```bash
git clone https://github.com/kennguy3n/cautious-fishstick.git
cd cautious-fishstick

# Run the test suite
make test

# Bring up the full backend (Postgres, Redis, all four services)
make docker-up
```

Default ports once the stack is up. The `pam-gateway` PostgreSQL, MySQL, and K8s proxy listeners stay bound to their canonical port numbers *inside* the container (5432 / 3306 / 8443) so the upstream protocol clients can drop in unmodified, but `docker-compose.yml` maps them to the host on shifted ports (`15432` / `13306` / `18443`) so they cannot collide with the dev-stack `Postgres` on 5432. The SSH listener and the combined health / SQL-WS port still map 1:1 (`2222` and `8081`). Production deployments map the proxy ports onto the dataplane LB without the shift (see [`docs/pam/architecture.md`](docs/pam/architecture.md) §9).

| Service                                                 | Host port | Container port |
|---------------------------------------------------------|-----------|----------------|
| `ztna-api`                                              | 8080      | 8080           |
| `access-workflow-engine`                                | 8082      | 8082           |
| `access-ai-agent`                                       | 8090      | 8090           |
| `pam-gateway` (SSH)                                     | 2222      | 2222           |
| `pam-gateway` (health + SQL WS)                         | 8081      | 8081           |
| `pam-gateway` (PostgreSQL proxy)                        | 15432     | 5432           |
| `pam-gateway` (MySQL / MariaDB proxy)                   | 13306     | 3306           |
| `pam-gateway` (K8s exec / HTTPS)                        | 18443     | 8443           |
| Postgres                                                | 5432      | 5432           |
| Redis                                                   | 6379      | 6379           |

Tear down with `make docker-down`. A five-minute walkthrough lives at [`docs/getting-started.md`](docs/getting-started.md).

---

## What's inside

### App connections
Guided setup for 200 providers across IAM/SSO, cloud, collaboration, CRM, finance, HR, DevOps, and security. Each connector covers some subset of identity sync, access provisioning, entitlement listing, SSO federation, and access audit. The complete matrix lives in [`docs/connectors.md`](docs/connectors.md).

### Access lifecycle
**Request → Review → Approve → Provision → Monitor → Re-review → Revoke** for every grant. Self-service requests with policy-based auto-approval, manager and multi-level workflows, periodic access reviews with auto-certification of low-risk grants, and SCIM-driven joiner / mover / leaver automation.

### Access rules with safe-test
Draft and simulate access rules before promotion. The platform resolves affected teams, members, and resources; flags conflicts with existing rules; and runs an AI risk assessment. Drafts never reach the dataplane — promotion is one click and idempotent.

### Server-side AI
Server-side AI agents over the A2A protocol provide risk assessment, auto-certification, anomaly detection, conversational connector setup, and policy recommendations. **No on-device inference, ever** — mobile and desktop clients are thin REST / IPC clients, enforced in CI by [`scripts/check_no_model_files.sh`](scripts/check_no_model_files.sh).

### Hybrid access
Connectors are auto-classified as `tunnel` (private resource via OpenZiti), `sso_only` (federated through Keycloak), or `api_only` (direct SaaS REST), so SaaS-heavy estates don't pay tunnel overhead they don't need. A six-layer leaver kill switch revokes grants, team memberships, the Keycloak user, upstream sessions, SCIM provisioning, and the OpenZiti identity in a single off-boarding call — every layer best-effort, idempotent, and audited.

### Privileged Access Management (PAM)
Identity-first privileged-access broker for SMEs. The PAM module ships an asset and account inventory, a secret broker with AES-GCM envelope encryption and step-up MFA on reveal, and JIT leases wired through the existing access-request state machine. The standalone `pam-gateway` binary brokers SSH (short-lived CA-signed certificates with credential-injection fallback), `kubectl exec` over WebSocket, and PostgreSQL / MySQL wire-protocol proxies — each session is recorded to S3, each command is captured with an output hash, and every command is filtered in real-time by the policy engine (`allow` / `deny` / `step_up`). The `PAMAuditService` ships immutable session events on the existing Kafka `ShieldnetLogEvent` envelope and issues 15-minute pre-signed replay URLs for the future replay UI. The `pam_session_risk_assessment` A2A skill scores each lease request against unusual-time, first-time-asset, repeated-denials, and emergency-access-rate factors. The iOS + Android SDKs ship matching `PAMSDKClient` surfaces for push-driven approver flows (number matching + passkey step-up). Full design and roadmap live in [`docs/pam/`](docs/pam/).

---

## Architecture

```
Admin UI (React)              ┐
Mobile SDK (iOS / Android)    ├──REST──▶ ZTNA Business Layer (Go)
Desktop Extension (Electron)  ┘                  │
                                                 ├──▶ PostgreSQL  (access_*, policies)
                                                 ├──▶ Redis       (queues, staging, locks)
                                                 ├──▶ Keycloak    (SSO federation)
                                                 ├──▶ OpenZiti    (ServicePolicy)
                                                 ├──▶ Kafka       (audit envelope)
                                                 └──▶ Access Connector Worker
                                                          │
                                                          └──▶ Access Connectors (200 providers)

ZTNA Business Layer ◀──A2A──▶ Access AI Agent (Python)
ZTNA Business Layer ◀──HTTP─▶ Access Workflow Engine
```

See [`docs/architecture.md`](docs/architecture.md) for the full diagrams, service contracts, and data model.

---

## Project layout

```
cautious-fishstick/
├── cmd/
│   ├── ztna-api/                  # HTTP API (Gin)
│   ├── access-connector-worker/   # Queue worker (sync / provision / revoke / audit)
│   ├── access-workflow-engine/    # LangGraph-style orchestration host
│   ├── access-ai-agent/           # Python A2A skill server
│   └── pam-gateway/               # PAM SSH gateway (cert / credential injection)
├── internal/
│   ├── config/                    # Env-driven configuration
│   ├── cron/                      # Schedulers (sync, campaigns, expiry)
│   ├── handlers/                  # HTTP handlers
│   ├── migrations/                # GORM migrations
│   ├── models/                    # Database models
│   ├── services/access/           # Access service + connector framework
│   │   └── connectors/            # 200 provider packages
│   ├── services/pam/              # PAM asset / secret / lease / session /
│   │                              # audit / command-policy services
│   ├── gateway/                   # PAM gateway library (SSH / K8s / PG /
│   │                              # MySQL listeners, recorder, command
│   │                              # parser, policy evaluator, SQL WS handler)
│   ├── services/notification/     # Email / Slack / WebPush notifiers
│   ├── workers/                   # Worker job handlers
│   └── pkg/                       # Shared libraries (aiclient, credentials, …)
├── sdk/
│   ├── ios/                       # Swift Package — REST client
│   ├── android/                   # Kotlin library — REST client
│   └── desktop/                   # Electron IPC module — REST client
├── deploy/                        # Kubernetes manifests + Helm chart
├── docker/                        # Multi-stage Dockerfiles per service
├── scripts/                       # CI guards
└── docs/                          # Architecture, guides, OpenAPI spec
```

---

## Connector coverage

| Tier | Category                                  | Count | Examples                                              |
|------|-------------------------------------------|------:|-------------------------------------------------------|
| 1    | Core Identity / SSO                       | 10    | Microsoft Entra ID, Google Workspace, Okta, Auth0     |
| 2    | Cloud Infrastructure                      | 15    | AWS IAM, Azure RBAC, GCP IAM, Cloudflare              |
| 3    | Business SaaS                             | 55    | Slack, GitHub, Jira, Salesforce                       |
| 4    | HR / Finance / Legal / Sales / Marketing  | 50    | BambooHR, Workday, QuickBooks, Stripe                 |
| 5    | Vertical / Niche                          | 70    | CrowdStrike, SentinelOne, Cisco Meraki, OpenAI        |
|      | **Total**                                 | **200** |                                                    |

The full per-provider matrix lives in [`docs/connectors.md`](docs/connectors.md).

Optional capability interfaces are layered on top of the base contract where the upstream provider exposes the underlying API. Current coverage:

| Optional interface       | Implementations |
|--------------------------|----------------:|
| `SCIMProvisioner`        |              21 |
| `GroupSyncer`            |              17 |
| `SessionRevoker`         |              18 |
| `SSOEnforcementChecker`  |              19 |
| `IdentityDeltaSyncer`    |               6 |

These counts are enforced by `internal/services/access/registry_count_test.go` and detailed per-provider in [`docs/connectors.md`](docs/connectors.md#optional-capability-interfaces).

---

## Tech stack

| Layer              | Stack                                                        |
|--------------------|--------------------------------------------------------------|
| Backend            | Go 1.25+, Gin, GORM, PostgreSQL, Redis, Kafka                |
| Admin frontend     | React (Next.js), TypeScript — [`ztna-frontend`](https://github.com/uneycom/ztna-frontend) |
| Mobile SDKs        | Swift Package (iOS), Kotlin library (Android)                |
| Desktop extension  | Electron + TypeScript                                        |
| AI agents          | Python (A2A protocol)                                        |
| Workflow engine    | LangGraph + Go orchestrator                                  |
| Identity broker    | Keycloak                                                     |
| Dataplane          | OpenZiti                                                     |
| Infrastructure     | Kubernetes, ArgoCD                                           |

---

## Documentation

| Document                                                | What's in it                                              |
|---------------------------------------------------------|-----------------------------------------------------------|
| [`docs/overview.md`](docs/overview.md)                   | Product overview, goals, and how the pieces fit together. |
| [`docs/architecture.md`](docs/architecture.md)           | Service topology, data model, and request lifecycles.     |
| [`docs/getting-started.md`](docs/getting-started.md)     | Five-minute local stack walkthrough.                      |
| [`docs/connectors.md`](docs/connectors.md)               | Per-provider capability matrix (all 200 connectors).      |
| [`docs/pam/`](docs/pam/)                                 | PAM module: proposal, architecture, and roadmap.          |
| [`docs/sdk.md`](docs/sdk.md)                             | Mobile + Desktop SDK contract and integration guide.      |
| [`docs/guides/`](docs/guides/)                           | Platform integration walkthroughs (iOS, Android, Desktop).|
| [`docs/swagger.yaml`](docs/swagger.yaml)                 | OpenAPI 3.0 spec for the HTTP API.                        |
| [`cmd/README.md`](cmd/README.md)                         | Per-binary catalogue (ports, env vars) for `ztna-api`, `access-connector-worker`, `access-workflow-engine`, `access-ai-agent`. |
| [`docker/README.md`](docker/README.md)                   | Dockerfile catalogue + two-stage build pattern.            |
| [`deploy/README.md`](deploy/README.md)                   | Kubernetes deployment (raw + Kustomize + Helm).            |

---

## Contributing

We welcome bug reports, feature requests, and pull requests. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) for prerequisites, the local dev loop, and how to add a new connector.

---

## License

See [`LICENSE`](LICENSE). All rights reserved.
