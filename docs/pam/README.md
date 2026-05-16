# ShieldNet PAM — Privileged Access Management

## What is ShieldNet PAM

ShieldNet PAM is an identity-first privileged access broker built as a native extension of the ShieldNet 360 Access Platform. It adds brokered privileged sessions, secret lifecycle management, just-in-time access, and immutable audit evidence to the existing access control plane — without requiring a separate product, a separate mental model, or a dedicated IT team.

Designed for SMEs: extremely automated, compliant by default, and explainable in plain language.

## Product principle

Identity-first by default. Secret-aware when necessary. Browser-first where possible. Native-bridge only for high-value edge cases. Passkey primary. OTP fallback. Explain everything in plain language.

## How it fits into ShieldNet 360

ShieldNet PAM = ShieldNet Access Privileged + ShieldNet Defense Evidence.

Privileged access is not a silo — it's a higher-assurance mode inside ShieldNet's existing access layer. Every privileged request, approval, session, secret event, and anomalous command becomes structured telemetry for ShieldNet Defense and plain-language operator workflows.

The PAM module reuses:

- The existing `AccessConnector` contract and registry pattern ([`internal/services/access/types.go`](../../internal/services/access/types.go))
- The existing `AccessRequestService` state machine ([`internal/services/access/request_service.go`](../../internal/services/access/request_service.go)) and workflow engine ([`cmd/access-workflow-engine`](../../cmd/access-workflow-engine))
- The existing AI risk assessment skills over A2A ([`cmd/access-ai-agent`](../../cmd/access-ai-agent))
- PostgreSQL, Redis, Kafka infrastructure
- Keycloak for identity federation
- OpenZiti for tunnel-mode assets
- The React admin console in [`ztna-frontend`](https://github.com/uneycom/ztna-frontend)
- Mobile SDKs (Swift/Kotlin) for push approval and passkey

## Documentation index

| Document | Purpose |
|---|---|
| [proposal.md](proposal.md) | Feature proposal — scope, requirements, what ships and what doesn't |
| [architecture.md](architecture.md) | Technical architecture — services, data model, protocols, integration points |
| [progress.md](progress.md) | Development progress tracker — phased milestones with checklist items |

## Quick orientation

PAM-specific code will live under:

- `internal/services/pam/` — core PAM services (session broker, secret broker, audit evidence, asset inventory)
- `internal/handlers/pam_*.go` — HTTP handlers for `/pam/*` routes
- `internal/models/pam_*.go` — GORM models for PAM tables
- `internal/workers/handlers/pam_*.go` — queue job handlers for PAM async work
- `internal/cron/pam_*.go` — PAM-specific schedulers (rotation, hygiene, lease expiry)
- `cmd/pam-gateway/` — Go binary for SSH, K8s, and DB session brokering
- `cmd/access-ai-agent/skills/pam_*.py` — PAM-specific AI skills

PAM extends the existing `ztna-api` router via new `Dependencies` fields (following the nil-safe pattern in [`internal/handlers/router.go`](../../internal/handlers/router.go)) and adds one new binary (`pam-gateway`) for protocol-level session brokering.

## Where to read next

- [proposal.md](proposal.md) — feature scope, phasing, and design constraints.
- [architecture.md](architecture.md) — service map, data model, protocol flows.
- [progress.md](progress.md) — phased milestone checklist.
- [`../overview.md`](../overview.md) — product overview for the wider ShieldNet 360 Access Platform.
- [`../architecture.md`](../architecture.md) — existing platform architecture that PAM extends.
