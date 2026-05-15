# Overview

The ShieldNet 360 Access Platform is a multi-tenant zero-trust access control plane. It lets a small or medium-sized business connect its IdP, cloud accounts, and SaaS apps from one product, then govern who can reach what — with self-service requests, automated reviews, AI-assisted risk decisions, and a hybrid network posture that doesn't force every app through a tunnel.

This page is the conceptual tour. For the local quick start see [`getting-started.md`](getting-started.md); for the service topology and data flows see [`architecture.md`](architecture.md); for the SDK contract see [`sdk.md`](sdk.md).

## Who it's for

- **SME founders and operations leads** who need IdP-grade access governance without a dedicated identity team.
- **IT generalists** who want self-service access requests, periodic reviews, and joiner / mover / leaver automation that actually runs on a schedule.
- **Security architects** who want a single audit envelope across 200 SaaS apps, plus a kill switch that locks a leaver out of every channel — IdP, SaaS sessions, SCIM, and the tunnel — in one call.

## Design principles

- **One connector contract, 200 providers.** Every upstream integration implements the same `AccessConnector` interface. Adding a provider is a bounded, recipe-shaped change — no cross-cutting concerns leak into the connector package.
- **AI-assisted, never AI-only.** Server-side agents risk-score requests, auto-certify routine reviews, and surface anomalies, but every recommendation is observable and overridable. Mobile and desktop clients never run inference on-device.
- **Hybrid by default.** Connectors are auto-classified as `tunnel` (private resource through OpenZiti), `sso_only` (federated through Keycloak), or `api_only` (direct SaaS REST), so SaaS-heavy estates don't pay tunnel overhead they don't need.
- **Wizard-first, not DSL-first.** Operators connect apps and draft access rules through guided UIs with safe-test simulation, not by hand-editing policy DSLs.

## The four pillars

### App connections

Guided setup for 200 providers across IAM/SSO, cloud infrastructure, collaboration, CRM, finance, HR, DevOps, security, and verticals. Each connector covers some subset of:

- **Identity sync** — pull users, groups, and memberships into the platform's `Teams` abstraction.
- **Access provisioning** — push grants out to the provider, idempotently.
- **Entitlement listing** — pull current upstream permissions for a periodic check-up.
- **SSO federation** — broker SAML / OIDC through Keycloak.
- **Access audit** — stream sign-in and permission-change events into the audit pipeline.

See [`connectors.md`](connectors.md) for the per-provider capability matrix.

### Access lifecycle

Every grant goes through the same state machine:

```
Request  →  Risk review  →  Workflow routing  →  Approve  →  Provision
                                                                 │
                                                                 ▼
                                                              Active
                                                                 │
                                                                 ▼
                                                         Periodic re-review
                                                                 │
                                                                 ▼
                                                              Revoke
```

Self-service requests, policy-based auto-approval for low-risk patterns, manager and multi-level approval workflows, periodic access reviews with AI auto-certification of low-risk grants, and SCIM-driven joiner / mover / leaver automation. Grants with `expires_at` set are automatically revoked through the same code path operators use, so time-bounded access is the default rather than an aspiration.

### Access rules with safe-test

Operators draft access rules in the admin UI. Before promotion, the platform simulates the rule against the live world:

- **Impact analysis** — who would gain or lose access, and to which resources.
- **Conflict detection** — flag redundant or contradictory rules against the existing set.
- **AI risk assessment** — over-provisioning, separation-of-duties violations, privilege concentration, stale drafts.

Drafts never reach the OpenZiti dataplane. Promotion to a live rule is one click and idempotent — there is no "create a live rule directly" code path.

### Server-side AI

Five Tier-1 skills run on the Python `access-ai-agent` over the A2A protocol:

| Skill                       | Purpose                                                              |
|-----------------------------|----------------------------------------------------------------------|
| `access_risk_assessment`    | Score requests and policy changes `low / medium / high` with factors.|
| `access_review_automation`  | Auto-certify low-risk grants during a campaign.                      |
| `access_anomaly_detection`  | Flag unusual usage on active grants.                                 |
| `connector_setup_assistant` | Natural-language guidance for connector setup wizards.               |
| `policy_recommendation`     | Suggest rules from org structure and historical access patterns.     |

LangGraph orchestrates multi-step workflows (risk routing, escalation, timeout-based auto-escalation) on the Go `access-workflow-engine`. The mobile and desktop SDKs never call the AI agent directly — they call REST endpoints on `ztna-api` that delegate over A2A.

## Hybrid access

### Per-connector access mode

Every connector is auto-classified at Connect time:

- `tunnel` — private resource fronted by OpenZiti. The platform writes a `ServicePolicy` to the controller.
- `sso_only` — SaaS app federated through Keycloak. The SAML / OIDC redirect *is* the access; the platform never opens a tunnel and never pushes a grant.
- `api_only` — SaaS app reachable directly via REST. The platform pushes grants but skips the tunnel.

Operators can override per connector. The classification surfaces through the policy promotion path so SaaS-heavy estates skip the OpenZiti write entirely.

### Six-layer leaver kill switch

A single off-boarding call locks the user out of every channel the platform knows about, each layer best-effort and idempotent:

1. Revoke all active access grants.
2. Remove team memberships.
3. Disable the Keycloak user (kill SSO at the IdP).
4. Revoke active sessions across every connector implementing `SessionRevoker`.
5. SCIM-deprovision across every connector implementing `SCIMProvisioner`.
6. Disable the OpenZiti identity (kill tunnel access).

Every layer outcome is published as a `LeaverKillSwitchEvent` onto the shared `ShieldnetLogEvent v1` Kafka envelope for SIEM ingestion.

### Unused app-account reconciliation

A daily cron asks every connector "who do you see?" and cross-references the answer against the IdP-side membership pivot. Upstream users with no IdP record land in `access_orphan_accounts` for operator triage (revoke, dismiss, acknowledge). A dry-run mode previews detections without persisting, and a configurable per-connector throttle protects upstream APIs.

### Automatic grant expiry

A cron sweeps every grant whose `expires_at` has passed and revokes through the same path the reviewer flow uses. A separate sweep emits expiry warnings before access goes dark so users can request renewal. Every revoke and warning emits an audit envelope for downstream SIEM.

## Product language

The admin UI, mobile SDK, desktop extension, and audit log use plain-language terminology. Internal code, logs, and metrics use the engineering vocabulary.

| Technical term            | Product language        |
|---------------------------|-------------------------|
| ZTNA policy               | Access rule             |
| Service policy            | Connection permission   |
| Identity provider         | Company directory       |
| SCIM provisioning         | Auto-sync users         |
| Access review campaign    | Access check-up         |
| Entitlement               | App permission          |
| Separation of duties      | Conflict check          |
| Connector                 | App connection          |
| Access certification      | Access check-up         |
| Access grant              | Access                  |
| Risk score                | Risk level              |
| Promote draft policy      | Turn the rule on        |
| Federated SSO             | Single sign-on          |

## Non-goals

- **No on-device inference** on mobile or desktop, today or as a roadmap commitment. The SDK contract is defined so a future "REST + local fallback" mode is non-breaking, but no embedded model ships.
- **No connector-side persistence or scheduling.** Connectors are RPC-shaped: the platform owns the queue, retries, and database.
- **No bespoke identity store.** Keycloak is the broker for federated SSO. The platform does not re-implement OIDC.
- **No operator-facing policy DSL.** Wizards and impact reports are the operator surface; a DSL is power-user territory and would compete with the plain-language goal.

## Where to read next

- [`getting-started.md`](getting-started.md) — bring the local stack up in five minutes.
- [`architecture.md`](architecture.md) — service topology, data model, connector contract.
- [`connectors.md`](connectors.md) — per-provider capability matrix for all 200 connectors.
- [`sdk.md`](sdk.md) — mobile + desktop SDK contract and integration guide.
- [`guides/`](guides/) — platform integration walkthroughs (iOS, Android, Desktop).
