# ShieldNet 360 Access Platform — Phase Definitions & Exit Criteria

This document collects the planned milestones in one place so reviewers and operators share a vocabulary. A phase is **shippable** only when *all* its exit criteria are demonstrably met. Phases stack: a later phase assumes the invariants of every earlier phase.

| Status legend |  |
|---------------|--|
| ✅ shipped | The phase is in `main` and exercised in production |
| 🟡 partial | Some exit criteria met; gaps tracked in `PROGRESS.md` §3 |
| ⏳ planned | Not yet started |

## Phase summary

| Phase | Title | Status |
|------:|-------|:------:|
| 0 | Access connector contract & registry | ✅ |
| 1 | Core Identity connectors (top 10) | 🟡 |
| 2 | Access request workflow | 🟡 |
| 3 | Policy simulation & testing | 🟡 |
| 4 | Server-side AI integration | 🟡 |
| 5 | Access review campaigns | 🟡 |
| 6 | JML automation & SCIM outbound | ✅ |
| 7 | Connector scale-out (200 providers) | ✅ |
| 8 | Workflow orchestration | ✅ |
| 9 | Mobile / Desktop SDKs | ✅ |
| 10 | Advanced connector capabilities | 🟡 |

Phases 1–5 are 🟡 because the backend is complete in every case; only the Admin UI surfaces (in [`ztna-frontend`](https://github.com/uneycom/ztna-frontend)) remain. Phase 10 is 🟡 because the long-tail advanced-capability work is still in progress: 194 / 200 connectors ship real `ProvisionAccess` / `RevokeAccess` / `ListEntitlements` (6 n/a), 198 / 200 ship the audit pipeline (2 n/a), and 104 / 200 are SSO-federated (96 n/a — many providers have no native SSO metadata API).

---

## Phase 0 — Access connector contract & registry  ✅

Define the `AccessConnector` interface and the global registry; every binary that needs access connectors imports the provider packages for their `init()` side-effects.

- [x] `AccessConnector` interface with the core capability surface (validate / connect / verify permissions / count identities / sync identities / provision / revoke / list entitlements / SSO metadata / credentials metadata).
- [x] Optional `IdentityDeltaSyncer`, `GroupSyncer`, `AccessAuditor`, `SCIMProvisioner` interfaces.
- [x] Process-global registry with `RegisterAccessConnector` / `GetAccessConnector` and a safe `t.Cleanup` test-swap pattern.
- [x] AES-GCM credential encryption.
- [x] Blank-import wiring across all three Go binaries.
- [x] `access_connectors` table and migration.

---

## Phase 1 — Core Identity connectors (top 10)  🟡

First 10 identity connectors, each with the minimum capability needed to power access requests downstream.

- [x] Ten Tier-1 connectors landed: Microsoft Entra ID, Google Workspace, Okta, Auth0, Generic SAML, Generic OIDC, Duo Security, 1Password, LastPass, Ping Identity.
- [x] Each connector implements at minimum validate / connect / sync identities / credentials metadata.
- [x] Each connector's `Validate` is pure-local (no I/O), enforced by a per-connector unit test.
- [x] SSO federation via Keycloak (SAML / OIDC) wired for every Tier-1 connector that exposes metadata.
- [ ] Admin UI: connector marketplace page with a setup wizard per connector.

---

## Phase 2 — Access request workflow  🟡

Basic access request lifecycle without AI in the path. Self-service and manager approval only.

- [x] `access_requests`, `access_request_state_history`, `access_grants`, `access_workflows` tables and migrations.
- [x] `AccessRequestService` and `AccessProvisioningService` with connector-based provision / revoke.
- [x] State machine for `requested → approved → provisioning → provisioned → active → revoked`.
- [x] Self-service workflow (auto-approve on active policy match) and manager-approval workflow.
- [x] HTTP handlers for the full request lifecycle plus active grants.
- [x] Mobile SDK + Desktop Extension access-request API contracts.
- [ ] Admin UI: access request management page.

---

## Phase 3 — Policy simulation & testing  🟡

Draft policies, impact analysis, and the promotion flow. No AI yet — that lands in Phase 4.

- [x] `policies.is_draft` and `policies.draft_impact` columns plus `policies`, `teams`, `team_members`, `resources` tables.
- [x] Draft create / list / get / simulate / promote / test-access endpoints.
- [x] Impact analysis: resolve affected Teams → Members → Resources via attribute and resource selectors.
- [x] Conflict detection against existing live policies (`redundant`, `contradictory`).
- [x] Drafts never reach the OpenZiti dataplane until promotion — covered by tests.
- [ ] Admin UI: policy simulator page with before / after comparison.

---

## Phase 4 — Server-side AI integration  🟡

AI agents for risk assessment, policy recommendation, and connector setup assistance — all server-side.

- [x] Python A2A skill server hosting `access_risk_assessment`, `connector_setup_assistant`, `policy_recommendation` (LLM-backed with deterministic fallbacks).
- [x] AI risk scoring integrated into the access request workflow (defaults to medium on AI failure).
- [x] AI risk assessment integrated into policy simulation.
- [x] Natural-language policy explanation and resource-suggestion endpoints.
- [x] Mobile SDK + Desktop Extension AI-query API contracts (REST-only, no on-device inference; enforced in CI).
- [ ] Admin UI: AI assistant chat interface.

---

## Phase 5 — Access review campaigns  🟡

Periodic access certification with AI-assisted automation.

- [x] `access_reviews` and `access_review_decisions` tables and `AccessReviewService` (start / submit decision / close / auto-revoke).
- [x] HTTP handlers for the full review lifecycle plus per-campaign metrics.
- [x] AI auto-certification via `access_review_automation` agent skill with deterministic fallback.
- [x] Scheduled campaigns with configurable frequency and skip dates.
- [x] Auto-certification rate as a per-campaign metric; admin toggle per resource category.
- [x] Notification channels: in-memory (dev), email (SMTP), Slack (webhook), WebPush — production-wired behind feature flags.
- [ ] Admin UI: review campaign management with bulk approve / revoke and per-grant detail.

---

## Phase 6 — JML automation & SCIM outbound  ✅

Joiner-Mover-Leaver automation end-to-end, plus outbound SCIM provisioning.

- [x] **Joiner.** SCIM user creation → default Teams → bulk-create approved access requests → fan-out provisioning.
- [x] **Mover.** SCIM group / attribute change → atomic batch of revokes + provisions (no partial-access window).
- [x] **Leaver.** SCIM deactivation → bulk-revoke → remove from Teams → disable OpenZiti identity.
- [x] Outbound SCIM v2.0 push: generic `SCIMClient` plus `SCIMProvisioner` composition across all 10 Tier-1 connectors.
- [x] `access_anomaly_detection` agent skill — cross-grant baseline, off-hours, geographic-outlier, and unused-high-privilege detectors.

---

## Phase 7 — Connector scale-out (200 providers)  ✅

Catalogue grows from 10 to **200 connectors** across all categories. Every connector ships the minimum capability surface plus the canonical 7-test suite.

- [x] **Tier 1 — Core Identity** (10 / 10).
- [x] **Tier 2 — Cloud Infrastructure** (15 / 15): AWS, Azure, GCP, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify, Vultr, Linode, OVHcloud, Alibaba, CloudSigma, Wasabi.
- [x] **Tier 3 — Business SaaS** (55 / 55): collaboration, CRM, finance, DevOps, support, observability, communications.
- [x] **Tier 4 — HR / Finance / Legal / Sales / Marketing** (50 / 50).
- [x] **Tier 5 — Vertical / Niche** (70 / 70): security tooling, GenAI, vertical SaaS, e-commerce, web platforms, analytics, social.

See [`LISTCONNECTORS.md`](LISTCONNECTORS.md) for the full per-provider matrix.

---

## Phase 8 — Workflow orchestration  ✅

LangGraph-style workflow engine for multi-step approval and provisioning flows.

- [x] Engine binary on `:8082` with `/health` and `POST /workflows/execute`.
- [x] `WorkflowExecutor` supporting four step types: `auto_approve`, `manager_approval`, `security_review`, `multi_level`.
- [x] Risk-based routing: low → self-service, medium → manager approval, high / sensitive → security review.
- [x] Linear pipeline runtime with `StepPerformer`, durable step state, retry / DLQ (3 attempts, exponential backoff).
- [x] DAG runtime: `WorkflowStepDefinition.Next` / `Join` plus topological execution with goroutine-parallel branches and Kahn cycle / out-of-range / self-loop validation.
- [x] Four seeded workflow templates: new-hire onboarding, contractor onboarding, role change, project access.
- [x] Timeout-driven escalation with CAS-protected fan-out and best-effort notifications.

---

## Phase 9 — Mobile / Desktop SDKs  ✅

Real HTTP-client implementations and publishing manifests for the SDK contracts shipped in Phase 2 / Phase 4.

- [x] iOS `URLSessionAccessSDKClient` (Foundation-only) plus SwiftUI sample app.
- [x] Android `OkHttpAccessSDKClient` (library-free JSON via `org.json`) plus Compose sample app.
- [x] Desktop `registerAccessIPC` + `registerAccessRenderer` (Electron `ipcMain.handle` + `contextBridge` + real `fetch`).
- [x] Per-platform `PUBLISHING.md`, `CHANGELOG.md`, and tag-triggered release workflows.
- [x] Host-app integration guides for each platform.
- [x] CI guard: no model files (`.mlmodel` / `.tflite` / `.onnx` / `.gguf`) anywhere under `sdk/`.

---

## Phase 10 — Advanced connector capabilities  🟡

Beyond the minimum capabilities of Phase 7: real `ProvisionAccess` / `RevokeAccess` / `ListEntitlements` / `AccessAuditor` / SSO federation across the catalogue.

- [x] **Advanced provisioning** (194 / 200 ✅; 6 n/a): every wired connector ships idempotent provision / revoke / list-entitlements with happy + failure tests against httptest mocks. `n/a` rows are providers where the capability does not apply (audit-only or SSO-only).
- [x] **Access audit pipeline** (198 / 200 ✅; 2 n/a): every connector that exposes audit data emits the canonical `ShieldnetLogEvent v1` envelope to the `access_audit_logs` Kafka topic. Generic SAML / Generic OIDC are `n/a` (SSO-only).
- [x] **SSO federation** (104 / 200 ✅; 96 n/a): every provider with a native SAML / OIDC metadata endpoint is brokered through Keycloak. `n/a` rows are providers without one.

---

## Phase 11 — Hybrid Access & Offboarding Safety Net  🟢

Phase 11 introduces an access-mode classification per connector, an
"unused app account" reconciler, SSO-only enforcement verification,
session revocation, a five-layer leaver kill switch, and automatic
grant-expiry enforcement (docs/PROPOSAL.md §13).

### WS1 — Per-connector access mode

- [x] `access_connectors.access_mode` column (values: `tunnel`,
  `sso_only`, `api_only`), default `api_only`.
- [x] Migration 014 / model index updated; no FOREIGN KEY constraints.
- [x] Auto-classification at Connect time (SSO metadata + Keycloak
  federation → `sso_only`; private connector_type → `tunnel`).
- [x] `PATCH /access/connectors/:id` accepts `access_mode` with enum
  validation.
- [x] `PolicyService.Promote` surfaces `access_mode` so downstream
  ztna-business-layer can skip the OpenZiti ServicePolicy write.

### WS2 — Orphan account reconciler

- [x] `access_orphan_accounts` table + model + migration.
- [x] `OrphanReconciler.ReconcileWorkspace` cross-references upstream
  `SyncIdentities` against `team_members.external_id`.
- [x] `RevokeOrphan` / `DismissOrphan` / `AcknowledgeOrphan` /
  `ListOrphans` service methods.
- [x] `OrphanReconcilerScheduler` cron wired into
  `access-connector-worker` with `ACCESS_ORPHAN_RECONCILE_INTERVAL`
  (default 24h).
- [x] `GET /access/orphans`, `POST /access/orphans/:id/revoke`,
  `POST /access/orphans/:id/dismiss`, `POST /access/orphans/reconcile`
  handlers using the SN360 "unused app accounts" envelope.
- [x] httptest-driven unit tests for reconciler, handler, scheduler.

### WS3 — SSO-only enforcement verification

- [x] `SSOEnforcementChecker` optional capability interface.
- [x] Top-6 implementations (Salesforce, Google Workspace, Okta,
  Slack, GitHub, Microsoft) with happy + failure tests.
- [x] Health endpoint surfaces `sso_enforcement_status`.
- [x] Orphan reconciler re-checks SSO enforcement on `sso_only`
  connectors daily.

### WS4 — Session revocation

- [x] `SessionRevoker` optional capability interface.
- [x] Top-7 implementations (Okta, Google Workspace, Microsoft,
  Salesforce, Slack, Auth0, GitHub) with happy + failure tests.
- [x] `SSOFederationService.DisableKeycloakUser` +
  `KeycloakClient.UpdateUser` added with tests.

### WS5 — Enhanced leaver flow (five-layer kill switch)

- [x] `JMLService.HandleLeaver` extended to call, in order: revoke
  grants → remove memberships → disable Keycloak user → revoke
  sessions across connectors → SCIM-deprovision across connectors →
  disable OpenZiti identity.
- [x] Pre-deletion snapshot of connector → external-id pivot so the
  later kill-switch layers retain the IDs they need after team
  memberships are removed.
- [x] All layers are best-effort; failures in one do not block the
  next. Idempotent on re-run.

### WS6 — Grant expiry enforcer

- [x] `GrantExpiryEnforcer` cron job (Phase 11 automation) added.
- [x] `ACCESS_GRANT_EXPIRY_CHECK_INTERVAL` configuration knob (default
  1h) and `access-connector-worker` wiring.
- [x] httptest-driven tests verifying expired grants get revoked and
  non-expired grants do not.

### WS7 — Documentation

- [x] PROPOSAL §13 (Hybrid Access Model).
- [x] PHASES.md Phase 11 section (this section).
- [x] ARCHITECTURE.md §12 (Hybrid Access Model & kill switch flow).
- [x] PROGRESS.md Phase 11 rows + changelog.
- [x] README.md feature list updated.

---

## Cross-cutting exit criteria for *every* phase

Independent of which phase a PR contributes to, the following must hold before merge:

- [ ] All affected `*_test.go` updated. New behavior has at least one happy-path + one failure-path test.
- [ ] No secret / token / PII logged. Sensitive payloads are sanitized before logging.
- [ ] No `c.Param` / `c.Query` direct usage in handlers (use `handlers.GetStringParam` / `handlers.GetPtrStringQuery`).
- [ ] No `FOREIGN KEY` constraints introduced.
- [ ] No new index without a documented query pattern.
- [ ] No raw SQL — GORM only.
- [ ] Translation keys added for any new operator-facing message.
- [x] **SN360 language alignment** verified by `scripts/check_sn360_language.sh`.
- [x] **Swagger drift** check via `scripts/generate-swagger.sh --check`.
- [x] **Client-side AI rule** — no model files anywhere under `sdk/`, enforced by `scripts/check_no_model_files.sh`.
