# ShieldNet 360 Access Platform — Phase Definitions & Exit Criteria

This document collects the planned milestones in one place so PR reviewers and operators have a shared vocabulary. The phase model intentionally mirrors `shieldnet360-backend/docs/connectors/PHASES.md`.

A phase is **shippable** only when *all* of its exit criteria are demonstrably met (test, runbook, metric, or migration as appropriate). Phases stack: a later phase assumes the invariants of every earlier phase.

| Status legend |  |
|---------------|--|
| ✅ shipped | The phase is in `main` and exercised in production |
| 🟡 partial | Some exit criteria met; gaps tracked in `PROGRESS.md` |
| ⏳ planned | Not yet started |

> **Phase 0 is `✅ shipped`; Phase 1 is `🟡 partial`** (3 of 10 connectors landed with minimum capabilities). Later phases remain `⏳ planned`. As phases land, flip the marker and move the supporting status row in `PROGRESS.md`.

---

## Phase 0 — Access Connector contract & registry  ✅ shipped

**Scope.** Define the `AccessConnector` interface and the global registry; every binary that needs access connectors imports the provider packages for their `init()` side-effects.

**Exit criteria.**

- [x] `AccessConnector` interface with `Validate / Connect / VerifyPermissions / CountIdentities / SyncIdentities / ProvisionAccess / RevokeAccess / ListEntitlements / GetSSOMetadata / GetCredentialsMetadata`.
- [x] Optional `IdentityDeltaSyncer`, `GroupSyncer`, `AccessAuditor`, `SCIMProvisioner` interfaces.
- [x] Process-global registry with `RegisterAccessConnector` / `GetAccessConnector` (mirror of `shieldnet360-backend/internal/services/connectors/factory.go:9-32`).
- [x] AES-GCM credential encryption reused from SN360's `internal/pkg/credentials/manager.go`.
- [x] Blank-import wiring in `cmd/ztna-api`, `cmd/access-connector-worker`, `cmd/access-workflow-engine`.
- [x] Unit-test pattern for swapping registry entries safely (`t.Cleanup` restoring the previous instance).
- [x] `access_connectors` table and migration.

**Reference.** `internal/services/access/types.go`, `internal/services/access/factory.go` (target paths).

---

## Phase 1 — Core Identity connectors (top 10)  🟡 partial

**Scope.** First 10 identity connectors, each with the minimum capability needed to power access requests downstream.

**Exit criteria.**

- [x] **Microsoft Entra ID** connector (extends existing ZTNA IdP integration). — 🟡 minimum capabilities only (`Validate`, `Connect`, `VerifyPermissions`, `CountIdentities`, `SyncIdentities`, `SyncIdentitiesDelta`, `GroupSyncer`, `GetSSOMetadata`, `GetCredentialsMetadata`).
- [x] **Google Workspace** connector. — 🟡 minimum capabilities only.
- [x] **Okta** connector. — 🟡 minimum capabilities only (`SyncIdentitiesDelta` via system log polling).
- [ ] **Auth0** connector.
- [ ] **Generic SAML** connector (covers 60 %+ of enterprise SaaS that have no custom API).
- [ ] **Generic OIDC** connector.
- [ ] **Duo Security** connector.
- [ ] **1Password** connector.
- [ ] **LastPass** connector.
- [ ] **Ping Identity** connector.
- [x] Each landed connector implements at minimum: `Validate`, `Connect`, `SyncIdentities`, `GetCredentialsMetadata`.
- [x] Each landed connector's `Validate` is pure-local (no I/O), enforced by a per-connector unit test.
- [ ] Admin UI: connector marketplace page with a setup wizard per connector.
- [ ] First-class SSO federation via Keycloak for SAML / OIDC / Microsoft Entra ID / Google Workspace.

---

## Phase 2 — Access request workflow  ⏳

**Scope.** Basic access request lifecycle without AI in the path. Self-service and manager approval only.

**Exit criteria.**

- [ ] `access_requests`, `access_request_state_history`, `access_grants`, `access_workflows` tables and migrations.
- [ ] `AccessRequestService` with `CreateRequest`, `ApproveRequest`, `DenyRequest`, `CancelRequest`.
- [ ] `AccessProvisioningService` with connector-based `ProvisionAccess` / `RevokeAccess`.
- [ ] State machine for the request lifecycle (`requested → approved → provisioning → provisioned → active → revoked`), implemented in the pattern of `ztna-business-layer/internal/state_machine/`.
- [ ] Self-service workflow (auto-approve when an active policy match exists).
- [ ] Manager approval workflow (single-step, manager resolved through manager-link pass).
- [ ] Admin UI: access request management page (list / approve / deny / view audit trail).
- [ ] Mobile SDK: access request API contract defined and published to the internal package registry.
- [ ] Desktop Extension: access request IPC contract defined and published as an internal npm package.

---

## Phase 3 — Policy simulation & testing  ⏳

**Scope.** Draft policies, impact analysis, and the promotion flow. **No AI yet** — that lands in Phase 4.

**Exit criteria.**

- [ ] `policies.is_draft` and `policies.draft_impact` columns added (with migration).
- [ ] `POST /workspace/policy/simulate` endpoint.
- [ ] `GET /workspace/policy/:id/impact` endpoint.
- [ ] `POST /workspace/policy/:id/promote` endpoint.
- [ ] `POST /workspace/policy/test-access` endpoint ("Can user X access resource Y under draft P?").
- [ ] Impact analysis: resolve affected Teams → Members → Resources via attribute / resource selector.
- [ ] Conflict detection against existing live policies (`redundant`, `contradictory`).
- [ ] Admin UI: policy simulator page with before / after comparison.
- [ ] **Drafts do not create OpenZiti `ServicePolicy` until promotion** — verified by an integration test that round-trips a draft → simulate → impact and asserts no Ziti write.

---

## Phase 4 — Server-side AI integration  ⏳

**Scope.** AI agents for risk assessment, policy recommendation, and connector setup assistance.

**Exit criteria.**

- [ ] `access_risk_assessment` agent skill implemented over A2A protocol (extends `aisoc-ai-agents/server/src/aisoc_agents/aisoc_agent.py`).
- [ ] `connector_setup_assistant` agent skill.
- [ ] `policy_recommendation` agent skill.
- [ ] AI risk scoring integrated into the access request workflow (Phase 2): every new request gets a `risk_score` populated within `T` seconds.
- [ ] AI risk assessment integrated into policy simulation (Phase 3): every `ImpactReport` carries a `risk_score`.
- [ ] Natural-language policy explanation endpoint (`POST /access/explain`) backed by the server-side agent.
- [ ] Admin UI: AI assistant chat interface for policy and access queries.
- [ ] Mobile SDK: AI query API contract defined (server-side, **no on-device inference**) — verified by a build-time check that no model files / inference frameworks are bundled.
- [ ] Desktop Extension: AI query IPC contract defined (server-side, **no on-device inference**) — same build-time check.

---

## Phase 5 — Access review campaigns  ⏳

**Scope.** Periodic access certification with AI-assisted automation.

**Exit criteria.**

- [ ] `access_reviews` and `access_review_decisions` tables and migrations.
- [ ] `AccessReviewService` with `StartCampaign`, `SubmitDecision`, `CloseCampaign`, `AutoRevoke`.
- [ ] `access_review_automation` agent skill — auto-certifies low-risk grants.
- [ ] Scheduled review campaigns with configurable frequency per resource category.
- [ ] Auto-certification rate observable as a per-campaign metric; operator can disable auto-certification per resource category.
- [ ] Admin UI: review campaign management with bulk approve / revoke and per-grant detail.
- [ ] Notification system for pending reviews (email + in-app).

---

## Phase 6 — JML automation & SCIM outbound  ⏳

**Scope.** Joiner-Mover-Leaver automation end-to-end, plus outbound SCIM provisioning.

**Exit criteria.**

- [ ] **Joiner** flow: SCIM user creation → auto-assign default Teams → bulk-create access requests in `approved` state → fan-out provisioning across all default-policy connectors.
- [ ] **Mover** flow: SCIM group / attribute change → diff old vs new Team membership → atomic batch of revokes + provisions (no partial-access window).
- [ ] **Leaver** flow: SCIM user deactivation → enumerate all active grants → bulk-revoke → remove from all Teams → disable OpenZiti identity.
- [ ] Outbound SCIM v2.0 push to SaaS apps (extends existing inbound SCIM in `ztna-business-layer/internal/service/scim_user.go`).
- [ ] `access_anomaly_detection` agent skill — flags unusual access patterns during the active phase.

---

## Phase 7 — Connector scale-out (50 connectors)  ⏳

**Scope.** Expand from 10 to ~50 connectors across all categories.

**Exit criteria.**

- [ ] **Cloud Infrastructure** (9): AWS IAM, Azure RBAC, GCP IAM, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify.
- [ ] **Collaboration** (10): Slack, MS Teams, Zoom, Notion, Asana, Monday.com, Figma, Miro, Trello, Airtable.
- [ ] **CRM** (4): Salesforce, HubSpot, Zoho CRM, Pipedrive.
- [ ] **Finance** (4): QuickBooks, Xero, Stripe, FreshBooks.
- [ ] **HR** (6): BambooHR, Gusto, Rippling, Personio, Hibob, Workday.
- [ ] **DevOps** (5): GitHub, GitLab, Jira, PagerDuty, Sentry.
- [ ] **Support** (3): Zendesk, Freshdesk, Help Scout.
- [ ] **Security** (3): CrowdStrike, SentinelOne, Snyk.
- [ ] Each connector implements at minimum: `Validate`, `Connect`, `SyncIdentities`.
- [ ] Connector health dashboard in Admin UI: per-connector last-sync time, error count, credential expiry.

---

## Phase 8 — Workflow orchestration  ⏳

**Scope.** Multi-agent workflow orchestration via LangGraph for complex access scenarios.

**Exit criteria.**

- [ ] LangGraph workflow engine deployed as `cmd/access-workflow-engine`.
- [ ] Multi-step approval workflows with conditional routing (e.g. `manager → resource-owner → security`).
- [ ] Risk-based routing: `low → auto-approve`, `medium → manager`, `high → security review`.
- [ ] Escalation workflows with timeout-based auto-escalation.
- [ ] Workflow templates for common access patterns (new-hire onboarding, contractor onboarding, role change, project access).

---

## Phase 9 — Client SDK / extension release  ⏳

**Scope.** Ship the SDK / library / extension packages for mobile and desktop integration.

**Exit criteria.**

- [ ] **iOS Access SDK** (Swift Package) released to the internal package registry: REST client for access requests, policy queries, AI suggestions.
- [ ] **Android Access SDK** (Kotlin library) released to the internal Maven registry: same API contract as iOS.
- [ ] **Desktop Access Extension** (Electron IPC module) released to the internal npm registry: access management UI components + server-side AI integration.
- [ ] SDK documentation and integration guides published.
- [ ] Sample integration code for each platform.
- [ ] **All AI capabilities are server-side** — SDKs are thin REST / IPC clients only. Verified by a CI check that fails the build if any model file (`.mlmodel`, `.tflite`, `.onnx`, `.gguf`) is committed to any SDK package, and by a runtime probe that the SDKs only ever issue HTTPS REST calls.

---

## Phase 10 — Connector scale-out (200 connectors)  ⏳

**Scope.** Complete the full 200-provider catalogue.

**Exit criteria.**

- [ ] Remaining ~150 connectors implemented across Marketing, Sales, Legal, E-commerce, Education, Health, Real Estate, Supply Chain, Analytics, Communications, Social, Web, Utility, Training, Customer-Feedback, Travel, and other categories.
- [ ] Each connector at minimum: `Validate`, `Connect`, `SyncIdentities`.
- [ ] Advanced capabilities (`ProvisionAccess`, `RevokeAccess`, `ListEntitlements`, `AccessAuditor`) for the top 50 connectors by usage.
- [ ] Connector quality bar: every connector has a `*_flow_test.go` with happy-path + at least one failure-path test.
- [ ] `LISTCONNECTORS.md` (or equivalent in this repo) kept in sync with the registry.

---

## Cross-cutting exit criteria for *every* phase

Independent of which phase a PR contributes to, the following must hold before merge:

- [ ] All affected `*_test.go` updated. New behavior has at least one happy-path + one failure-path test.
- [ ] No secret / token / PII logged. Sensitive payloads are sanitized before logging via the same helper used in `shieldnet360-backend/internal/services/integration/service_helper.go`.
- [ ] No `c.Param` / `c.Query` direct usage in handlers (use `handlers.GetStringParam` / `handlers.GetPtrStringQuery`).
- [ ] No `FOREIGN KEY` constraints introduced (per the SN360 `database-index-rules.md`).
- [ ] No new index without a documented query pattern.
- [ ] No raw SQL — GORM only.
- [ ] Translation keys added for any new operator-facing message.
- [ ] **SN360 language alignment verified** — no jargon (`policy`, `entitlement`, `connector`, `IdP`) in user-facing strings. Use the SN360-language column from `PROPOSAL.md` §8 instead.
- [ ] Swagger regenerated when the public API surface changes (`./generate-swagger.sh` or equivalent).
- [ ] **Client-side AI rule.** No model file (`.mlmodel`, `.tflite`, `.onnx`, `.gguf`) is committed under any mobile / desktop SDK directory. AI calls must be REST.
