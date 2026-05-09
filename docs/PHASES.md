# ShieldNet 360 Access Platform — Phase Definitions & Exit Criteria

This document collects the planned milestones in one place so PR reviewers and operators have a shared vocabulary. The phase model intentionally mirrors `shieldnet360-backend/docs/connectors/PHASES.md`.

A phase is **shippable** only when *all* of its exit criteria are demonstrably met (test, runbook, metric, or migration as appropriate). Phases stack: a later phase assumes the invariants of every earlier phase.

| Status legend |  |
|---------------|--|
| ✅ shipped | The phase is in `main` and exercised in production |
| 🟡 partial | Some exit criteria met; gaps tracked in `PROGRESS.md` |
| ⏳ planned | Not yet started |

> **Phase 0 is `✅ shipped`; Phase 1 is `🟡 partial`** (10 of 10 connectors landed with minimum capabilities; Admin UI + Keycloak federation exit criteria still open). **Phase 2 is `🟡 partial`** — the four request-lifecycle tables, request state machine, the request / provisioning / workflow services AND the HTTP handler layer (POST/GET `/access/requests`, approve/deny/cancel, GET `/access/grants`) have landed; Admin UI / Mobile SDK / Desktop Extension exit criteria remain open. **Phase 3 is `🟡 partial`** — the policy / team / resource tables, `PolicyService`, `ImpactResolver`, `ConflictDetector` AND the HTTP handler layer (`POST /workspace/policy`, drafts, `:id/simulate|promote`, `test-access`) have landed; the Admin UI policy simulator remains open. **Phase 4 is `🟡 partial`** — the Go-side A2A AI client (`internal/pkg/aiclient`), env-driven config (`internal/config`), AI risk-scoring integration into `AccessRequestService.CreateRequest` and `PolicyService.Simulate`, `POST /access/explain` + `POST /access/suggest` endpoints, AND the Python A2A skill server (`cmd/access-ai-agent/`, all five Tier-1 stubs) have landed; the Admin UI assistant and LLM-backed agent skills remain open. **Phase 5 is `🟡 partial`** — the access-review tables, `AccessReviewService` (`StartCampaign` / `SubmitDecision` / `CloseCampaign` / `AutoRevoke` / `GetCampaignMetrics` / `SetAutoCertifyEnabled`), the HTTP handler layer (`POST /access/reviews`, `:id/decisions|close|auto-revoke`, `GET /access/reviews/:id/metrics`, `PATCH /access/reviews/:id`), the scheduled-campaigns scaffold (`access_campaign_schedules` table + migration `005` + `internal/cron.CampaignScheduler`), AND the notification fan-out scaffold (`internal/services/notification`, `Notifier`, `InMemoryNotifier`, fan-out from `StartCampaign` after commit) have landed; AI auto-certification (the Go-side wire-in), email / Slack channels, and the Admin UI dashboard remain open. **Phase 6 is `🟡 partial`** — the JML service (`JMLService.ClassifyChange` / `HandleJoiner` / `HandleMover` / `HandleLeaver`), the inbound SCIM handler (`POST/PATCH/DELETE /scim/Users`), the outbound SCIM v2.0 client (`SCIMClient.PushSCIMUser` / `PushSCIMGroup` / `DeleteSCIMResource`), and the Go-side anomaly stub (`AIClient.DetectAnomalies` + `DetectAnomaliesWithFallback` + `AnomalyDetectionService.ScanWorkspace`) have landed; per-connector SCIM composition shipped for Okta + 1Password (PR #8) and for Microsoft Entra + Google Workspace + Auth0 + Duo + LastPass + Ping Identity (PR #9), so all 10 Tier-1 connectors now expose outbound SCIM; OpenZiti identity-disable on leaver and the cross-grant baseline histogram remain open. **Phase 7 is `🟡 partial`** — all 9 Cloud Infrastructure connectors (AWS IAM, Azure RBAC, GCP IAM, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify) land in PR #9, and 5 of 10 Collaboration connectors (Slack, MS Teams, Zoom, Notion, Asana) land alongside them. Each connector ships at minimum `Validate` (pure-local), `Connect`, `SyncIdentities` (paginated), plus `GetCredentialsMetadata` with token redaction, and is registered via blank-import in the three cmd binaries. Remaining Tier-2 / Tier-3 categories (CRM, Finance, HR, DevOps, Support, Security, plus the rest of Collaboration) remain `⏳ planned`. Later phases remain `⏳ planned`. As phases land, flip the marker and move the supporting status row in `PROGRESS.md`.

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
- [x] **Auth0** connector. — 🟡 minimum capabilities only (`Validate`, `Connect`, `VerifyPermissions`, `CountIdentities`, `SyncIdentities`, `SyncIdentitiesDelta` via Auth0 logs API, `GetSSOMetadata`, `GetCredentialsMetadata`).
- [x] **Generic SAML** connector (covers 60 %+ of enterprise SaaS that have no custom API). — 🟡 minimum capabilities only (SSO-only: `Validate`, `Connect`, `GetSSOMetadata` parsed from IdP metadata XML; `SyncIdentities` is a no-op).
- [x] **Generic OIDC** connector. — 🟡 minimum capabilities only (SSO-only: `Validate`, `Connect`, `GetSSOMetadata` parsed from `/.well-known/openid-configuration`).
- [x] **Duo Security** connector. — 🟡 minimum capabilities only (`Validate`, `Connect` with HMAC-SHA1 request signing, `CountIdentities`, `SyncIdentities`).
- [x] **1Password** connector. — 🟡 minimum capabilities only (`Validate`, `Connect`, `CountIdentities`, `SyncIdentities` via SCIM v2).
- [x] **LastPass** connector. — 🟡 minimum capabilities only (`Validate`, `Connect`, `CountIdentities`, `SyncIdentities` via Enterprise API `cmd=getuserdata`).
- [x] **Ping Identity** connector. — 🟡 minimum capabilities only (`Validate`, `Connect`, `CountIdentities`, `SyncIdentities` via PingOne v1 with regional NA/EU/AP routing, `GetSSOMetadata`).
- [x] Each landed connector implements at minimum: `Validate`, `Connect`, `SyncIdentities`, `GetCredentialsMetadata`.
- [x] Each landed connector's `Validate` is pure-local (no I/O), enforced by a per-connector unit test.
- [ ] Admin UI: connector marketplace page with a setup wizard per connector.
- [ ] First-class SSO federation via Keycloak for SAML / OIDC / Microsoft Entra ID / Google Workspace.

---

## Phase 2 — Access request workflow  🟡 partial

**Scope.** Basic access request lifecycle without AI in the path. Self-service and manager approval only.

**Exit criteria.**

- [x] `access_requests`, `access_request_state_history`, `access_grants`, `access_workflows` tables and migrations (`internal/migrations/002_create_access_request_tables.go`).
- [x] `AccessRequestService` with `CreateRequest`, `ApproveRequest`, `DenyRequest`, `CancelRequest` (`internal/services/access/request_service.go`).
- [x] `AccessProvisioningService` with connector-based `ProvisionAccess` / `RevokeAccess` (`internal/services/access/provisioning_service.go`).
- [x] State machine for the request lifecycle (`requested → approved → provisioning → provisioned → active → revoked`), implemented in the pattern of `ztna-business-layer/internal/state_machine/` (`internal/services/access/request_state_machine.go`).
- [x] Self-service workflow (auto-approve when an active policy match exists) (`internal/services/access/workflow_service.go`).
- [x] Manager approval workflow (single-step, manager resolved through manager-link pass) (`internal/services/access/workflow_service.go`).
- [x] HTTP handler layer for access requests: `POST /access/requests`, `GET /access/requests` (filtered by state / requester / target / resource), `POST /access/requests/:id/approve`, `POST /access/requests/:id/deny`, `POST /access/requests/:id/cancel`, `GET /access/grants` (active grants for caller). All handlers use `GetStringParam` / `GetPtrStringQuery` per cross-cutting criteria. (`internal/handlers/access_request_handler.go`, `internal/handlers/access_grant_handler.go`)
- [ ] Admin UI: access request management page (list / approve / deny / view audit trail).
- [ ] Mobile SDK: access request API contract defined and published to the internal package registry.
- [ ] Desktop Extension: access request IPC contract defined and published as an internal npm package.

---

## Phase 3 — Policy simulation & testing  🟡 partial

**Scope.** Draft policies, impact analysis, and the promotion flow. **No AI yet** — that lands in Phase 4.

**Exit criteria.**

- [x] `policies.is_draft` and `policies.draft_impact` columns added (with migration `003_create_policy_tables`). Tables `policies`, `teams`, `team_members`, `resources` all landed.
- [x] `POST /workspace/policy` (creates a draft) and `POST /workspace/policy/:id/simulate` endpoints. (`internal/handlers/policy_handler.go`)
- [x] `GET /workspace/policy/drafts` (list drafts) and `GET /workspace/policy/:id` (get one) endpoints; the persisted impact is returned on the `:id` row's `draft_impact` field.
- [x] `POST /workspace/policy/:id/promote` endpoint.
- [x] `POST /workspace/policy/test-access` endpoint ("Can user X access resource Y under draft P?").
- [x] Impact analysis: resolve affected Teams → Members → Resources via attribute / resource selector (`internal/services/access/impact_resolver.go`).
- [x] Conflict detection against existing live policies (`redundant`, `contradictory`) (`internal/services/access/conflict_detector.go`).
- [ ] Admin UI: policy simulator page with before / after comparison.
- [x] **Drafts do not create OpenZiti `ServicePolicy` until promotion** — verified by `TestPromote_DoesNotInvokeOpenZiti` in `policy_service_test.go`.

---

## Phase 4 — Server-side AI integration  🟡 partial

**Scope.** AI agents for risk assessment, policy recommendation, and connector setup assistance.

**Exit criteria.**

- [x] `access_risk_assessment` agent skill implemented over A2A protocol (extends `aisoc-ai-agents/server/src/aisoc_agents/aisoc_agent.py`). *(Go-side A2A client + fallback shipped (PR #6); Python stub now ships under `cmd/access-ai-agent/skills/access_risk_assessment.py` (PR #7); LLM-backed scorer is the open piece.)*
- [x] `connector_setup_assistant` agent skill. *(Python stub now ships under `cmd/access-ai-agent/skills/connector_setup_assistant.py` (PR #7); Admin-UI conversational surface still ⏳.)*
- [x] `policy_recommendation` agent skill. *(Go-side A2A client + fallback shipped (PR #6); Python stub now ships under `cmd/access-ai-agent/skills/policy_recommendation.py` (PR #7); LLM-backed generator still ⏳.)*
- [x] AI risk scoring integrated into the access request workflow (Phase 2): `AccessRequestService.CreateRequest` calls the assessor and persists `risk_score` / `risk_factors`; on AI failure the access-request workflow defaults to `medium` per PROPOSAL §5.3. (`internal/services/access/request_service.go`, `internal/pkg/aiclient/fallback.go`)
- [x] AI risk assessment integrated into policy simulation (Phase 3): `PolicyService.Simulate` stamps `RiskScore` / `RiskFactors` onto the `ImpactReport` before persisting `draft_impact`. AI failure leaves the report empty rather than synthesising a default. (`internal/services/access/policy_service.go`)
- [x] Natural-language policy explanation endpoint (`POST /access/explain`) backed by the server-side agent. Pair endpoint `POST /access/suggest` shares the same handler. (`internal/handlers/ai_handler.go`)
- [ ] Admin UI: AI assistant chat interface for policy and access queries.
- [ ] Mobile SDK: AI query API contract defined (server-side, **no on-device inference**) — verified by a build-time check that no model files / inference frameworks are bundled.
- [ ] Desktop Extension: AI query IPC contract defined (server-side, **no on-device inference**) — same build-time check.

---

## Phase 5 — Access review campaigns  🟡 partial

**Scope.** Periodic access certification with AI-assisted automation.

**Exit criteria.**

- [x] `access_reviews` and `access_review_decisions` tables and migrations (`004_create_access_review_tables`).
- [x] `AccessReviewService` with `StartCampaign`, `SubmitDecision`, `CloseCampaign`, `AutoRevoke` (`internal/services/access/review_service.go`).
- [x] HTTP handler layer for review campaigns: `POST /access/reviews`, `POST /access/reviews/:id/decisions`, `POST /access/reviews/:id/close`, `POST /access/reviews/:id/auto-revoke`, `GET /access/reviews/:id/metrics`, `PATCH /access/reviews/:id`. (`internal/handlers/access_review_handler.go`)
- [ ] `access_review_automation` agent skill — auto-certifies low-risk grants. *(Python stub now ships under `cmd/access-ai-agent/skills/access_review_automation.py` (PR #7); the Go-side wire-in that flips pending→certify based on the agent's verdict is still ⏳.)*
- [x] Scheduled review campaigns with configurable frequency per resource category. The `access_campaign_schedules` table (migration `005`), `AccessCampaignSchedule` model, and `internal/cron.CampaignScheduler` (scans for due rows, calls `StartCampaign`, bumps `NextRunAt` by `FrequencyDays`) are all in place. (`internal/cron/campaign_scheduler.go`)
- [x] Auto-certification rate observable as a per-campaign metric; operator can disable auto-certification per resource category. *(`AccessReviewService.GetCampaignMetrics` returns `total_decisions` / `pending` / `certified` / `auto_certified` / `revoked` / `escalated` / `auto_certification_rate`; surfaced via `GET /access/reviews/:id/metrics`. Admin toggle for `auto_certify_enabled` ships as `PATCH /access/reviews/:id` (PR #7).)*
- [ ] Admin UI: review campaign management with bulk approve / revoke and per-grant detail.
- [x] Notification system for pending reviews (email + in-app). *(Phase 5 scaffold ships in PR #7: `internal/services/notification.NotificationService`, `Notifier` interface, `InMemoryNotifier` for dev / tests, `NotifyReviewersPending` / `NotifyRequester` methods, fan-out from `AccessReviewService.StartCampaign` after commit; failures never roll back. Email + Slack channels are still ⏳.)*

---

## Phase 6 — JML automation & SCIM outbound  🟡 partial

**Scope.** Joiner-Mover-Leaver automation end-to-end, plus outbound SCIM provisioning.

**Exit criteria.**

- [x] **Joiner** flow: SCIM user creation → auto-assign default Teams → bulk-create access requests in `approved` state → fan-out provisioning across all default-policy connectors. *(Lands as `JMLService.HandleJoiner` (PR #7); inbound SCIM `POST /scim/Users` calls `ClassifyChange` → `HandleJoiner`. `internal/services/access/jml_service.go`, `internal/handlers/scim_handler.go`)*
- [x] **Mover** flow: SCIM group / attribute change → diff old vs new Team membership → atomic batch of revokes + provisions (no partial-access window). *(Lands as `JMLService.HandleMover` (PR #7); revoke + provision run inside a single GORM transaction. `internal/services/access/jml_service.go`)*
- [x] **Leaver** flow: SCIM user deactivation → enumerate all active grants → bulk-revoke → remove from all Teams → disable OpenZiti identity. *(Lands as `JMLService.HandleLeaver` (PR #7); revokes + Team-membership removal complete; OpenZiti identity disable is still ⏳ pending per-connector `RevokeIdentity`.)*
- [x] Outbound SCIM v2.0 push to SaaS apps (extends existing inbound SCIM in `ztna-business-layer/internal/service/scim_user.go`). *(Lands as the generic `SCIMClient` (`PushSCIMUser` / `PushSCIMGroup` / `DeleteSCIMResource`) with sentinel errors for 409 / 404 / 401 / 5xx and idempotent 404-on-DELETE handling (PR #7); per-connector composition shipped for Okta + 1Password (PR #8) and for Microsoft Entra + Google Workspace + Auth0 + Duo + LastPass + Ping Identity (PR #9). All 10 Tier-1 connectors now expose outbound SCIM. `internal/services/access/scim_provisioner.go`)*
- [x] `access_anomaly_detection` agent skill — flags unusual access patterns during the active phase. *(Go-side `AIClient.DetectAnomalies` + `DetectAnomaliesWithFallback` + `AnomalyDetectionService.ScanWorkspace` AND Python stub all ship in PR #7; cross-grant baseline histogram still ⏳.)*

---

## Phase 7 — Connector scale-out (50 connectors)  🟡 partial

**Scope.** Expand from 10 to ~50 connectors across all categories.

**Exit criteria.**

- [x] **Cloud Infrastructure** (9): AWS IAM, Azure RBAC, GCP IAM, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify. *(All 9 land in PR #9; each connector ships `Validate` (pure-local), `Connect`, `SyncIdentities` (paginated), `CountIdentities`, `GetCredentialsMetadata` (token redacted) and is registered via `init()` in its package + blank-imported in the three cmd binaries.)*
- [ ] **Collaboration** (10): Slack, MS Teams, Zoom, Notion, Asana, Monday.com, Figma, Miro, Trello, Airtable. *(5 of 10 land in PR #9: Slack (auth.test + users.list cursor pagination + Enterprise-Grid SAML metadata), MS Teams (client_credentials + /teams/{id}/members + Entra SAML), Zoom (Server-to-Server OAuth + /users page tokens), Notion (start_cursor pagination), Asana (offset pagination). Monday.com / Figma / Miro / Trello / Airtable still ⏳.)*
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
