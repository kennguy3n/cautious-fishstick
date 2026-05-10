# ShieldNet 360 Access Platform — Phase Definitions & Exit Criteria

This document collects the planned milestones in one place so PR reviewers and operators have a shared vocabulary. The phase model intentionally mirrors `shieldnet360-backend/docs/connectors/PHASES.md`.

A phase is **shippable** only when *all* of its exit criteria are demonstrably met (test, runbook, metric, or migration as appropriate). Phases stack: a later phase assumes the invariants of every earlier phase.

| Status legend |  |
|---------------|--|
| ✅ shipped | The phase is in `main` and exercised in production |
| 🟡 partial | Some exit criteria met; gaps tracked in `PROGRESS.md` |
| ⏳ planned | Not yet started |

> **Phase 0 is `✅ shipped`; Phase 1 is `🟡 partial`** (10 of 10 connectors landed with minimum capabilities; Admin UI + Keycloak federation exit criteria still open). **Phase 7 connector totals: 123 / 200 (Tier 1 10/10, Tier 2 25/25, Tier 3 55/55, Tier 4 40/50, Tier 5 3/60). PR #14 closes Tier 3 (Travis CI, Mezmo, Sumo Logic, Drift, Crisp, LiveChat, Gorgias, Loom, Discord, Slack Enterprise, Basecamp, Quip, Wrike, Teamwork, LiquidPlanner, KnowBe4) and lands the first 4 Tier-4 Sales/Marketing connectors (Gong, Salesloft, Mailchimp, Klaviyo); PR #15 lands the next 20 Tier-4 connectors (Apollo.io, Copper, Insightly, Close, ActiveCampaign, Constant Contact, Braze, Mixpanel, Segment, Typeform, SurveyMonkey, Eventbrite, Navan, SAP Concur, Coupa, Anvyl, Bill.com, Expensify, Sage Intacct, Plaid) bringing Tier 4 to 40/50.** **Phase 2 is `🟡 partial`** — the four request-lifecycle tables, request state machine, the request / provisioning / workflow services AND the HTTP handler layer (POST/GET `/access/requests`, approve/deny/cancel, GET `/access/grants`) have landed; Admin UI / Mobile SDK / Desktop Extension exit criteria remain open. **Phase 3 is `🟡 partial`** — the policy / team / resource tables, `PolicyService`, `ImpactResolver`, `ConflictDetector` AND the HTTP handler layer (`POST /workspace/policy`, drafts, `:id/simulate|promote`, `test-access`) have landed; the Admin UI policy simulator remains open. **Phase 4 is `🟡 partial`** — the Go-side A2A AI client (`internal/pkg/aiclient`), env-driven config (`internal/config`), AI risk-scoring integration into `AccessRequestService.CreateRequest` and `PolicyService.Simulate`, `POST /access/explain` + `POST /access/suggest` endpoints, AND the Python A2A skill server (`cmd/access-ai-agent/`, all five Tier-1 stubs) have landed; the Admin UI assistant and LLM-backed agent skills remain open. **Phase 5 is `🟡 partial`** — the access-review tables, `AccessReviewService` (`StartCampaign` / `SubmitDecision` / `CloseCampaign` / `AutoRevoke` / `GetCampaignMetrics` / `SetAutoCertifyEnabled`), the HTTP handler layer (`POST /access/reviews`, `:id/decisions|close|auto-revoke`, `GET /access/reviews/:id/metrics`, `PATCH /access/reviews/:id`), the scheduled-campaigns scaffold (`access_campaign_schedules` table + migration `005` + `internal/cron.CampaignScheduler`), AND the notification fan-out scaffold (`internal/services/notification`, `Notifier`, `InMemoryNotifier`, fan-out from `StartCampaign` after commit) have landed; AI auto-certification (the Go-side wire-in), email / Slack channels, and the Admin UI dashboard remain open. **Phase 6 is `🟡 partial`** — the JML service (`JMLService.ClassifyChange` / `HandleJoiner` / `HandleMover` / `HandleLeaver`), the inbound SCIM handler (`POST/PATCH/DELETE /scim/Users`), the outbound SCIM v2.0 client (`SCIMClient.PushSCIMUser` / `PushSCIMGroup` / `DeleteSCIMResource`), and the Go-side anomaly stub (`AIClient.DetectAnomalies` + `DetectAnomaliesWithFallback` + `AnomalyDetectionService.ScanWorkspace`) have landed; per-connector SCIM composition shipped for Okta + 1Password (PR #8) and for Microsoft Entra + Google Workspace + Auth0 + Duo + LastPass + Ping Identity (PR #9), so all 10 Tier-1 connectors now expose outbound SCIM; OpenZiti identity-disable on leaver and the cross-grant baseline histogram remain open. **Phase 7 is `🟡 partial`** — Tier 1 (10/10), Tier 2 Cloud Infrastructure (15/15) and Tier 3 Business SaaS (55/55) are complete; Tier 4 (HR / Finance / Legal / Sales / Marketing) sits at 40/50 with the first Sales/Marketing batch (Gong, Salesloft, Mailchimp, Klaviyo) in PR #14 and the 20-connector Tier-4 batch B (Apollo.io, Copper, Insightly, Close, ActiveCampaign, Constant Contact, Braze, Mixpanel, Segment, Typeform, SurveyMonkey, Eventbrite, Navan, SAP Concur, Coupa, Anvyl, Bill.com, Expensify, Sage Intacct, Plaid) in PR #15; Tier 5 Vertical/Niche stays at 3/60 (CrowdStrike, SentinelOne, Snyk). Each connector ships at minimum `Validate` (pure-local), `Connect`, `SyncIdentities` (paginated), plus `GetCredentialsMetadata` with token redaction, and is registered via blank-import in the three cmd binaries. The remaining Tier-4 sub-categories and the Tier-5 catalogue, plus the per-connector health dashboard in the Admin UI, remain `⏳ planned`. Later phases remain `⏳ planned`. As phases land, flip the marker and move the supporting status row in `PROGRESS.md`.

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
- [x] `access_review_automation` agent skill — auto-certifies low-risk grants. *(Python stub ships under `cmd/access-ai-agent/skills/access_review_automation.py` (PR #7); the Go-side wire-in flipping pending→certify ships as `ReviewAutomator` + `applyAutoCertification` inside `AccessReviewService.StartCampaign` (PR #8). Real LLM-backed verdicts beyond the deterministic stub are still ⏳ and tracked in PROGRESS.md §3.2.)*
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

- [x] **Cloud Infrastructure** (15): AWS IAM, Azure RBAC, GCP IAM, Cloudflare, Tailscale, DigitalOcean, Heroku, Vercel, Netlify, Vultr, Linode, OVHcloud, Alibaba Cloud, CloudSigma, Wasabi. *(All 15 land — 9 in PR #9 (each connector ships `Validate` (pure-local), `Connect`, `SyncIdentities` (paginated), `CountIdentities`, `GetCredentialsMetadata` (token redacted) and is registered via `init()` in its package + blank-imported in the three cmd binaries); 6 more in PR #11 — Vultr `/v2/users` cursor pagination; Linode `/v4/account/users` page/page_size; OVHcloud `/1.0/me/identity/user` with OVH application-key/consumer-key/secret signature headers; Alibaba RAM `ListUsers` HMAC-SHA1 + Marker/IsTruncated; CloudSigma `/api/2.0/profile/` per-region HTTP Basic; Wasabi IAM-compatible `ListUsers` with AWS SigV4 reused from `aws/sigv4.go`.)*
- [x] **Collaboration** (10): Slack, MS Teams, Zoom, Notion, Asana, Monday.com, Figma, Miro, Trello, Airtable. *(All 10 land — 5 in PR #9 (Slack auth.test + users.list cursor + Enterprise-Grid SAML; MS Teams client_credentials + /teams/{id}/members + Entra SAML; Zoom Server-to-Server OAuth + /users page tokens; Notion start_cursor pagination; Asana offset pagination); 5 more in PR #10 (Monday.com GraphQL `users` page-number pagination; Figma `/v1/teams/{team_id}/members` cursor pagination; Miro `/v2/orgs/{org_id}/members` cursor pagination; Trello `/1/organizations/{org_id}/members` query-string auth; Airtable enterprise users with offset pagination).)*
- [x] **CRM** (4): Salesforce, HubSpot, Zoho CRM, Pipedrive. *(All 4 land in PR #10 — Salesforce SOQL with nextRecordsUrl pagination + SAML metadata; HubSpot `/settings/v3/users` after-cursor pagination; Zoho CRM `/crm/v5/users` page/per_page + `Zoho-oauthtoken` auth; Pipedrive `/v1/users` query-string auth + `additional_data.pagination.next_start`.)*
- [x] **Finance** (4): QuickBooks, Xero, Stripe, FreshBooks. *(All 4 land in PR #11 / PR #12 — QuickBooks `/v3/company/{realm}/query` with `SELECT * FROM Employee STARTPOSITION/MAXRESULTS` and OAuth2 bearer; Xero `/api.xro/2.0/Users` with `Xero-Tenant-Id` header + offset pagination; **Stripe** in PR #11 originally targeted the non-existent `/v1/team_members` endpoint and is corrected in PR #12 to sync Stripe Connect connected accounts via `/v1/accounts` with `starting_after` cursor + `has_more`; FreshBooks `/accounting/account/{account_id}/users/staffs` with page/per_page.)*
- [x] **Finance batch B** (2): PayPal, Wave. *(Both land in PR #12 — PayPal OAuth2 client_credentials at `/v1/oauth2/token` with HTTP Basic `client_id:client_secret`, then `/v1/customer/partners/{partner_id}/merchant-integrations` with `page`/`page_size` (`IdentityTypeServiceAccount`); Wave Financial GraphQL POST `/graphql/public` with `Authorization: Bearer …` + `businesses(first, after)` connection with `pageInfo.endCursor` cursor (`IdentityTypeServiceAccount`).)*
- [x] **HR** (6): BambooHR, Gusto, Rippling, Personio, Hibob, Workday. *(All 6 land in PR #11 — BambooHR `/api/gateway.php/{subdomain}/v1/employees/directory` with `api_key:x` Basic auth + SAML metadata at `{subdomain}.bamboohr.com/saml/metadata`; Gusto `/v1/companies/{company_id}/employees` with page/per pagination; Rippling `/platform/api/employees` with cursor `nextCursor`/`next`; Personio OAuth2 client_credentials -> `/v1/auth` -> `/v1/company/employees` with offset/limit + attribute-wrapped JSON unwrap; Hibob `/v1/people?showInactive=true` with `Basic {api_token}`; Workday `/ccx/api/v1/{tenant}/workers` with offset/limit + `total` field + Workday SAML metadata at `/{tenant}/saml2/metadata`.)*
- [x] **HR batch B** (4): Paychex, Deel, Zenefits, Namely. *(All 4 land in PR #12 — Paychex `/companies/{company_id}/workers` with OAuth2 bearer + offset/limit + `content.metadata.pagination.totalItems`; Deel `/rest/v2/contracts` with bearer + page/page_size (workers projected from `contract.worker.{id,first_name,last_name,email}` with cross-contract dedupe); Zenefits `/core/people` with bearer + `next_url` link pagination on `data.next_url` envelope; Namely `/api/v1/profiles` with bearer + page/per_page + `meta.total_count` + subdomain-derived host.)*
- [x] **Storage** (3): Dropbox Business, Box, Egnyte. *(Dropbox + Box land in PR #11; Egnyte lands in PR #12 — `/pubapi/v2/users` with `Authorization: Bearer …` + offset/count pagination + SCIM-like `resources` / `totalResults` / `itemsPerPage` envelope.)*
- [x] **Observability** (4): Datadog, New Relic, Splunk Cloud, Grafana. *(All 4 land in PR #12 — Datadog `/api/v2/users` with `DD-API-KEY` + `DD-APPLICATION-KEY` headers + URL-encoded `page[number]`/`page[size]` + Site config; New Relic NerdGraph POST `/graphql` with `API-Key: …` + cursor pagination via `nextCursor` on `users` connection inside `authenticationDomains`; Splunk Cloud `/services/authentication/users?output_mode=json` with bearer + count/offset + `paging.total` + `locked-out` status mapping; Grafana `/api/org/users` with bearer or HTTP Basic — single-page response.)*
- [x] **DevOps** (5): GitHub, GitLab, Jira, PagerDuty, Sentry. *(All 5 land in PR #10 — GitHub `/orgs/{org}/members` Link-header pagination + Enterprise SAML metadata; GitLab `/api/v4/groups/{group_id}/members/all` X-Next-Page pagination + group SAML metadata; Jira Atlassian Cloud `/rest/api/3/users/search` with `email:api_token` Basic auth + startAt/maxResults + Atlassian Access SAML metadata; PagerDuty `/users` offset/limit pagination + `Token token=` auth; Sentry `/api/0/organizations/{org_slug}/members/` with `Link rel="next"; results="true"` cursor pagination.)*
- [x] **DevOps batch B** (6): Terraform, Docker Hub, JFrog, SonarCloud, CircleCI, LaunchDarkly. *(All 6 land in PR #12 — Terraform Cloud `/api/v2/organizations/{org}/organization-memberships` with bearer + `page[number]`/`page[size]` + JSON:API `data`/`included`; Docker Hub `/v2/users/login` JWT exchange first, then `/v2/orgs/{org}/members` with `next` URL pagination; JFrog `/access/api/v2/users` with bearer + offset/limit + `pagination.total`; SonarCloud `/api/organizations/search_members?organization={org}` with bearer + `p`/`ps` 1-indexed page pagination; CircleCI `/api/v2/me/collaborations` with `Circle-Token` header — single-page list of collaborations; LaunchDarkly `/api/v2/members` with raw API key in `Authorization` header + offset/limit + `totalCount`.)*
- [x] **Support** (3): Zendesk, Freshdesk, Help Scout. *(All 3 land in PR #10 — Zendesk `/api/v2/users.json` with `email/token:api_token` Basic auth + `next_page` URL pagination + SAML metadata; Freshdesk `/api/v2/agents` with `api_key:X` Basic auth + page-size-as-EOF pagination; Help Scout `/v2/users` HAL `_embedded.users` + `page.totalPages` pagination.)*
- [x] **Support batch B** (2): Front, Intercom. *(Both land in PR #12 — Front `/teammates` with bearer + `_pagination.next` URL cursor + `is_blocked` → `blocked` status mapping; Intercom `/admins` with bearer — single-page response + `away_mode_enabled` → `away` status mapping.)*
- [x] **Security** (3): CrowdStrike, SentinelOne, Snyk. *(All 3 land in PR #10 — CrowdStrike OAuth2 client_credentials at `/oauth2/token` + Falcon query-then-hydrate (`/queries/users/v1` then `POST /entities/users/GET/v1`); SentinelOne `/web/api/v2.1/users` with `ApiToken` auth + `pagination.nextCursor`; Snyk `/rest/orgs/{org_id}/members` with `token` auth + `links.next` cursor + relative-URL rewrite.)*
- [x] **DevOps batch C** (1): Travis CI. *(Lands in PR #14 — `/users` with `Authorization: token …` + offset/limit pagination via `@pagination`; closes the Tier-3 DevOps category.)*
- [x] **Observability batch B** (2): Mezmo, Sumo Logic. *(Both land in PR #14 — Mezmo `/v1/config/members` with `Authorization: servicekey …` (single-page); Sumo Logic `/api/v1/users` with HTTP Basic `accessId:accessKey` + offset/limit + `X-Sumo-Client` header + deployment-based host routing using `isDNSLabel`.)*
- [x] **Support / Marketing batch C** (4): Drift, Crisp, LiveChat, Gorgias. *(All 4 land in PR #14 — Drift `/v1/users/list` with OAuth2 bearer (single-page); Crisp `/v1/website/{website_id}/operators/list` with HTTP Basic `identifier:key` + URL-path-escaped website_id; LiveChat `/v3.5/agents` with PAT bearer + page/page_size; Gorgias `/api/users` with HTTP Basic `email:api_key` + page/per_page + `X-Gorgias-Account` header + DNS-label-validated subdomain.)*
- [x] **Collab batch B** (3): Loom, Discord, Slack Enterprise. *(All 3 land in PR #14 — Loom `/v1/members` with bearer + `next_cursor` cursor + URL-encoded cursor; Discord `/api/v10/guilds/{guild_id}/members` with Bot token + `after` snowflake cursor + numeric guild_id (bots projected to `IdentityTypeServiceAccount`); Slack Enterprise SCIM `/scim/v2/Users` with bearer + startIndex/count + `application/scim+json`.)*
- [x] **Productivity batch C** (5): Basecamp, Quip, Wrike, Teamwork, LiquidPlanner. *(All 5 land in PR #14 — Basecamp `/people.json` with OAuth2 bearer + numeric account_id + Basecamp-required `User-Agent`; Quip `/1/users/contacts` with bearer (single-page); Wrike `/api/v4/contacts` with bearer + `nextPageToken` cursor + URL-encoded token + Person/Group identity-type mapping; Teamwork `/people.json` with HTTP Basic `api_key:xxx` + page/pageSize; LiquidPlanner `/api/v1/workspaces/{workspace_id}/members` with bearer + URL-path-escaped numeric workspace_id (single-page).)*
- [x] **Security Training** (1): KnowBe4. *(Lands in PR #14 — `/v1/users` with bearer + page/per_page + region-based host routing with `isDNSLabel` validation + `archived_at` → `archived` status mapping; closes the Tier-3 catalogue at 55/55.)*
- [x] **Tier 4 Sales / Marketing first batch** (4): Gong, Salesloft, Mailchimp, Klaviyo. *(All 4 land in PR #14 — Gong `/v2/users` with HTTP Basic `access_key:secret_key` + cursor `records.cursor` + URL-encoded cursor (both `key_short` and `secret_short` redacted in `GetCredentialsMetadata`); Salesloft `/v2/users` with bearer + page/per_page + `metadata.paging.next_page`; Mailchimp `/3.0/lists/{list_id}/members` with HTTP Basic `anystring:api_key` + offset/count + datacenter-suffix-based host routing parsed from API-key suffix `…-us12` + URL-path-escaped list_id; Klaviyo `/api/accounts/` with `Authorization: Klaviyo-API-Key …` + JSON:API `page[cursor]` pagination from `links.next` + `revision` header pinned (accounts modelled as `IdentityTypeServiceAccount`); Tier 4 now sits at 20/50.)*
- [x] **Tier 4 Sales / Marketing / Finance / Legal / Supply batch B** (20): Apollo.io, Copper, Insightly, Close, ActiveCampaign, Constant Contact, Braze, Mixpanel, Segment, Typeform, SurveyMonkey, Eventbrite, Navan, SAP Concur, Coupa, Anvyl, Bill.com, Expensify, Sage Intacct, Plaid. *(All 20 land in PR #15 — Apollo.io `/v1/users` with bearer + page/per_page; Copper `/developer_api/v1/users` with `X-PW-AccessToken` + `X-PW-Application` + `X-PW-UserEmail` triple-header auth + page_number/page_size; Insightly `/v3.1/Users` with HTTP Basic `api_key:` + skip/top + DNS-label-validated `pod` defaulting to `na1`; Close `/api/v1/user/` with HTTP Basic `api_key:` + _skip/_limit + `has_more` continuation; ActiveCampaign `/api/3/users` with `Api-Token` header + offset/limit + DNS-label-validated `account` subdomain into `{account}.api-us1.com`; Constant Contact `/v3/account/users` with OAuth2 bearer + offset/limit + `login_enabled` → active/disabled; Braze SCIM `/scim/v2/Users` with bearer + `application/scim+json` + startIndex/count + cluster validation against `iad-01`/`fra-01`/etc. allow-list + primary-email extraction; Mixpanel `/api/app/me/organizations/{id}/members` with HTTP Basic service-account `user:secret` + URL-path-escaped numeric org_id; Segment `/users` with bearer + `pagination.cursor`/`pagination.count` + `application/vnd.segment.v1+json` accept; Typeform `/teams/members` with bearer (single-page); SurveyMonkey `/v3/users` with bearer + page/per_page + `links.next` continuation; Eventbrite `/v3/organizations/{id}/members/` with bearer + `continuation` cursor + `pagination.has_more_items` + URL-path-escaped numeric org_id; Navan `/api/v1/users` with bearer + page/size 0-indexed + status normalization to lower-case; SAP Concur `/api/v3.0/common/users` with OAuth2 bearer + offset/limit + `Active` bool → status; Coupa `/api/users` with `X-COUPA-API-KEY` header + offset/limit + DNS-label-validated `instance` subdomain into `{instance}.coupahost.com`; Anvyl `/api/v1/users` with bearer + page/per_page; Bill.com `/v3/orgs/{org_id}/users` with `devKey` + `sessionId` headers + start/max + URL-path-escaped org_id; Expensify POST `/Integration-Server/ExpensifyIntegrations` with form-encoded `requestJobDescription` JSON containing partner `partnerUserID`/`partnerUserSecret` credentials and `policyList` `readByQuery`; Sage Intacct POST `/ia/xml/xmlgw.phtml` with sender + user XML credentials + `<readByQuery><object>USERINFO</object></readByQuery>` + 100-page offset pagination + `STATUS` → active/inactive; Plaid POST `/team/list` with `client_id` + `secret` JSON body + environment-routed base URL across `sandbox`/`development`/`production`; Tier 4 now sits at 40/50, total at 123/200.)*
- [x] Each connector implements at minimum: `Validate`, `Connect`, `SyncIdentities`. *(Enforced for every shipped connector via the per-package `connector_test.go` suite — `TestValidate_HappyPath`, `TestValidate_PureLocal` (no I/O), `TestRegistryIntegration`, `TestSync_PaginatesUsers` (httptest.Server), `TestConnect_Failure`, `TestGetCredentialsMetadata_RedactsToken`.)*
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
