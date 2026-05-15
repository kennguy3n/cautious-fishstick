# ShieldNet 360 Access Platform — Technical Specification

> Status: **Greenfield design specification.** This document is the long-form contract that `README.md` (overview) and `ARCHITECTURE.md` (diagrams) reference. Where the implementation later disagrees with this document, the code wins and this document must be updated.

---

## 1. Goals & non-goals

### Goals

- Single, stable `AccessConnector` interface for any external system that needs to:
  - Sync identities (users / groups / memberships) into ZTNA Teams.
  - Provision and revoke access grants on demand.
  - Federate SSO through Keycloak.
  - Pull current entitlements for periodic access check-ups.
  - Stream access audit logs (sign-in events, permission changes) into the audit pipeline.
- Connector code stays free of cross-cutting concerns. Credential storage, scheduling, retries, lifecycle orchestration, observability all live in the `access` service layer of `ztna-business-layer`. Adding a new connector is bounded, recipe-shaped work.
- Reuse proven patterns from the existing SN360 connector framework (`shieldnet360-backend/internal/services/connectors`): registry, AES-GCM credential encryption, tombstoning, full / delta sync strategy resolution, `*_test.go` registry-swap pattern.
- AI-first lifecycle: risk-score every access request at intake, auto-certify routine reviews, surface anomalies during the active phase, recommend policies from organizational structure — all server-side.
- SME-friendly: zero IT-knowledge required for connector setup or policy management. Wizards, plain-language explanations, "safe test" before promotion.
- Client-side AI capabilities exposed strictly as **SDK / library / extension** with REST calls to server-side agents. **No on-device model inference** on mobile or desktop, ever.

### Non-goals

- **No on-device SLM inference** for mobile or desktop clients. The SDK / extension contract is defined here; embedding a model is explicitly deferred.
- **No connector-side persistence or scheduling.** Connectors return batches via callbacks and execute one-shot RPC-style operations. The platform owns the queue, the retries, and the database.
- **No real-time streaming protocol connectors** beyond webhook + polling. WebSocket / gRPC server-streaming connectors require a new optional capability interface and a re-think of the worker model.
- **No bespoke identity store.** Keycloak is the broker for federated SSO. The platform does not re-implement OIDC.

---

## 2. AccessConnector contract

The contract extends the existing SN360 `Connector` pattern from `shieldnet360-backend/internal/services/connectors/types.go:21-145`, with access-specific methods layered on.

### 2.1 Mandatory interface

```go
package access

type AccessConnector interface {
    // Lifecycle (inherited pattern from SN360)
    Validate(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) error
    Connect(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) error
    VerifyPermissions(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}, capabilities []string) (missing []string, err error)

    // Identity sync — pull users / groups into ZTNA Teams
    CountIdentities(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) (int, error)
    SyncIdentities(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}, checkpoint string, handler func(batch []*Identity, nextCheckpoint string) error) error

    // Access provisioning — push grants out to the SaaS
    ProvisionAccess(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}, grant AccessGrant) error
    RevokeAccess(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}, grant AccessGrant) error

    // Access review — pull current entitlements for one user
    ListEntitlements(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}, userExternalID string) ([]Entitlement, error)

    // SSO metadata — for Keycloak federation
    GetSSOMetadata(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) (*SSOMetadata, error)

    // Credential metadata — expiry, scope, key fingerprint
    GetCredentialsMetadata(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) (map[string]interface{}, error)
}
```

| Method | I/O | Failure semantics |
|--------|-----|-------------------|
| `Validate` | **MUST NOT** perform network I/O | error → 4xx during connect; nothing persisted |
| `Connect` | network probe to the provider | error → connect aborts; nothing persisted |
| `VerifyPermissions` | network probe per requested capability | returns `missing []string`; non-empty list surfaced to operator UI |
| `CountIdentities` | cheap header-only request when possible | best-effort; logged but does not fail sync |
| `SyncIdentities` | streaming pages via callback | returning a non-nil error from the handler aborts the sync |
| `ProvisionAccess` | one-shot RPC — must be idempotent on `(grant.UserExternalID, grant.ResourceExternalID)` | 4xx → permanent fail and surface to operator; 5xx → retry with exponential backoff |
| `RevokeAccess` | one-shot RPC — must be idempotent | same retry semantics as `ProvisionAccess` |
| `ListEntitlements` | network call per user | best-effort during a campaign; per-user failures do not fail the campaign |
| `GetSSOMetadata` | usually a metadata-URL fetch | error → SSO federation cannot be configured; user-visible |
| `GetCredentialsMetadata` | optional — returns `{credential_expired_time: time.Time, scopes: []string, ...}` if known | drives expiry alerts and the renewal cron |

### 2.2 Optional capability interfaces

| Interface | Purpose | Required for |
|-----------|---------|--------------|
| `IdentityDeltaSyncer` | `SyncIdentitiesDelta(deltaLink, handler)` returning `batch + removedExternalIDs + nextLink + finalDeltaLink` | Incremental identity sync (Microsoft Graph, Okta, Auth0) |
| `GroupSyncer` | `CountGroups`, `SyncGroups`, `SyncGroupMembers` | Connectors that expose groups / teams as a separate entity from users |
| `AccessAuditor` | `FetchAccessAuditLogs(since, handler)` | Connectors that expose sign-in events or permission-change logs |
| `SCIMProvisioner` | `PushSCIMUser(user)`, `PushSCIMGroup(group)`, `DeleteSCIMResource(id)` | Outbound SCIM v2.0 push to SaaS |

Delta semantics mirror SN360:

- The handler is invoked once per provider page.
- The very last page sets `finalDeltaLink` and an empty `nextLink`. Callers persist `finalDeltaLink` in `access_sync_state`.
- A 410 Gone from the provider MUST be returned as `access.ErrDeltaTokenExpired`. The service catches it, drops the stored delta link, and falls back to a full enumeration.

### 2.3 Canonical record shapes

`Identity`, `AccessGrant`, `Entitlement`, and `SSOMetadata` are minimal by design — provider-specific extras live in `RawData map[string]interface{}` (allowed but not required; production connectors generally set it to `nil` for memory reasons).

```go
type Identity struct {
    ExternalID  string
    Type        IdentityType  // user | group | service_account
    DisplayName string
    Email       string
    ManagerID   string        // provider-side external ID; resolved post-import
    Status      string        // active | disabled | suspended
    GroupIDs    []string
    RawData     map[string]interface{}
}

type AccessGrant struct {
    UserExternalID     string
    ResourceExternalID string
    Role               string   // provider-specific role / SKU / license
    Scope              map[string]interface{}
    GrantedAt          time.Time
    ExpiresAt          *time.Time
}

type Entitlement struct {
    ResourceExternalID string
    Role               string
    Source             string   // direct | group | inherited
    LastUsedAt         *time.Time
    RiskScore          *int     // populated by AI agent later, not by the connector
}
```

---

## 3. Registry & wiring

Same pattern as SN360, in a new package `internal/services/access`.

- Process-global `map[string]AccessConnector` populated by `init()` blocks in each provider package under `internal/services/access/connectors/`.
- Lookups are by lowercased provider key (`"microsoft"`, `"google_workspace"`, `"okta"`, `"generic_saml"`, `"generic_oidc"`).
- Tests legitimately swap registry entries — see the `t.Cleanup` patterns in the SN360 `*_flow_test.go`. Production code never re-registers.
- Every binary that needs a connector at runtime imports the package for its side-effect:
  - `_ "ztna-business-layer/internal/services/access/connectors/microsoft"` (etc.)
  - Wired into `cmd/ztna-api`, `cmd/access-connector-worker`, `cmd/access-workflow-engine`.

### 3.1 Provider key naming convention

| Convention | Example |
|------------|---------|
| Lowercase, snake_case | `microsoft`, `google_workspace`, `okta`, `auth0`, `ping_identity`, `duo_security` |
| Generic protocol connectors prefixed with `generic_` | `generic_saml`, `generic_oidc`, `generic_scim` |
| Provider-key === directory name under `connectors/` | `internal/services/access/connectors/google_workspace/` |

---

## 4. Credential management

Reuses the SN360 credential manager exactly. Source of truth: `shieldnet360-backend/internal/services/integration/service.go:720-809` and `internal/pkg/credentials/manager.go`.

### 4.1 At rest

```
access_connectors.config         jsonb       plaintext, operator-visible
access_connectors.credentials    text        AES-GCM ciphertext over secrets JSON
access_connectors.key_version    int         which org DEK version was used
```

- The DEK is per-organization, fetched via `keymanager.KeyManager.GetLatestOrgDEK(orgID)`.
- The DEK itself is wrapped under a master key (KMS / Vault / dev-only `secrets.Manager`) and cached in memory.
- AES-GCM AAD = the access connector ULID. This binds ciphertext to its row; copy-pasting between connectors renders it undecryptable.

### 4.2 At runtime

- Worker handlers fetch `map[string]interface{}` via `credentialManager.GetCredentials(ctx, accessConnectorID, orgID, keyVersion, ciphertext)`.
- Decrypted secrets are scoped to one job execution and never persisted to logs / metrics.
- `GetCredentialsMetadata` is called only during `Connect` and on demand by the renewal cron, so the platform never decrypts secrets just to know an expiry date.

### 4.3 Rotation

- Operator triggers `UpdateSecret` (handler in `cmd/ztna-api`). The service runs `Validate + Connect` against the new payload, encrypts under the latest DEK, and writes back atomically.
- Org DEK rotation is independent: `KeyManager.RotateOrgDEK` produces a new version. Old ciphertext stays readable because `key_version` on each row pins the DEK that was used. Re-encryption is offline / lazy.

### 4.4 Failure modes

- **Connect succeeds but encryption fails** → row never inserted; operator gets a 500 with a sanitized error (PII / token fragments stripped).
- **Decrypt fails at job time** → handler logs the connector ID and marks the job failed; operator must rotate or reconnect.
- **DEK missing for a `key_version`** → the platform refuses to decrypt rather than degrade silently. Surfaces as a hard failure on the connector page.

---

## 5. Access lifecycle workflow engine

The lifecycle engine is the core of the access platform. It is a deterministic state machine over `access_requests` rows, with optional AI hooks at well-defined transitions.

### 5.1 States

```
requested
    │
    ▼
reviewing ─────┬─────► denied (terminal)
    │          │
    ▼          │
approved       │
    │          │
    ▼          │
provisioning ──┴─────► provision_failed (operator action required)
    │
    ▼
provisioned
    │
    ▼
active
    │
    ▼
review_pending ───┬───► active (recertified)
                  │
                  ▼
                revoked (terminal)
```

State transitions are stored in `access_requests.state` with an audited `access_request_state_history` write on every transition. The engine pattern follows `ztna-business-layer/internal/state_machine/`.

### 5.2 Workflow types

| Workflow | Routing |
|----------|---------|
| `self_service` | Auto-approve when an active policy match exists for the requested grant. AI risk score must be `low`. |
| `manager_approval` | Single-step approval routed to the requester's manager (resolved through the manager-link pass — see SN360 Phase 4.3). |
| `multi_level` | Multiple approvers in sequence (e.g. manager → resource owner → security). |
| `security_review` | Auto-routed when AI risk score is `high` or when the resource is tagged `sensitive`. |

Workflows are configurable per resource category (`access_workflows` rows scoped by `resource_category`, `risk_band`, `requestor_role`).

### 5.3 AI integration points

| Transition | AI agent skill | Effect |
|------------|----------------|--------|
| `requested → reviewing` | `access_risk_assessment` | Populates `access_requests.risk_score` and `risk_factors`. Routes to the right workflow. |
| `provisioned → active` | (none) | Provisioning success is mechanical. |
| `active → review_pending` | `access_review_automation` | Auto-certifies low-risk grants without surfacing them to the reviewer. |
| `active` (continuous) | `access_anomaly_detection` | Flags anomalous usage; can suggest `review_pending` ahead of schedule. |

AI calls are best-effort. If the AI agent server is unavailable, the engine continues with a default risk score of `medium`, routes through `manager_approval`, and emits an alert. AI is decision-support, not in the critical path.

### 5.4 JML automation

Joiner / Mover / Leaver flows are driven by SCIM webhooks (inbound from the IdP) and the periodic IdP identity sync. They re-use the lifecycle engine but pre-resolve the workflow:

- **Joiner** → bulk `access_requests` rows in state `approved` (skips review), provisioning fanned out to all default-policy connectors.
- **Mover** → bulk `revoke` of stale grants + bulk `approved` of new grants, with reconciliation against the new Team membership.
- **Leaver** → bulk `revoked` for every active grant on the user, plus a `disable` on the OpenZiti identity. Synchronous.

---

## 6. Policy simulation engine

The policy simulation engine is the answer to "I'm afraid to change this rule because I don't know what will happen". It is a draft-and-promote system that resolves the impact of a change before it touches the OpenZiti dataplane.

### 6.1 Draft policies

- Drafts are stored in the existing `policies` table with `is_draft = true`.
- Drafts have a non-nullable `draft_impact jsonb` populated at simulation time.
- Drafts **never** create an OpenZiti `ServicePolicy`. They are platform-side abstractions until promotion.
- Drafts inherit org / workspace scoping from the live policy table; the existing tenancy pattern in `ztna-business-layer/internal/service/policies.go` is reused unchanged.

### 6.2 Impact analysis

Given a draft, the simulator resolves:

1. **Affected Teams.** Walk Team-membership rules that match the draft's `attributes` selector.
2. **Affected Members.** Expand each Team to its current users (live snapshot — no caching).
3. **Affected Resources.** Walk the resource selector to resource ULIDs.
4. **Conflicts.** For every `(member, resource)` pair, find existing live policies that already grant or deny that pair. The diff is the impact.

The output is a structured `ImpactReport` stored in `policies.draft_impact`:

```jsonc
{
  "members_gaining_access": 47,
  "members_losing_access": 3,
  "new_resources_granted": 12,
  "resources_revoked": 0,
  "conflicts_with_existing_rules": [
    {
      "rule_id": "...",
      "rule_name": "Engineering — Production Database",
      "kind": "redundant" // or "contradictory"
    }
  ],
  "affected_teams": ["..."],
  "highlights": [
    "47 new people will gain SSH access to prod-db-01",
    "3 people will lose access to staging-finance-app"
  ]
}
```

### 6.3 AI risk assessment

The `access_risk_assessment` server-side agent evaluates the impact report and flags:

- **Over-provisioning.** Granting more access than peers in the same job role.
- **Separation-of-duties violations.** Same user gets approve-payment + execute-payment.
- **Privilege concentration.** Admin role granted to a Team larger than `N` people.
- **Stale-policy risk.** Promoting a draft authored more than `D` days ago without re-simulation.

### 6.4 "What-if" access tester

A standalone endpoint `POST /workspace/policy/test-access` answers `Can user X access resource Y under this draft policy?` without going through full simulation. Used in the admin UI as an interactive sandbox.

### 6.5 Promotion flow

```
draft  ──simulate──►  draft + impact_report  ──admin reviews──►  promote
                                                                      │
                                                                      ▼
                                                       live policy + OpenZiti ServicePolicy
```

Promotion is the only path that creates `ServicePolicy` records. There is no "create live policy directly" code path — every live policy was a draft first, even if for a single second.

---

## 7. AI integration architecture

The platform uses two tiers of server-side AI. **No on-device inference, ever.** Mobile and desktop clients reach AI exclusively through REST.

### 7.1 Tier 1 — Server-side AI agents (A2A protocol)

Extends the pattern in `aisoc-ai-agents/server/src/aisoc_agents/aisoc_agent.py`. Skills are registered on a single `access_agent` server.

| Skill | Purpose |
|-------|---------|
| `access_risk_assessment` | Score policy changes and access requests on a `low / medium / high` scale, with structured `risk_factors`. |
| `access_review_automation` | Auto-certify low-risk grants during a review campaign. |
| `access_anomaly_detection` | Flag unusual usage on active grants (sudden volume, off-hours, geographic outliers). |
| `connector_setup_assistant` | Guide admins through setup in natural language. Maps free-text questions to wizard answers. |
| `policy_recommendation` | Suggest policies given the current org structure (Teams + resources + historical access). |

### 7.2 Tier 2 — Workflow orchestration (LangGraph)

Extends the pattern in `aisoc-workflow-agents/config/agents/lead_orchestrator.toml`. The workflow engine is responsible for:

- Multi-step lifecycle workflows with phase transitions (`requested → reviewed → approved → provisioned`).
- Risk-based routing (`low → auto-approve; medium → manager; high → security review`).
- Escalation workflows with timeout-based auto-escalation.

### 7.3 Client-side SDK / extension contract

The mobile and desktop clients are **integration libraries / extensions** consumed by an existing main application. They expose three logical surfaces over REST:

| Surface | Method | Server endpoint |
|---------|--------|------------------|
| Access query | "I need access to X" → structured `access_requests` row | `POST /access/requests` |
| Policy explanation | Policy ULID → plain-English summary | `POST /access/explain` (delegates to `policy_recommendation` agent) |
| Suggestion | User context → list of recommended resources | `POST /access/suggest` (delegates to `policy_recommendation` agent) |

These are REST API definitions only. There is **no on-device model**, no SLM, no quantized weights bundled into the SDK. Future on-device support is tracked in §12.

---

## 8. SN360 language alignment

Every public-facing string in the admin UI, mobile SDK, desktop extension, and audit log uses the SN360 language column. Internal logs, metrics, code identifiers, and this doc may use the technical column.

| Technical term | SN360 language |
|----------------|----------------|
| ZTNA policy | Access rule |
| Service policy | Connection permission |
| Identity provider | Company directory |
| SCIM provisioning | Auto-sync users |
| Access review campaign | Access check-up |
| Entitlement | App permission |
| Separation of duties | Conflict check |
| Connector | App connection |
| Access certification | Access check-up |
| Access grant | Access |
| Access request | Access request |
| Risk score | Risk level |
| Promote draft policy | Turn the rule on |
| Federated SSO | Single sign-on |
| Tombstone | (internal only — never shown to operators) |

The translation table is enforced by a CI check that greps user-facing message keys for technical terms.

---

## 9. Database schema

All new tables live in the `ztna` schema alongside the existing `policies` and `teams` tables. None of these tables introduce real `FOREIGN KEY` constraints — the SN360 database-index rule is preserved (referential integrity is enforced in application code).

### 9.1 New tables

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `access_connectors` | Per-workspace connector instances | `id ULID`, `workspace_id`, `provider`, `connector_type`, `config jsonb`, `credentials text`, `key_version`, `status`, `credential_expired_time`, `deleted_at` |
| `access_requests` | Lifecycle tracking for one access ask | `id`, `workspace_id`, `requester_user_id`, `target_user_id`, `resource_external_id`, `role`, `state`, `risk_score`, `risk_factors jsonb`, `workflow_id`, `created_at` |
| `access_request_state_history` | Audit trail of state transitions | `request_id`, `from_state`, `to_state`, `actor_user_id`, `reason`, `created_at` |
| `access_grants` | Active entitlements (one row per `(user, resource, role)`) | `id`, `workspace_id`, `user_id`, `connector_id`, `resource_external_id`, `role`, `granted_at`, `expires_at`, `last_used_at`, `revoked_at` |
| `access_reviews` | Periodic certification campaigns | `id`, `workspace_id`, `name`, `scope_filter jsonb`, `due_at`, `state` |
| `access_review_decisions` | Per-grant decision in a campaign | `review_id`, `grant_id`, `decision` (`certify`/`revoke`/`escalate`), `decided_by`, `auto_certified bool`, `reason` |
| `access_workflows` | Configurable approval chains | `id`, `workspace_id`, `name`, `match_rule jsonb`, `steps jsonb` |
| `access_sync_state` | Delta-link / checkpoint store per `(connector_id, kind)` | `connector_id`, `kind`, `delta_link`, `updated_at` |

### 9.2 Schema extensions

| Table | Columns added |
|-------|---------------|
| `policies` | `is_draft bool default false`, `draft_impact jsonb`, `promoted_at timestamp` |

### 9.3 Indexing

Indexes are added only for proven query patterns:

- `access_requests (workspace_id, state)` — list all open requests in a workspace.
- `access_requests (target_user_id, state)` — "what is open for this user".
- `access_grants (user_id, revoked_at)` — active grants per user.
- `access_grants (connector_id, revoked_at)` — active grants per connector (for review campaigns).
- `access_review_decisions (review_id, decision)` — campaign progress.

No `FOREIGN KEY` constraints. Application code enforces referential integrity (mirrors the SN360 pattern).

---

## 10. Deployment model

| Component | Process | Container image | Notes |
|-----------|---------|-----------------|-------|
| `ztna-api` | extended `cmd/ztna-api` | shared image | Adds `/access/*` routes, draft-policy routes, AI delegation routes |
| `access-connector-worker` | new `cmd/access-connector-worker` | `docker/Dockerfile.access-worker` | Runs `SyncIdentities`, `ProvisionAccess`, `RevokeAccess`, `ListEntitlements` jobs from Redis queue |
| `access-ai-agent` | new Python service | `docker/Dockerfile.access-ai-agent` | A2A skill server hosting the five Tier-1 skills |
| `access-workflow-engine` | new Go service | `docker/Dockerfile.access-workflow` | LangGraph orchestrator wired against `ztna-api` and `access-ai-agent` |
| `keycloak` | existing | unchanged | New realms / IdP brokers configured per connector |
| `openziti-controller` | existing | unchanged | Receives `ServicePolicy` writes only on draft promotion |

### 10.1 Required infra

- PostgreSQL (reuses the `ztna` schema; new tables in §9).
- Redis (queue, distributed locks, sync staging).
- Kafka (audit envelope reuse — same `ShieldnetLogEvent v1` schema).
- KMS-equivalent secret backend for the master key (same as SN360).

### 10.2 Required env

A new `internal/config/access.go` will be authoritative. Notable knobs:

- `ACCESS_AI_AGENT_BASE_URL` / `ACCESS_AI_AGENT_API_KEY`
- `ACCESS_WORKFLOW_ENGINE_BASE_URL`
- `ACCESS_FULL_RESYNC_INTERVAL` (default 7 days, mirrors SN360's `INTEGRATION_FULL_RESYNC_INTERVAL`)
- `ACCESS_REVIEW_DEFAULT_FREQUENCY` (default 90 days)
- `ACCESS_DRAFT_POLICY_STALE_AFTER` (default 14 days)

### 10.3 Public network exposure

Only `ztna-api` (and the Keycloak public ingress) is exposed publicly. `access-ai-agent` and `access-workflow-engine` live on the cluster-internal network and authenticate via shared secret (`X-API-Key`).

---

## 11. Client SDK / extension specification

All three clients are **integration packages** for an existing host application. None of them is a standalone product, and none of them does on-device inference.

### 11.1 iOS Access SDK (Swift Package)

- Distributed as a Swift Package via the internal package registry.
- Exposes Swift protocols for: list / create access requests, query draft / live policies, ask the AI assistant.
- Networking is a thin `URLSession` wrapper. Auth tokens are passed in by the host app (the SDK does not own login state).
- No `CoreML`, no `MLX`, no on-device model files. The SDK declares a hard rule: any inference call is a REST call.

### 11.2 Android Access SDK (Kotlin library)

- Distributed as an AAR via the internal Maven registry.
- Same logical interface as iOS — list / create requests, policy queries, AI assistant.
- Networking via `OkHttp`. Auth tokens injected by the host app.
- No `TensorFlow Lite`, no `ONNX Runtime`, no bundled weights. REST only.

### 11.3 Desktop Access Extension (Electron IPC module)

- Distributed as an npm package consumed by the host Electron app.
- Exposes an IPC surface: `access.requestAccess`, `access.listGrants`, `access.queryPolicy`, `access.askAI`.
- Renderer-side React components shipped in the same package for the access management screens.
- Main-process side talks to `ztna-api` over REST. No native inference binaries.

### 11.4 Shared REST API

All three SDKs target the same REST surface on `ztna-api`:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/access/requests` | Create an access request |
| `GET` | `/access/requests` | List requests (filtered by state, requester, resource) |
| `POST` | `/access/requests/:id/approve` | Approve (subject to workflow) |
| `POST` | `/access/requests/:id/deny` | Deny |
| `POST` | `/access/requests/:id/cancel` | Requester cancels their own |
| `GET` | `/access/grants` | List active grants for the calling user |
| `POST` | `/access/explain` | Plain-English explanation of a policy or grant |
| `POST` | `/access/suggest` | Recommended resources for the calling user |
| `POST` | `/access/test` | "Can user X access resource Y under draft policy P?" |

---

## 13. Hybrid Access Model (Phase 11)

Phase 11 extends the access platform with a hybrid access posture so the
operator can run a SaaS-heavy workload without paying OpenZiti tunnel
overhead, while still safely off-boarding leavers across every channel
the user has access to.

### 13.1 Access mode classification (per connector)

Every `access_connectors` row carries an `access_mode` column with one of
three values:

- `tunnel` — private / self-hosted resource fronted by an OpenZiti
  dataplane tunnel. Default for connectors whose `connector_type`
  declares a private endpoint.
- `sso_only` — SaaS app federated through Keycloak. The platform never
  pushes grants and never opens a tunnel for `sso_only` rows; the SAML /
  OIDC redirect IS the access. Auto-classified at Connect time when
  `GetSSOMetadata` returns a non-nil metadata block and the Keycloak
  federation handshake succeeds.
- `api_only` — SaaS app reachable directly via the connector's REST
  surface. Default for everything else.

The mode is operator-overridable via `PATCH /access/connectors/:id`. The
classification is surfaced from `PolicyService.Promote` so the
`ztna-business-layer` can skip the OpenZiti `ServicePolicy` write for
`sso_only` / `api_only` rows.

### 13.2 SSO-only enforcement verification

Connectors that federate through Keycloak optionally implement
`SSOEnforcementChecker.CheckSSOEnforcement`. The connector setup flow
calls the checker after SSO federation succeeds and includes a warning
in the connect response when password-login is still permitted upstream.
The connector health endpoint surfaces `sso_enforcement_status` so the
admin UI can render an "SSO-only mode is OFF" warning that operators can
remediate without leaving the dashboard. The orphan reconciler re-checks
this status on every daily pass.

Top-six implementations: Salesforce, Google Workspace, Okta, Slack,
GitHub, Microsoft.

### 13.3 Session revocation (kill the live session, not just the grant)

Phase 5 revoke removed the upstream entitlement but did not kick the
user out of any session they had already established. Phase 11 adds the
`SessionRevoker.RevokeUserSessions` optional capability and implements
it for the highest-impact connectors:

| Connector | Upstream endpoint |
|-----------|-------------------|
| Okta | `DELETE /api/v1/users/{userId}/sessions` |
| Google Workspace | `POST /admin/directory/v1/users/{userKey}/signOut` |
| Microsoft (Graph) | `POST /users/{id}/revokeSignInSessions` |
| Salesforce | `DELETE /services/oauth2/revoke` |
| Slack | `POST /auth.revoke` |
| Auth0 | `POST /api/v2/users/{id}/multifactor/actions/invalidate-remember-browser` |
| GitHub | org membership removal |

All session-revocation calls are best-effort: failures are logged but
never block the rest of the leaver flow.

### 13.4 Unused app-account reconciliation (orphan accounts)

The reconciler periodically asks every connector "who do you see?" and
cross-references the result against the IdP-side `team_members` pivot.
Upstream users with no IdP record are persisted to
`access_orphan_accounts` (status `detected`). Operators see them in the
admin UI labelled as "unused app accounts" (SN360 language) and may
either revoke (`auto_revoked`), dismiss permanently (`dismissed`), or
acknowledge (`acknowledged`).

The reconciler runs on a configurable schedule
(`ACCESS_ORPHAN_RECONCILE_INTERVAL`, default `24h`). New detections
fire a notification through the existing `NotificationService`.

### 13.5 Six-layer leaver kill switch

The Phase 4 leaver flow used to do two things: revoke active grants and
remove team memberships. Phase 11 extends `JMLService.HandleLeaver` into
a six-layer kill switch so a single off-boarding call locks the user
out of every channel the platform knows about:

1. Revoke all active access grants (existing).
2. Remove team memberships (existing).
3. Disable the Keycloak user (kill SSO at the IdP).
4. Revoke active sessions across every connector implementing
   `SessionRevoker` (kill SaaS sign-in tokens).
5. SCIM-deprovision across every connector implementing
   `SCIMProvisioner` (drop the upstream user object).
6. Disable the OpenZiti identity (kill tunnel access; existing).

Every layer is best-effort: a failure in any one layer logs but does
not block the others. The flow is idempotent — replaying it on a
half-applied leaver is safe.

### 13.6 Automatic grant expiry enforcement

`GrantExpiryEnforcer` is the Phase 11 cron job that runs every
`ACCESS_GRANT_EXPIRY_CHECK_INTERVAL` (default `1h`) and revokes every
`access_grants` row whose `expires_at` has passed. Revocation goes
through the same `AccessProvisioningService.Revoke` path as the
reviewer-driven Phase 5 flow so the upstream side-effects (connector
revoke + DB stamp + audit event) are identical regardless of trigger.

This closes the "approved JIT grant that nobody bothers to clean up"
gap and makes time-bounded access posture the default.

---

## 14. Open questions / future work

Listed so they don't get rediscovered:

1. **On-device SLM inference for mobile / desktop.** Deferred. The SDK / extension surface is defined here so the future swap from "REST only" to "REST + local fallback" is non-breaking. No timeline.
2. **Streaming-protocol connectors** (WebSocket, gRPC server-streaming). Today every connector is request-response. Adding a long-lived stream needs a new optional capability interface and a re-think of the worker model.
3. **Per-tenant Kafka quotas for access audit logs.** Same blast-radius vs throughput tension SN360 already lives with (PROPOSAL §9.2 in `shieldnet360-backend`). Operator-side policy.
4. **Multi-region access connector worker routing.** Today connector-worker URL is resolved from a single per-org resource key. Multi-region routing + circuit-breaking is parked.
5. **Federated review campaigns** that span multiple workspaces (e.g. M&A scenarios). Not in scope; tracked only here.
6. **Operator-facing policy DSL.** The platform is wizard-first by design; a DSL is power-user territory and would compete with the SN360-language goal. Re-evaluate after Phase 4.
