# Changelog

All notable changes to the ShieldNet 360 Access Platform are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Component-level changelogs:
- iOS SDK — [`sdk/ios/CHANGELOG.md`](sdk/ios/CHANGELOG.md)
- Android SDK — [`sdk/android/CHANGELOG.md`](sdk/android/CHANGELOG.md)
- Desktop extension — [`sdk/desktop/CHANGELOG.md`](sdk/desktop/CHANGELOG.md)

## Unreleased

### Added (PAM)

- **PAM data model** — 8 GORM models (`PAMAsset`, `PAMAccount`, `PAMSecret`, `PAMSession`, `PAMSessionCommand`, `PAMLease`, `PAMCommandPolicy`, `PAMRotationSchedule`) plus migration `016_create_pam_tables.go`.
- **PAMAssetService** — asset + account CRUD with workspace scoping and protocol / criticality / port validation.
- **SecretBrokerService** — vault, reveal-with-step-up-MFA, rotate, rotation history, check-out, and inject — reusing the existing AES-GCM `CredentialEncryptor`.
- **MFAVerifier interface** — `NoOpMFAVerifier` for dev / test wiring; `RevealSecretHandler` returns 503 when no verifier is configured.
- **PAMLeaseService** — JIT lease lifecycle (request → approve → revoke / expire) integrated with `AccessRequestService` via the narrow `AccessRequestCreator` interface.
- **PAMLeaseExpiryEnforcer cron** — configurable tick via `PAM_LEASE_EXPIRY_CHECK_INTERVAL` (default 1m), per-lease session-termination hook, structured `pam_lease_expiry_summary` log.
- **PAM workflow templates** — seed migration `017_seed_pam_workflow_templates.go` for `pam_session_low_risk`, `pam_session_standard`, `pam_session_critical`.
- **HTTP surface** — `/pam/assets/*`, `/pam/secrets/*`, `/pam/leases/*`, `/pam/sessions/*`, `/pam/policies/*` with nil-safe wiring into the existing `handlers.Dependencies` struct.
- **`pam-gateway` binary** (`cmd/pam-gateway/`) — SSH listener with one-shot connect-token auth against `ztna-api`, short-lived CA-signed certificate issuance, and injected-credential fallback. Library code lives in `internal/gateway/` so the SSH paths are unit-testable without booting the binary.
- **SSH session recording + per-command audit** — `IORecorder` writes a framed binary blob of session I/O to a `ReplayStore` (S3-compatible, with a local-disk dev sink); `CommandParser` feeds per-command audit rows into a worker-serialised `APICommandSink` that POSTs to `/pam/sessions/:id/commands`. `SSHListener.handleChannel` now forwards channel requests (shell / pty-req / env / window-change), closes upstream stdin on operator EOF, and forwards the upstream exit-status.
- **Kubernetes exec gateway** — WebSocket bridge to a target K8s API server's `pods/exec` endpoint with operator-token auth against `ztna-api`, namespace / pod / container validation against the issued lease, per-session service-account token or kubeconfig injection via `SecretInjector`, and stdin / stdout / stderr teed through the recorder + command parser pipeline.
- **Database gateways** — PostgreSQL (port 5432) and MySQL / MariaDB (port 3306) wire-protocol proxies that speak the real startup → auth → query frames. Each Simple Query / `COM_QUERY` is captured as a `pam_session_commands` row with a SHA-256 of the result-set bytes, evaluated against the command policy engine before forwarding, and proxied back with a plain-language reason on deny. `db_ws_handler.go` exposes the same surface over a browser WebSocket so the future SQL console can speak straight to the gateway.
- **`PAMAuditService` + Kafka audit producer** — immutable `pam.session.*` / `pam.secret.*` / `pam.lease.*` events on the existing `ShieldnetLogEvent` envelope, replay-bytes stored under `sessions/{id}/replay.bin` in S3 with 15-minute pre-signed GETs, command-timeline + force-terminate + evidence-pack export handlers.
- **AI risk assessment for PAM sessions** — `pam_session_risk_assessment` A2A skill (`cmd/access-ai-agent/skills/pam_session_risk.py`) computing unusual-time, first-time-asset, repeated-denials, and emergency-access-rate factors with a deterministic recommendation; Go side calls it through the existing `aiclient.AssessRiskWithFallback` helper.
- **`PAMCommandPolicyService`** — regex-pattern allow / deny / step_up evaluation against `pam_command_policies` in priority order with workspace + asset + account selectors. Wired into the SSH / K8s / PG / MySQL listeners through `APIPolicyEvaluator` so every command is filtered in real-time; `step_up` outcomes toggle the `risk_flag` on the captured command row.
- **Mobile SDK PAM extensions** — `PAMSDKClient` on both iOS (Swift `PAMSDKProtocol` + `URLSessionPAMSDKClient`) and Android (Kotlin `PAMSDKClient` + `OkHttpPAMSDKClient`). Pure-function `parseApprovalNotification` runs from `UNNotificationServiceExtension` / `FirebaseMessagingService` without I/O; constant-time byte-equal `verifyMatchedCode` defends against stolen-device attacks; `approveLease` / `denyLease` route to `POST /pam/leases/:id/approve|revoke`; `revealSecret` posts a `PassKeyAssertion` to `POST /pam/secrets/:id/reveal` for FIDO2/WebAuthn step-up. SDKs reuse the existing `AccessSDKError` / `AccessSDKException` surface so host apps can branch on transport / auth / decoding failures uniformly.

## 0.1.0

### Added

- **200 connectors** across identity, cloud, SaaS, HR/finance, security, and verticals. Each implements the `AccessConnector` interface with identity sync, access provisioning, entitlement listing, audit, and SSO federation where supported.
- **Access request workflow** — self-service requests with AI risk scoring, policy-based auto-approval, manager and multi-level approval workflows.
- **Policy simulation engine** — draft access rules with impact analysis, conflict detection, and AI risk assessment before one-click promotion.
- **Access review campaigns** — scheduled certification with AI auto-certification of low-risk grants, email / Slack / WebPush notifications.
- **Server-side AI agents** — five A2A skills (risk assessment, review automation, anomaly detection, setup assistant, policy recommendation) with deterministic fallbacks.
- **JML automation** — joiner / mover / leaver flows via inbound SCIM, with outbound SCIM provisioning across 8 Tier-1 connectors.
- **Workflow orchestration** — LangGraph-style engine with linear and DAG runtimes, risk-based routing, escalation, retry / DLQ.
- **Mobile and desktop SDKs** — iOS (Swift Package), Android (Kotlin/Maven), Desktop (Electron/npm). REST-only, no on-device inference.
- **Hybrid access model** — per-connector access-mode classification (`tunnel` / `sso_only` / `api_only`), six-layer leaver kill switch, orphan account reconciler, SSO enforcement verification, automatic grant expiry.
- **AES-GCM credential encryption** at rest for all connector credentials.
- **Request-ID correlation** — `X-Request-ID` header on every HTTP response, threaded into logs and error envelopes.
- **Infrastructure** — multi-stage Dockerfiles, docker-compose local stack, Kubernetes manifests (Kustomize + Helm), CI workflows, OpenAPI 3.0 spec.
