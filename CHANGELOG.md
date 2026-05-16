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
- **HTTP surface** — `/pam/assets/*`, `/pam/secrets/*`, `/pam/leases/*` with nil-safe wiring into the existing `handlers.Dependencies` struct.
- **`pam-gateway` binary** (`cmd/pam-gateway/`) — SSH listener with one-shot connect-token auth against `ztna-api`, short-lived CA-signed certificate issuance, and injected-credential fallback. Library code lives in `internal/gateway/` so the SSH paths are unit-testable without booting the binary.

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
