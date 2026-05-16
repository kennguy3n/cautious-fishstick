# Changelog

All notable changes to the ShieldNet 360 Access Platform are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Component-level changelogs:
- iOS SDK — [`sdk/ios/CHANGELOG.md`](sdk/ios/CHANGELOG.md)
- Android SDK — [`sdk/android/CHANGELOG.md`](sdk/android/CHANGELOG.md)
- Desktop extension — [`sdk/desktop/CHANGELOG.md`](sdk/desktop/CHANGELOG.md)

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
