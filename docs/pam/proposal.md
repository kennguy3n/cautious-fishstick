# ShieldNet PAM — Feature Proposal

## Problem statement

SMEs need PAM capabilities without classic enterprise PAM overhead. They have privileged accounts (cloud admin, database root, SSH keys, shared service accounts) but lack dedicated identity teams to manage vault-first bastion products. The current ShieldNet Access Platform governs SaaS access lifecycle but does not broker privileged infrastructure sessions, manage shared secrets, or capture session-level evidence.

## Target user

- SME IT generalists who manage 5–500 infrastructure assets alongside SaaS.
- Compliance officers who need audit evidence for SOC 2, PCI DSS, and ISO 27001.
- Contractors and vendors who need time-bounded, supervised access to customer environments.

## Core judgement

Build an identity-first privileged access broker, not a heavyweight vault-first bastion clone. The default workflow should be: verify identity and device → approve the request → broker the session → inject the secret if needed → record the evidence. Vault and reveal are fallback paths, not the primary experience.

## Assurance model

| Mode | When | Operator explanation |
|---|---|---|
| Allow | Low-risk action, approved identity, trusted device | "Access granted — your identity and device meet the policy" |
| Step up | Sensitive action (secret reveal, policy change, session share, emergency checkout) | "Please confirm with your passkey before viewing this secret" |
| Approve | Crown-jewel access, contractor access, break-glass | "Your request needs approval from [approver] — they'll see the risk summary and evidence plan" |
| Deny | Conditions fail, policy conflict, device untrusted, risk too high | "Access denied — [plain-language reason]" |

Authentication priority: Passkeys (FIDO2/WebAuthn) primary → TOTP fallback → SMS/email recovery-only.

## What ships in Phase 1 (ShieldNet Access Privileged)

1. **Asset and account inventory** — register infrastructure assets (servers, databases, K8s clusters) with protocol, owner, criticality, and account mappings. Auto-discovery deferred.
2. **Just-in-time access** — request, approve, lease, auto-expire. No permanent standing grant by default for crown-jewel assets. Reuses the existing `AccessRequestService` state machine ([`internal/services/access/request_service.go`](../../internal/services/access/request_service.go)).
3. **Brokered SSH sessions** — browser-based SSH terminal via WebSocket. Session recording (command + output). Secret injection (SSH CA short-lived certs preferred, injected password/key fallback).
4. **Brokered Kubernetes sessions** — `kubectl exec` proxy with command capture.
5. **Brokered database sessions** — browser SQL console for PostgreSQL and MySQL. Query capture and audit.
6. **Secret broker** — vault, rotate, check-out, inject. Envelope encryption with KMS-backed DEK (extends existing `ACCESS_CREDENTIAL_DEK` pattern in [`internal/services/access/aesgcm_encryptor.go`](../../internal/services/access/aesgcm_encryptor.go)). Approval-aware reveal with step-up MFA.
7. **Audit and evidence service** — immutable event trail, session replay metadata, command/query capture, file transfer evidence. Extends existing Kafka `ShieldnetLogEvent v1` envelope used by [`internal/services/access/audit_producer.go`](../../internal/services/access/audit_producer.go).
8. **Mobile approval** — push approval with number matching via the existing SN360 mobile SDK. Passkey assertion for step-up.
9. **AI risk assessment** — new `pam_session_risk_assessment` A2A skill. Unusual access path, unusual time, repeated denials, emergency access rate.
10. **Minimal admin UI** — asset registration wizard, session list with replay, secret operations page. Added as routes in the existing `ztna-frontend` React app. No standalone PAM UI.

## What ships in Phase 2

- Windows RDP graphical gateway (Rust, narrow scope — RDP proxy + browser stream + replay).
- Password rotation automation (cron-driven, per-account policy).
- Account hygiene detection (dormant admin, weak/duplicate password, expired credentials).
- Vendor portal with sponsor workflow.
- SIEM and ticketing integrations (ServiceNow, Jira ticket linking, Slack/Teams approval).
- Live session intervention (terminate, pause, takeover for SSH/DB sessions).

## What ships in Phase 3

- Windows RemoteApp publishing.
- Linux graphical app publishing.
- Machine secret and workload identity management.
- Endpoint privilege elevation and delegation (PEDM).
- Behavioural analytics and Defense-driven narrative summaries.

## What is explicitly deferred

- Full auto-discovery of infrastructure assets (Phase 1 is manual + CSV import).
- VNC proxy (Phase 2+ after RDP).
- Face recognition MFA.
- Heavyweight desktop client (lightweight native bridge only).
- On-device inference for PAM risk (server-side only, per existing SN360 rule enforced by [`scripts/check_no_model_files.sh`](../../scripts/check_no_model_files.sh)).

## Design constraints

- **Minimal UI** — core functionality first. The operator interacts through the existing admin console, approval notifications, and the browser terminal. No new standalone app.
- **Automation-first** — lease auto-expiry, rotation cron, hygiene scanning, session auto-recording, risk auto-assessment. If it can be automated, it must be automated.
- **Plain language** — every denial, step-up, and approval surfaces a human-readable explanation (extends the product language table in [`docs/overview.md`](../overview.md)).
- **Existing stack only** — Go for the control plane and text-protocol gateways, Python for AI skills, React for UI, Swift/Kotlin for mobile. Rust only for Phase 2 RDP/VNC. No new languages in Phase 1.
- **Existing infrastructure only** — PostgreSQL, Redis, Kafka, S3-compatible object storage for replays. No new databases in Phase 1. OpenSearch deferred to Phase 2 for full-text command search.

## Product language additions

The existing product language table in [`docs/overview.md`](../overview.md) is extended with PAM-specific terms. The admin UI, mobile SDK, desktop extension, and operator-facing audit log use the right-hand column; internal code, logs, and metrics use the left-hand column.

| Technical term            | Product language        |
|---------------------------|-------------------------|
| Privileged session        | Secure connection       |
| Secret vault              | Credential safe         |
| Lease                     | Time-limited access     |
| Just-in-time access       | Access on request       |
| Step-up MFA               | Extra confirmation      |
| Session replay            | Connection recording    |
| Command policy            | Allowed actions list    |
| Secret rotation           | Credential refresh      |
| Break-glass access        | Emergency override      |
| Number matching           | Confirm-the-number prompt |
| Asset                     | Connected system        |
| Privileged account        | Admin account           |
| Crown-jewel asset         | Critical system         |

## Success metrics (Phase 1)

- 90%+ of privileged sessions brokered through the platform within 90 days of rollout.
- Median time-from-request-to-active-session under 60 seconds for low-risk patterns.
- Zero plaintext credentials shared outside the platform once PAM is enabled.
- 100% of brokered sessions produce a replay artefact and Kafka audit envelope.
- Audit-export-ready evidence pack generated in under 5 minutes for any historical session.

## Where to read next

- [README.md](README.md) — module landing page and quick orientation.
- [architecture.md](architecture.md) — service map, data model, protocol flows.
- [progress.md](progress.md) — phased milestone checklist.
