# ShieldNet PAM — Development Progress

Status legend: ⬜ Not started | 🟡 In progress | ✅ Complete

## Phase 1 — ShieldNet Access Privileged

### Milestone 1: Foundation (Data model + Asset inventory)

- ⬜ Create `internal/models/pam_asset.go` — PAMAsset GORM model
- ⬜ Create `internal/models/pam_account.go` — PAMAccount GORM model
- ⬜ Create `internal/models/pam_secret.go` — PAMSecret GORM model
- ⬜ Create `internal/models/pam_session.go` — PAMSession GORM model
- ⬜ Create `internal/models/pam_session_command.go` — PAMSessionCommand GORM model
- ⬜ Create `internal/models/pam_lease.go` — PAMLease GORM model
- ⬜ Create `internal/models/pam_command_policy.go` — PAMCommandPolicy GORM model
- ⬜ Create `internal/models/pam_rotation_schedule.go` — PAMRotationSchedule GORM model
- ⬜ Create `internal/migrations/0XX_create_pam_tables.go` — GORM auto-migrate for all PAM tables
- ⬜ Create `internal/services/pam/asset_service.go` — CRUD for assets + accounts
- ⬜ Create `internal/handlers/pam_asset_handler.go` — HTTP handlers for `/pam/assets/*`
- ⬜ Wire PAMAssetService into `router.go` Dependencies
- ⬜ Tests: asset CRUD happy path + validation + not-found

### Milestone 2: Secret Broker

- ⬜ Create `internal/services/pam/secret_broker.go` — vault, encrypt, rotate, check-out, inject, reveal
- ⬜ Extend AESGCMEncryptor for `pam_secrets` (reuse existing DEK pattern)
- ⬜ Create `internal/handlers/pam_secret_handler.go` — HTTP handlers for `/pam/secrets/*`
- ⬜ Step-up MFA gate on reveal endpoint (passkey assertion or TOTP)
- ⬜ Wire SecretBrokerService into `router.go` Dependencies
- ⬜ Tests: vault + reveal + rotation + encryption round-trip

### Milestone 3: JIT Lease Service

- ⬜ Create `internal/services/pam/lease_service.go` — request, approve, auto-expire
- ⬜ Integrate with existing `AccessRequestService` state machine (new `request_type: "pam_session"`)
- ⬜ Seed PAM workflow templates in migrations (extends `008_seed_workflow_templates` pattern)
- ⬜ Create `internal/cron/pam_lease_expiry_enforcer.go` — auto-revoke expired leases
- ⬜ Create `internal/handlers/pam_lease_handler.go` — HTTP handlers for `/pam/leases/*`
- ⬜ Wire into notification service for approval prompts
- ⬜ Tests: lease lifecycle + auto-expiry + approval flow

### Milestone 4: PAM Gateway — SSH

- ⬜ Create `cmd/pam-gateway/main.go` — new Go binary entry point
- ⬜ Implement SSH listener with token-based auth against `ztna-api`
- ⬜ SSH CA short-lived certificate issuance (preferred path)
- ⬜ Injected password/key fallback for legacy targets
- ⬜ I/O stream capture → S3 replay storage
- ⬜ Command parsing and per-command audit logging to `pam_session_commands`
- ⬜ Create `docker/Dockerfile.pam-gateway`
- ⬜ Add `pam-gateway` to `docker-compose.yml`
- ⬜ Tests: SSH session lifecycle + recording + command capture

### Milestone 5: PAM Gateway — Kubernetes

- ⬜ `kubectl exec` proxy via `pam-gateway`
- ⬜ Namespace and pod-level command capture
- ⬜ Short-lived kubeconfig or service-account token injection
- ⬜ Tests: K8s session brokering + command audit

### Milestone 6: PAM Gateway — Database

- ⬜ PostgreSQL wire-protocol proxy in `pam-gateway`
- ⬜ MySQL wire-protocol proxy in `pam-gateway`
- ⬜ Browser SQL console (WebSocket → `pam-gateway` → DB)
- ⬜ Query capture and per-query audit logging
- ⬜ Tests: DB session + query capture + injection

### Milestone 7: Audit and Evidence

- ⬜ Create `internal/services/pam/audit_service.go` — immutable event capture, replay metadata, export
- ⬜ Kafka integration — new event types: `pam.session.*`, `pam.secret.*`, `pam.lease.*`
- ⬜ S3 replay storage integration (signed URL issuance for playback)
- ⬜ Create `internal/handlers/pam_audit_handler.go` — replay URL, command timeline, evidence export
- ⬜ Tests: audit event emission + replay retrieval

### Milestone 8: AI Risk Assessment

- ⬜ Create `cmd/access-ai-agent/skills/pam_session_risk.py` — risk scoring for PAM session requests
- ⬜ Wire into PAMSessionService via A2A (same pattern as `access_risk_assessment`)
- ⬜ Risk factors: unusual time, unusual asset, repeated denials, emergency access rate, first-time asset access
- ⬜ Tests: risk skill happy path + fallback when agent unavailable

### Milestone 9: Command Policy Engine

- ⬜ Create `internal/services/pam/command_policy_service.go` — command allow/deny/step_up evaluation
- ⬜ `pam-gateway` integration — real-time command filtering during active sessions
- ⬜ Tests: allow/deny matching + priority ordering

### Milestone 10: Mobile Approval Integration

- ⬜ Extend iOS SDK (`sdk/ios/`) — PAM approval push with number matching
- ⬜ Extend Android SDK (`sdk/android/`) — PAM approval push with number matching
- ⬜ Passkey step-up assertion flow for secret reveal via mobile
- ⬜ Tests: mobile approval contract tests

### Milestone 11: Admin UI (minimal)

- ⬜ Asset registration wizard in `ztna-frontend`
- ⬜ Session list with replay player component
- ⬜ Secret operations page (vault, metadata, rotation status)
- ⬜ Lease dashboard (active leases, pending approvals)
- ⬜ PAM-specific plain-language explanation panel

### Milestone 12: Deployment and CI

- ⬜ Kubernetes manifests: `deploy/k8s/pam-gateway/`
- ⬜ Helm templates: `deploy/helm/shieldnet-access/templates/pam-gateway.yaml`
- ⬜ CI workflow updates for `pam-gateway` build and test
- ⬜ Integration tests: end-to-end PAM session flow
- ⬜ Documentation: update root `README.md` with PAM section
- ⬜ Documentation: update `docs/architecture.md` with PAM component map
- ⬜ Documentation: update `cmd/README.md` with `pam-gateway` binary

## Phase 2 — Last Mile + Automation (future)

- ⬜ Windows RDP graphical gateway (Rust)
- ⬜ Password rotation automation cron
- ⬜ Account hygiene scanner (dormant, weak, duplicate)
- ⬜ Vendor portal + sponsor workflow
- ⬜ SIEM export + ticketing integration
- ⬜ Live session intervention (terminate/pause/takeover)
- ⬜ OpenSearch for full-text command search

## Phase 3 — Premium Surfaces (future)

- ⬜ Windows RemoteApp publishing
- ⬜ Linux graphical app publishing
- ⬜ Machine secret / workload identity management
- ⬜ Endpoint privilege elevation (PEDM)
- ⬜ Behavioural analytics + Defense narrative
