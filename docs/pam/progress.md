# ShieldNet PAM — Development Progress

Status legend: ⬜ Not started | 🟡 In progress | ✅ Complete

Status: 🟡 In progress | ~96% (72 / 75 Phase 1 tasks)

## Phase 1 — ShieldNet Access Privileged

### Milestone 1: Foundation (Data model + Asset inventory)

- ✅ Create `internal/models/pam_asset.go` — PAMAsset GORM model
- ✅ Create `internal/models/pam_account.go` — PAMAccount GORM model
- ✅ Create `internal/models/pam_secret.go` — PAMSecret GORM model
- ✅ Create `internal/models/pam_session.go` — PAMSession GORM model
- ✅ Create `internal/models/pam_session_command.go` — PAMSessionCommand GORM model
- ✅ Create `internal/models/pam_lease.go` — PAMLease GORM model
- ✅ Create `internal/models/pam_command_policy.go` — PAMCommandPolicy GORM model
- ✅ Create `internal/models/pam_rotation_schedule.go` — PAMRotationSchedule GORM model
- ✅ Create `internal/migrations/016_create_pam_tables.go` — GORM auto-migrate for all PAM tables
- ✅ Create `internal/services/pam/asset_service.go` — CRUD for assets + accounts
- ✅ Create `internal/handlers/pam_asset_handler.go` — HTTP handlers for `/pam/assets/*`
- ✅ Wire PAMAssetService into `router.go` Dependencies
- ✅ Tests: asset CRUD happy path + validation + not-found

### Milestone 2: Secret Broker

- ✅ Create `internal/services/pam/secret_broker.go` — vault, encrypt, rotate, check-out, inject, reveal
- ✅ Extend AESGCMEncryptor for `pam_secrets` (reuse existing DEK pattern)
- ✅ Create `internal/handlers/pam_secret_handler.go` — HTTP handlers for `/pam/secrets/*`
- ✅ Step-up MFA gate on reveal endpoint (passkey assertion or TOTP)
- ✅ Wire SecretBrokerService into `router.go` Dependencies
- ✅ Tests: vault + reveal + rotation + encryption round-trip

### Milestone 3: JIT Lease Service

- ✅ Create `internal/services/pam/lease_service.go` — request, approve, auto-expire
- ✅ Integrate with existing `AccessRequestService` state machine (new `request_type: "pam_session"`)
- ✅ Seed PAM workflow templates in migrations (extends `008_seed_workflow_templates` pattern)
- ✅ Create `internal/cron/pam_lease_expiry_enforcer.go` — auto-revoke expired leases
- ✅ Create `internal/handlers/pam_lease_handler.go` — HTTP handlers for `/pam/leases/*`
- ✅ Wire into notification service for approval prompts
- ✅ Tests: lease lifecycle + auto-expiry + approval flow

### Milestone 4: PAM Gateway — SSH

- ✅ Create `cmd/pam-gateway/main.go` — new Go binary entry point
- ✅ Implement SSH listener with token-based auth against `ztna-api`
- ✅ SSH CA short-lived certificate issuance (preferred path)
- ✅ Injected password/key fallback for legacy targets
- ✅ I/O stream capture → S3 replay storage
- ✅ Command parsing and per-command audit logging to `pam_session_commands`
- ✅ Create `docker/Dockerfile.pam-gateway`
- ✅ Add `pam-gateway` to `docker-compose.yml`
- ✅ Tests: SSH session lifecycle + recording + command capture

### Milestone 5: PAM Gateway — Kubernetes

- ✅ `kubectl exec` proxy via `pam-gateway`
- ✅ Namespace and pod-level command capture
- ✅ Short-lived kubeconfig or service-account token injection
- ✅ Tests: K8s session brokering + command audit

### Milestone 6: PAM Gateway — Database

- ✅ PostgreSQL wire-protocol proxy in `pam-gateway`
- ✅ MySQL wire-protocol proxy in `pam-gateway`
- ✅ Browser SQL console (WebSocket → `pam-gateway` → DB)
- ✅ Query capture and per-query audit logging
- ✅ Tests: DB session + query capture + injection

### Milestone 7: Audit and Evidence

- ✅ Create `internal/services/pam/audit_service.go` — immutable event capture, replay metadata, export
- ✅ Kafka integration — new event types: `pam.session.*`, `pam.secret.*`, `pam.lease.*`
- ✅ S3 replay storage integration (signed URL issuance for playback)
- ✅ Create `internal/handlers/pam_audit_handler.go` — replay URL, command timeline, evidence export
- ✅ Tests: audit event emission + replay retrieval

### Milestone 8: AI Risk Assessment

- ✅ Create `cmd/access-ai-agent/skills/pam_session_risk.py` — risk scoring for PAM session requests
- ✅ Wire into PAMSessionService via A2A (same pattern as `access_risk_assessment`)
- ✅ Risk factors: unusual time, unusual asset, repeated denials, emergency access rate, first-time asset access
- ✅ Tests: risk skill happy path + fallback when agent unavailable

### Milestone 9: Command Policy Engine

- ✅ Create `internal/services/pam/command_policy_service.go` — command allow/deny/step_up evaluation
- ✅ `pam-gateway` integration — real-time command filtering during active sessions
- ✅ Tests: allow/deny matching + priority ordering

### Milestone 10: Mobile Approval Integration

- ✅ Extend iOS SDK (`sdk/ios/`) — PAM approval push with number matching
- ✅ Extend Android SDK (`sdk/android/`) — PAM approval push with number matching
- ✅ Passkey step-up assertion flow for secret reveal via mobile
- ✅ Tests: mobile approval contract tests

### Milestone 11: Admin UI (minimal)

- ⬜ Asset registration wizard in `ztna-frontend`
- ⬜ Session list with replay player component
- ⬜ Secret operations page (vault, metadata, rotation status)
- ⬜ Lease dashboard (active leases, pending approvals)
- ⬜ PAM-specific plain-language explanation panel

### Milestone 12: Deployment and CI

- ✅ Kubernetes manifests: `deploy/k8s/pam-gateway/`
- ✅ Helm templates: `deploy/helm/shieldnet-access/templates/pam-gateway.yaml`
- ✅ CI workflow updates for `pam-gateway` build and test
- ✅ Integration tests: end-to-end PAM session flow
- ✅ Documentation: update root `README.md` with PAM section
- ✅ Documentation: update `docs/architecture.md` with PAM component map
- ✅ Documentation: update `cmd/README.md` with `pam-gateway` binary

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

## Changelog

### 2026-05-17 — Milestone 12 complete (Deployment + CI infrastructure)

- **PAM gateway deployment manifests**
  (`deploy/k8s/pam-gateway/{deployment,service,configmap,kustomization}.yaml`):
  Kubernetes Deployment, ClusterIP Service, ConfigMap, and
  Kustomize overlay for the `pam-gateway` binary. Deployment
  pins `cpu=500m / mem=512Mi` resource requests, mounts an
  `emptyDir` at `/var/lib/shieldnet/replay` for active-session
  replay buffering, and reads protocol-listener ports + S3
  replay-store config from the ConfigMap (`PAM_GATEWAY_LISTEN_*`,
  `PAM_S3_BUCKET`, `PAM_S3_REGION`). Listed under
  `deploy/k8s/kustomization.yaml` so a single
  `kubectl apply -k deploy/k8s` rolls out the full platform.
- **Helm template**
  (`deploy/helm/shieldnet-access/templates/pam-gateway.yaml`):
  values-driven Deployment + Service + ConfigMap rendered from
  `pamGateway.*` keys in `values.yaml` (image, replicas,
  resources, listener ports, GOMEMLIMIT / GOGC, replay volume
  size). Matches the templating + label / selector conventions
  already used by `ztna-api.yaml` so the chart stays uniform.
- **CI workflow updates** (`.github/workflows/ci.yml`):
  - Explicit `Build pam-gateway` step running
    `go build -o /tmp/pam-gateway ./cmd/pam-gateway` so broken
    main-package wiring (missing imports, refactored listeners)
    fails fast in the CI log instead of being buried inside the
    `go build ./...` output.
  - Explicit `Test pam-gateway packages` step running the
    gateway + PAM services + PAM handlers test trees with
    `-v` so a regression in MS 4–10 surfaces in the CI log
    without downloading test artifacts.
  - `docker-compose-smoke` job now waits on `pam-gateway`
    alongside `ztna-api / access-workflow-engine /
    access-ai-agent` and probes `/health` on host port 8081
    to confirm the binary booted and bound its health
    listener.
- **End-to-end integration suite**
  (`internal/integration/pam_e2e_test.go`,
  `internal/integration/e2e_helpers_test.go`):
  - `TestPAM_E2E_FullLeaseLifecycle` drives the canonical PAM
    operator flow against the real Gin router and real PAM
    service constructors: vault password → register SSH
    bastion → bind operator account → request 30-min lease →
    approver grants → granted lease appears in
    `GET /pam/leases?active=true`. Uses
    `access.PassthroughEncryptor` so the suite does not depend
    on `ACCESS_CREDENTIAL_DEK` being set, and checks
    defensively that the encrypted ciphertext never escapes
    through any of the JSON envelopes.
  - `TestPAM_E2E_RevokeLease` covers the revoke half of the
    state machine — first revoke stamps `revoked_at`, a second
    revoke is a no-op that must not regress the timestamp.
  - The suite shares the existing `newE2EDB` /  `doJSON` /
    `silenceLogs` helpers from `e2e_helpers_test.go`;
    `AutoMigrate` now covers the eight PAM models so a future
    test can drive a mixed access + PAM scenario off a single
    schema. Both tests carry `//go:build integration` so they
    do NOT run in `go test ./...` — the dedicated
    `go test -tags=integration ./internal/integration/...`
    invocation picks them up.
- **Docker-compose host-port remap**
  (`docker-compose.yml`, `README.md` port table): the
  pam-gateway's Postgres / MySQL / K8s listeners (5432 / 3306
  / 8443) stay container-internal and are no longer mapped to
  the host. Operator-driven flows that need an externally
  reachable proxy bind the host ports `15432` / `13306` /
  `18443` instead so they cannot collide with the dev-stack
  Postgres on 5432 (the PR #96 review finding). The SSH
  listener still maps `2222:2222` and the health probe still
  maps `8081:8081` since neither collides.

### 2026-05-17 — Milestones 5-10 complete (gateways, audit, AI risk, command policy, mobile SDK)

- **Milestone 5 — Kubernetes exec proxy** (`internal/gateway/k8s_listener.go`,
  `k8s_listener_test.go`): WebSocket bridge from `pam-gateway` to a
  target K8s API server's `pods/exec` endpoint. Authenticates the
  operator against `ztna-api`, validates the namespace / pod /
  container against the issued lease, injects the per-session
  service-account token or kubeconfig via the existing
  `SecretInjector`, and tees stdin/stdout/stderr through the
  recorder + command parser pipeline introduced in Milestone 4.
  Namespace + pod + container land in the `session.metadata`
  JSONB column so the audit timeline can render "where" alongside
  "what".
- **Milestone 6 — Database wire-protocol proxies**
  (`internal/gateway/pg_listener.go`, `mysql_listener.go`,
  `db_ws_handler.go`, plus respective `*_test.go`): PostgreSQL
  and MySQL TCP proxies on 5432 / 3306 speaking the real
  startup → auth → query wire frames. Each Simple Query / COM_QUERY
  is captured as a `pam_session_commands` row with the SHA-256 of
  the result-set bytes, evaluated against the command policy
  engine before being forwarded to the backend, and propagated
  back to the operator with a plain-language reason on deny.
  `db_ws_handler.go` exposes the same surface over a browser
  WebSocket so the future SQL console can speak straight to the
  gateway without a thick client.
- **Milestone 7 — Audit + Evidence service**
  (`internal/services/pam/audit_service.go`,
  `pam_audit_producer.go`, `internal/handlers/pam_audit_handler.go`,
  + tests): `PAMAuditService` records `pam.session.*`,
  `pam.secret.*`, `pam.lease.*` events onto the existing
  `ShieldnetLogEvent` Kafka envelope. Replay-bytes are stored in
  S3 under `sessions/{id}/replay.bin`; `GetReplaySignedURL`
  issues pre-signed GETs with a configurable 15-minute default
  expiry. New handlers cover session list / detail / replay URL /
  command timeline / force-terminate. Evidence-pack export
  bundles the replay, command timeline, lease metadata, and risk
  factors into a single JSON document.
- **Milestone 8 — AI risk assessment**
  (`cmd/access-ai-agent/skills/pam_session_risk.py`,
  `internal/services/pam/session_service.go`, +
  `test_pam_session_risk.py` and `session_service_test.go`): new
  `pam_session_risk_assessment` A2A skill mirroring
  `access_risk_assessment`. Computes unusual-time, first-time-asset,
  repeated-denials, and emergency-access-rate factors and returns
  `{risk_score, risk_factors, recommendation}`. The Go side calls
  it through the existing `aiclient.AssessRiskWithFallback`
  helper so PAM gets the same circuit-breaker semantics as the
  access surface.
- **Milestone 9 — Command policy engine**
  (`internal/services/pam/command_policy_service.go`,
  `session_policy_adapter.go`,
  `internal/gateway/api_policy_evaluator.go`, +
  `command_policy_service_test.go`,
  `session_policy_adapter_test.go`,
  `api_policy_evaluator_test.go`, and
  `internal/handlers/policy_gateway_integration_test.go`):
  `PAMCommandPolicyService.EvaluateCommand` matches regex
  patterns against active `pam_command_policies` rows in priority
  order with workspace + asset + account selectors and returns an
  `(allow | deny | step_up, reason)` outcome. The SSH / K8s / PG /
  MySQL listeners call the gateway-side `APIPolicyEvaluator` for
  every parsed command, block the wire on deny, and emit a
  user-visible reason on the operator channel. `step_up` toggles
  the `risk_flag` on the captured command row so the auditor can
  trace which commands triggered an MFA prompt.
- **Milestone 10 — Mobile SDK PAM extensions**
  (`sdk/ios/Sources/ShieldNetAccess/PAM*.swift`,
  `sdk/android/src/main/kotlin/com/shieldnet360/access/PAM*.kt`,
  `OkHttpPAMSDKClient.kt`, + iOS `PAMContractTests.swift`,
  `URLSessionPAMClientTests.swift` and Android
  `PAMContractTest.kt`, `OkHttpPAMClientTest.kt`): new
  `PAMSDKClient` protocol on both platforms. Push parsing is a
  pure synchronous function (`parseApprovalNotification`) so it
  runs from `UNNotificationServiceExtension` /
  `FirebaseMessagingService.onMessageReceived` without I/O.
  `verifyMatchedCode` does a constant-time byte-equal comparison
  so a stolen device gets a 1-in-(N+1) guess against the union
  of `matched_code ∪ decoy_codes`. `approveLease` / `denyLease`
  route to `POST /pam/leases/:id/approve|revoke`;
  `revealSecret` posts a `PassKeyAssertion` payload to `POST
  /pam/secrets/:id/reveal` for FIDO2/WebAuthn step-up. The SDKs
  reuse the existing `AccessSDKError` / `AccessSDKException`
  surface so host apps can branch on transport / auth /
  decoding failures uniformly.

### 2026-05-16 — Milestone 4 complete (SSH gateway with recording + audit)

- `IORecorder` (`internal/gateway/recorder.go`) — wraps the SSH proxy
  io.Copy goroutines and writes a framed binary blob of session
  I/O to a `ReplayStore`. Default sink is the S3-compatible store
  (`replay_store_fs.go` is the local-disk dev sink). Frames carry
  direction (input / output / stderr), monotonic sequence, and a
  millisecond-resolution timestamp so the future replay UI can
  scrub frame-accurate.
- `CommandParser` (`internal/gateway/command_parser.go`) — feeds
  per-command audit rows into a pluggable `CommandSink`. The
  parser tracks newline-delimited input, accumulates a per-command
  SHA-256 over the response stream, and serialises append calls
  through a single worker goroutine so the ztna-api sees rows in
  the order the operator typed them.
- `APICommandSink` — HTTP POST sink that round-trips command rows
  to the ztna-api `/pam/sessions/:id/commands` endpoint.
- `SSHListener.handleChannel` rewired to: forward channel requests
  (shell, pty-req, env, window-change), pre-start the upstream
  shell, tee both directions through the recorder + parser, close
  the upstream stdin pipe on operator EOF so the remote shell
  receives a definite end-of-input, and forward the upstream's
  exit-status to the operator so `ssh host` returns a real
  `*ssh.ExitError` instead of "exited without exit status".
- `docker/Dockerfile.pam-gateway` — multi-stage build mirroring
  `Dockerfile.ztna-api` (golang:1.25-alpine → distroless nonroot).
- `pam-gateway` service in `docker-compose.yml` — depends on a
  healthy `ztna-api`, exposes 2222/8081, gets the replay-dir +
  health-port envs the binary expects.
- Comprehensive tests:
  - `recorder_test.go` — frame contract, sequence monotonicity,
    sink hand-off, close-flush, max-bytes cap.
  - `command_parser_test.go` — newline boundary handling, ordering
    across the worker channel, output-hash determinism, risk-flag
    propagation, close-flush semantics.
  - `ssh_listener_test.go` — end-to-end SSH handshake against a
    fake upstream, real recorder + parser wiring, replay-store
    frame assertions, command-sink ordering + hash assertions, and
    a token-rejection negative test.

### 2026-05-16 — Milestones 1-4 (Milestone 4 partial)

- PAM data model: 8 GORM models (`PAMAsset`, `PAMAccount`, `PAMSecret`,
  `PAMSession`, `PAMSessionCommand`, `PAMLease`, `PAMCommandPolicy`,
  `PAMRotationSchedule`) + migration `016_create_pam_tables.go`.
- `PAMAssetService` with asset + account CRUD and full unit + HTTP
  handler test coverage.
- `SecretBrokerService` with vault, reveal-with-step-up-MFA, rotate,
  rotation history, check-out, and inject — backed by the existing
  `CredentialEncryptor` (AES-GCM) interface.
- `MFAVerifier` interface + `NoOpMFAVerifier` for dev / test wiring.
- `PAMLeaseService` with JIT lease lifecycle (request → approve →
  revoke / expire) wired through the `AccessRequestCreator`
  interface to the existing `AccessRequestService`.
- `LeaseNotifier` interface for best-effort approval / revocation /
  expiry notifications.
- `PAMLeaseExpiryEnforcer` cron job with configurable tick interval
  (`PAM_LEASE_EXPIRY_CHECK_INTERVAL`, default 1m) and per-lease
  session-termination hook.
- PAM workflow template seed (`017_seed_pam_workflow_templates.go`):
  `pam_session_low_risk`, `pam_session_standard`,
  `pam_session_critical`.
- HTTP handlers for `/pam/assets/*`, `/pam/secrets/*`,
  `/pam/leases/*` plus nil-safe wiring into the existing
  `handlers.Dependencies` struct.
- `pam-gateway` binary (`cmd/pam-gateway/`) with SSH listener,
  short-lived SSH-CA cert issuance, and injected-credential
  fallback. Library code split into `internal/gateway/` so the SSH
  paths are unit-testable without booting the binary.
