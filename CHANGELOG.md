# Changelog

All notable changes to the ShieldNet 360 Access Platform are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Component-level changelogs live alongside their packages:

- iOS SDK — [`sdk/ios/CHANGELOG.md`](sdk/ios/CHANGELOG.md)
- Android SDK — [`sdk/android/CHANGELOG.md`](sdk/android/CHANGELOG.md)
- Desktop extension — [`sdk/desktop/CHANGELOG.md`](sdk/desktop/CHANGELOG.md)

## [Unreleased]

### Added

- **Request-ID correlation** — every HTTP response now carries an `X-Request-ID` header (echoed from a sanitised, 128-byte-capped inbound value or minted as UUIDv4) and every 4xx/5xx body mirrors it under `request_id`. Implemented in `internal/handlers/request_id_middleware.go`, threaded into the JSON logger as the `request_id` slog attribute, and documented as a reusable `headers.X-Request-ID` component in both `docs/swagger.{json,yaml}` and the embedded `internal/handlers/swagger.{json,yaml}` copies.
- **Migration integration test** (`internal/migrations/migrations_integration_test.go`, `//go:build integration`) — runs the full 15-migration suite twice on a fresh DB and validates the resulting table set; uses `ACCESS_DATABASE_URL` to target Postgres in CI, falls back to in-memory SQLite locally.
- **Healthcheck binary tests** for `cmd/ztna-api` and `cmd/access-workflow-engine` — assert `runHealthcheck()` returns exit 0 on healthy `/health`, exit 1 on 503, and exit 1 on unreachable server.
- **`make test-integration` target** — `go test -race -timeout=300s -tags=integration ./...`; currently exercises the leaver kill-switch, orphan reconciler, audit, and migration integration tests.
- **`scripts/check_stale_references.sh`** + `make stale-ref-check` — CI guard that fails if any retired doc filename (`PROPOSAL.md`, `ARCHITECTURE.md`, `LISTCONNECTORS.md`, `SDK_CONTRACTS.md`) reappears outside `docs/internal/` or `CHANGELOG.md`. Wired into `make lint` and `make ci`.
- **`.github/workflows/integration-test.yml`** — runs `make test-integration` on PRs touching `internal/`, `go.mod/sum`, or the `Makefile` against a Postgres 16 service container.
- **`docker/README.md`** — documents the four Dockerfiles, the two-stage `golang:1.25-alpine` → distroless build pattern, and the Python sidecar runtime.
- **`cmd/README.md`** — catalogues the four binaries (ports 8080 / — / 8082 / 8090) with the env-var contract per binary.
- **Router integration test** (`internal/handlers/router_integration_test.go`) — exercises the full middleware chain (`gin.Recovery` → JSON logger → metrics → rate limiter → JSON validation) plus dependency-gated route registration, malformed-body handling, rate-limit tripping, and `/health` bypass.
- **Connector management service test** (`internal/services/access/connector_management_service_test.go`) — covers the full `ConnectAccessConnector` lifecycle (validate → connect → verify permissions → encrypt → persist) with mock connectors that fail at each step, plus the credential rotation path.
- **SSO federation integration test** (`internal/services/access/sso_federation_service_integration_test.go`) — exercises the SAML / OIDC metadata paths against a mock Keycloak HTTP server and asserts the `ErrSSOFederationUnsupported` path for connectors without SSO metadata.
- **Anomaly scanner integration test** (`internal/cron/anomaly_scanner_integration_test.go`) — covers cross-grant baseline, off-hours, geographic outlier, and unused high-privilege detectors with a mock AI client.
- **Impact resolver edge tests** (`internal/services/access/impact_resolver_edge_test.go`) — empty team, zero resources matched, very large team expansion, circular team membership.
- **Config validation tests** (`internal/config/access_validation_test.go`) — table-driven env-var parsing, required-var error surfacing, and optional-var defaults (`ACCESS_GRANT_EXPIRY_CHECK_INTERVAL=1h`, `ACCESS_ORPHAN_RECONCILE_INTERVAL=24h`).
- Public-facing documentation set under [`docs/`](docs/): overview, architecture deep-dive, getting-started walkthrough, connector capability matrix, SDK contract, and per-platform integration guides.
- Root `CHANGELOG.md` (this file).
- Hybrid access model: per-connector access-mode classification (`tunnel` / `sso_only` / `api_only`) with auto-classification at Connect time. Operators can override per connector.
- Six-layer leaver kill switch: a single off-boarding call revokes grants, removes team memberships, disables the Keycloak user, revokes upstream sessions, SCIM-deprovisions, and disables the OpenZiti identity. Every layer is best-effort, idempotent, and audited.
- 14 connectors implement `SessionRevoker` for live-session revocation on leaver flows: Okta, Google Workspace, Microsoft, Salesforce, Slack, Auth0, GitHub, Zoom, Zendesk, HubSpot, Dropbox, Jira / Atlassian, Notion, BambooHR.
- 14 connectors implement `SSOEnforcementChecker` for password-fallback detection: Salesforce, Google Workspace, Okta, Slack, GitHub, Microsoft, Auth0, Ping Identity, Zendesk, BambooHR, Workday, HubSpot, Dropbox, Zoom.
- `OrphanReconciler` cron with dry-run mode and per-connector throttle. Surfaces upstream accounts the IdP no longer knows about for operator triage.
- `GrantExpiryEnforcer` cron with separate expiry-warning sweep. Both revoke and warning paths emit audit envelopes for downstream SIEM.
- AES-GCM credential encryptor driven by `ACCESS_CREDENTIAL_DEK`. Connector credentials at rest are no longer plaintext.
- `ztna-api` graceful shutdown: `http.Server.Shutdown(10s)` on SIGINT / SIGTERM, matching the worker drain.
- `access-connector-worker` bounded drain: `sync.WaitGroup` plus a 10-second watchdog so in-flight cron ticks complete before exit.
- Uniform Postgres + SQLite migration paths across all three Go services via the shared `internal/pkg/database` helper.
- Mobile and desktop SDKs published to their respective registries: SwiftPM (iOS), GitHub Packages Maven (Android), GitHub Packages npm (Desktop). Tag-triggered release workflows validate manifests, run contract tests, and assert a matching `CHANGELOG.md` entry.

### Changed

- README rewritten for public consumption — value proposition, install, quick start, and a navigable documentation table.
- CONTRIBUTING rewritten as a focused develop / test / send-PR guide.
- Internal trackers (`PROGRESS.md`, `PHASES.md`) relocated under [`docs/internal/`](docs/internal/) and headered as internal documents.
- Connector capability matrix refactored: typographic bullets in place of emoji markers, no internal status mixing, dropped "source of truth" framing.
- All cross-references retargeted from old uppercase doc names to the new lowercase structure.

### Removed

- `docs/PROPOSAL.md`, `docs/ARCHITECTURE.md`, `docs/LISTCONNECTORS.md`, `docs/SDK_CONTRACTS.md` — superseded by the new public docs.
