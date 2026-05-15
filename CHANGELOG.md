# Changelog

All notable changes to the ShieldNet 360 Access Platform are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Component-level changelogs live alongside their packages:

- iOS SDK — [`sdk/ios/CHANGELOG.md`](sdk/ios/CHANGELOG.md)
- Android SDK — [`sdk/android/CHANGELOG.md`](sdk/android/CHANGELOG.md)
- Desktop extension — [`sdk/desktop/CHANGELOG.md`](sdk/desktop/CHANGELOG.md)

## [Unreleased]

### Added

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
