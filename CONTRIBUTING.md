# Contributing

Thanks for sending a change to the ShieldNet 360 Access Platform. This file is the short version of "how do I land code here?"; the longer phase-by-phase plan lives in [`docs/PHASES.md`](docs/PHASES.md), the architecture in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the product proposal in [`docs/PROPOSAL.md`](docs/PROPOSAL.md).

## Prerequisites

- **Go 1.25+** for every server binary under `cmd/` and the access-platform service / connector code under `internal/`.
- **Python 3.12+** for the AI sidecar at `cmd/access-ai-agent/`.
- **Docker (compose v2)** for the local stack — `docker compose up --wait` brings up Postgres, Redis, and the three Go services with healthchecks.
- (Optional) `swag` (`go install github.com/swaggo/swag/cmd/swag@latest`) if you want `make swagger` to regenerate from annotations; the repo ships hand-maintained `docs/swagger.{json,yaml}` so `make swagger-check` still works without it.

## Clone & build

```bash
git clone https://github.com/kennguy3n/cautious-fishstick.git
cd cautious-fishstick

go mod download
make build      # go build ./...
make test       # go test -race -timeout=180s ./...
```

For the Python sidecar:

```bash
cd cmd/access-ai-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make -C ../.. test-python
```

## Local stack via Docker

```bash
make docker-up     # docker compose up --build --wait
make docker-logs   # tail the running services
make docker-down   # docker compose down -v
```

## Running the CI gates locally

The CI workflow in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs every gate the merge queue blocks on. The Makefile mirrors each gate as a target:

```bash
make ci            # vet + test + swagger-check + sn360-check + model-check
make lint          # all the static gates without the test suite
make vet           # go vet ./...
make swagger-check # fail if docs/swagger.{json,yaml} is stale vs annotations
make sn360-check   # fail if SN360 user-facing vocabulary regressed
make model-check   # fail if a binary model file landed under sdk/
```

## Adding a new connector

Connectors live under `internal/services/access/connectors/<provider>/`. The "seven-test minimum" mirrors the existing suites (see `connectors/dropbox/` for a canonical example):

1. Create the package directory and a `connector.go` that declares a `Config` + `Secrets` struct, a `ProviderName` constant, a `New()` constructor, and an `init()` that calls `access.RegisterAccessConnector(ProviderName, New())`. Blank-import the package from each `cmd/*/main.go` binary that should expose it.
2. Implement every method of `access.AccessConnector` — `Validate`, `Connect`, `VerifyPermissions`, `CountIdentities`, `SyncIdentities`, `ProvisionAccess`, `RevokeAccess`, `ListEntitlements`, `GetSSOMetadata`, `GetCredentialsMetadata`. Methods that the provider doesn't support should return `access.ErrProvisioningUnavailable` (or the relevant sentinel) rather than `nil`.
3. Add the **seven-test minimum** under the same package:
   - `TestValidate_HappyPath` + at least one missing-field variant.
   - `TestConnect_*` for happy + 4xx + 5xx paths.
   - `TestSyncIdentities_*` for happy + pagination + error paths.
   - `TestCountIdentities_*`.
   - `TestProvisionAccess_*` (happy + idempotent re-provision + permanent error).
   - `TestRevokeAccess_*` (happy + idempotent + permanent error).
   - `TestGetCredentialsMetadata_*`.
4. Implement any **optional interfaces** the provider supports (`SessionRevoker`, `SSOEnforcementChecker`, `SCIMProvisioner`, `GroupSyncer`, `IdentityDeltaSyncer`, etc.) and add the matching httptest happy + failure tests in a dedicated `<feature>_test.go`.
5. Update the registry guard test in `internal/services/access/registry_count_test.go` if a count changed (connectors / SessionRevoker / SSOEnforcementChecker).
6. Update the matching documentation: `README.md` (connector list & counts), `docs/PROGRESS.md` (§1/§2 tables), `docs/LISTCONNECTORS.md` (per-connector capability table). Keep the numbers consistent across every file.

## PR checklist

Every PR is gated on the cross-cutting criteria in [`docs/PHASES.md`](docs/PHASES.md):

- [ ] All affected `*_test.go` files updated to cover the new behaviour (happy + at least one failure path).
- [ ] No secret, token, or PII is logged.
- [ ] `go test -race -timeout=180s ./...` passes locally.
- [ ] `make ci` (or the equivalent CI gates) passes locally.
- [ ] If you touched a connector list or count, the README + `docs/PROGRESS.md` + `docs/LISTCONNECTORS.md` + `internal/services/access/registry_count_test.go` are all updated to the same number.
- [ ] If you touched the public HTTP surface, `docs/swagger.{json,yaml}` and the embedded copies under `internal/handlers/` are regenerated and committed.

## Where to look next

- [`README.md`](README.md) — high-level pitch + quick start.
- [`docs/PROPOSAL.md`](docs/PROPOSAL.md) — product definition.
- [`docs/PHASES.md`](docs/PHASES.md) — phase-by-phase plan + per-PR cross-cutting criteria.
- [`docs/PROGRESS.md`](docs/PROGRESS.md) — current status and changelog.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — service topology, data model, hybrid-access layers.
- [`docs/LISTCONNECTORS.md`](docs/LISTCONNECTORS.md) — per-connector capability matrix.
- [`docs/SDK_CONTRACTS.md`](docs/SDK_CONTRACTS.md) — mobile / desktop SDK contracts.
