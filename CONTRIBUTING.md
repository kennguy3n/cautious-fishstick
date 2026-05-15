# Contributing

Thanks for sending a change to the ShieldNet 360 Access Platform.

This file covers prerequisites, the local dev loop, the CI gates a PR must pass, and the recipe for adding a new connector. For project context start with [`README.md`](README.md); for architecture and the SDK contract see [`docs/architecture.md`](docs/architecture.md) and [`docs/sdk.md`](docs/sdk.md).

## Prerequisites

- **Go 1.25+** for the server binaries under `cmd/` and the platform code under `internal/`.
- **Python 3.12+** for the AI sidecar at `cmd/access-ai-agent/`.
- **Docker** with Compose v2 for the local stack — `docker compose up --wait` brings up Postgres, Redis, and all four services with healthchecks.
- (Optional) `swag` (`go install github.com/swaggo/swag/cmd/swag@latest`) if you want `make swagger` to regenerate from annotations. The repo ships hand-maintained `docs/swagger.{json,yaml}`, so `make swagger-check` still works without it.

## Clone and build

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

## Local stack

```bash
make docker-up     # docker compose up --build --wait
make docker-logs   # tail running services
make docker-down   # docker compose down -v
```

## CI gates

The CI workflow in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs every gate the merge queue blocks on. The Makefile mirrors each gate as a target so you can run them locally before pushing:

```bash
make ci               # vet + test + swagger-check + sn360-check + model-check + stale-ref-check
make lint             # all static gates (vet + swagger-check + sn360-check + model-check + stale-ref-check), no test suite
make vet              # go vet ./...
make swagger-check    # fail if docs/swagger.{json,yaml} is stale vs annotations
make sn360-check      # fail if user-facing vocabulary regressed
make model-check      # fail if a binary model file landed under sdk/
make stale-ref-check  # fail if a retired doc filename or bare shorthand (PROPOSAL.md / ARCHITECTURE.md / LISTCONNECTORS.md / SDK_CONTRACTS.md, OR `PROPOSAL §X` / `ARCHITECTURE §X` / `LISTCONNECTORS §X` / `SDK_CONTRACTS §X` without `.md`) is referenced outside docs/internal/
```

## Adding a connector

Connectors live under `internal/services/access/connectors/<provider>/`. The pattern below mirrors the existing suites — see `connectors/dropbox/` for a canonical example.

1. **Scaffold the package.** Create the directory and a `connector.go` that declares `Config` + `Secrets` structs, a `ProviderName` constant, a `New()` constructor, and an `init()` that calls `access.RegisterAccessConnector(ProviderName, New())`. Blank-import the package from each `cmd/*/main.go` binary that should expose it.
2. **Implement `access.AccessConnector`.** Every method — `Validate`, `Connect`, `VerifyPermissions`, `CountIdentities`, `SyncIdentities`, `ProvisionAccess`, `RevokeAccess`, `ListEntitlements`, `GetSSOMetadata`, `GetCredentialsMetadata`. Methods the provider does not support return the relevant sentinel error (e.g. `access.ErrProvisioningUnavailable`) rather than `nil`.
3. **Ship the seven-test minimum** in the same package:
   - `TestValidate_HappyPath` plus at least one missing-field variant.
   - `TestConnect_*` covering happy, 4xx, and 5xx paths.
   - `TestSyncIdentities_*` covering happy, pagination, and error paths.
   - `TestCountIdentities_*`.
   - `TestProvisionAccess_*` (happy + idempotent re-provision + permanent error).
   - `TestRevokeAccess_*` (happy + idempotent + permanent error).
   - `TestGetCredentialsMetadata_*`.
4. **Add any optional capabilities the provider supports** (`SessionRevoker`, `SSOEnforcementChecker`, `SCIMProvisioner`, `GroupSyncer`, `IdentityDeltaSyncer`, etc.) with matching httptest happy + failure tests in a dedicated `<feature>_test.go`.
5. **Update the registry guard test** in `internal/services/access/registry_count_test.go` if a count changed.
6. **If the directory name differs from the `ProviderName` constant** (e.g. `connectors/duo/` registers as `duo_security`), add the mapping to `directoryToProvider` in `TestRegistry_NoOrphanDirectories`. Otherwise the orphan-directory guard will fire and claim the directory is unregistered.
7. **Update the documentation:** [`README.md`](README.md) (connector counts) and [`docs/connectors.md`](docs/connectors.md) (capability matrix). Keep numbers consistent across files.

## Pull request checklist

- [ ] All affected `*_test.go` files updated to cover the new behaviour (happy + at least one failure path).
- [ ] No secret, token, or PII is logged.
- [ ] `go test -race -timeout=180s ./...` passes locally.
- [ ] `make ci` (or equivalent CI gates) passes locally.
- [ ] If you touched a connector list or count, the README, [`docs/connectors.md`](docs/connectors.md), and `internal/services/access/registry_count_test.go` are all in sync.
- [ ] If you touched the public HTTP surface, `docs/swagger.{json,yaml}` and the embedded copies under `internal/handlers/` are regenerated and committed.

## Reporting issues

Open a GitHub issue with reproduction steps and your environment (Go version, OS, compose version). Security-sensitive reports should be sent privately to the maintainers instead of filed publicly.
