# cmd/

Entry points for the ShieldNet 360 Access Platform. Four runtime
binaries — three Go services and one Python sidecar — boot from the
sub-directories below. Every binary blank-imports the same 200
connector packages and shares the `internal/services/access/...`
service layer so the wire contract stays consistent across
processes.

## Binaries

| Directory                      | Binary                    | Port  | Role                                                                 |
|--------------------------------|---------------------------|:-----:|----------------------------------------------------------------------|
| `ztna-api/`                    | `ztna-api`                | 8080  | Public HTTP API (Gin). Serves `/health`, `/swagger`, `/access/*`, `/scim/*`, `/metrics`. |
| `access-connector-worker/`     | `access-connector-worker` | —     | Redis-queue consumer (sync / provision / revoke / audit). No HTTP surface. |
| `access-workflow-engine/`      | `access-workflow-engine`  | 8082  | LangGraph-style approval orchestrator + Phase-11 background crons.   |
| `access-ai-agent/`             | `access-ai-agent`         | 8090  | Python A2A skill server (risk assessment, explain, suggest).         |
| `pam-gateway/`                 | `pam-gateway`             | 2222  | PAM SSH gateway. Validates one-shot connect tokens via `ztna-api` and proxies the channel to the target asset using a short-lived CA-signed cert (or injected credential fallback). |

Run any of them locally with `go run ./cmd/<binary>` (Go services)
or `python cmd/access-ai-agent/main.py` (Python). The compose stack
at the repo root wires all four together with healthchecks.

## Environment variables

Every binary degrades gracefully when its dependencies are not
configured — a missing DB falls through to in-memory SQLite, a
missing AI agent surfaces a structured 503 from `/access/explain`,
and so on. The variables below are the ones each binary actually
reads at boot.

### `ztna-api` ([cmd/ztna-api/](./ztna-api/))

| Variable                       | Required | Default                | Notes                                                                           |
|--------------------------------|:--------:|------------------------|---------------------------------------------------------------------------------|
| `ZTNA_API_LISTEN_ADDR`         | no       | `:8080`                | HTTP bind address.                                                              |
| `ACCESS_DATABASE_URL`          | prod     | (in-memory SQLite)     | Postgres DSN. Falls back to a short-lived SQLite so `go run` works without Postgres. |
| `ACCESS_REDIS_URL`             | prod     | unset                  | Redis URL for the connector-worker queue (consumed by handlers that enqueue jobs). |
| `ACCESS_CREDENTIAL_DEK`        | prod     | unset                  | Base64-encoded 32-byte AES-GCM key. **Unset = PassthroughEncryptor (plaintext)**. |
| `ACCESS_AI_AGENT_BASE_URL`     | no       | unset                  | A2A endpoint (e.g. `http://access-ai-agent:8090`). Unset → AI handlers 503.     |
| `ACCESS_AI_AGENT_API_KEY`      | no       | unset                  | `X-API-Key` for the agent. Unset in dev; required in non-local deploys.          |
| `ZTNA_API_RATE_LIMIT_RPS`      | no       | (Router default)       | Per-workspace request budget for the rate limiter.                              |

`--healthcheck`: runs as a self-probe (used by docker-compose and the
k8s liveness probe) — exits 0 when the binary is healthy.

### `access-connector-worker` ([cmd/access-connector-worker/](./access-connector-worker/))

| Variable                                       | Required | Default            | Notes                                                                  |
|------------------------------------------------|:--------:|--------------------|------------------------------------------------------------------------|
| `ACCESS_DATABASE_URL`                          | prod     | (in-memory SQLite) | Same Postgres DSN as ztna-api.                                         |
| `ACCESS_REDIS_URL`                             | prod     | unset              | Redis queue URL.                                                       |
| `ACCESS_CREDENTIAL_DEK`                        | prod     | unset              | Same key the api uses — decrypts connector credentials before sync.    |
| `ACCESS_IDENTITY_SYNC_INTERVAL`                | no       | `15m`              | Identity-sync scheduler cadence.                                       |
| `ACCESS_DRAFT_STALENESS_INTERVAL`              | no       | `1h`               | Draft-policy staleness checker cadence.                                |
| `ACCESS_GRANT_EXPIRY_CHECK_INTERVAL`           | no       | `1h`               | Grant-expiry enforcer cadence.                                         |
| `ACCESS_ORPHAN_RECONCILE_INTERVAL`             | no       | `24h`              | Phase-11 unused-account reconciler cadence.                            |

No HTTP listener; the worker pulls jobs off Redis and drains on
SIGINT / SIGTERM with a bounded watchdog (see commit `fc24693`).

### `access-workflow-engine` ([cmd/access-workflow-engine/](./access-workflow-engine/))

| Variable                                    | Required | Default            | Notes                                                                       |
|---------------------------------------------|:--------:|--------------------|-----------------------------------------------------------------------------|
| `ACCESS_WORKFLOW_ENGINE_LISTEN_ADDR`        | no       | `:8082`            | HTTP bind address.                                                          |
| `ACCESS_DATABASE_URL`                       | prod     | (in-memory SQLite) | Postgres DSN.                                                               |
| `ACCESS_WORKFLOW_ENGINE_SQLITE_PATH`        | dev      | `:memory:`         | Override the SQLite fallback (used only when `ACCESS_DATABASE_URL` is unset). |
| `NOTIFICATION_SMTP_HOST` + port/from/user/pass | no    | unset              | Email notifier wiring. Disabled when host is empty.                         |
| `NOTIFICATION_SLACK_WEBHOOK_URL`            | no       | unset              | Slack incoming webhook for approval notifications.                          |

`--healthcheck`: same self-probe pattern as ztna-api.

### `access-ai-agent` ([cmd/access-ai-agent/](./access-ai-agent/))

| Variable                          | Required | Default            | Notes                                                            |
|-----------------------------------|:--------:|--------------------|------------------------------------------------------------------|
| `ACCESS_AI_AGENT_LISTEN_ADDR`     | no       | `127.0.0.1:8765`   | Bind address. Compose overrides to `0.0.0.0:8090`.               |
| `ACCESS_AI_AGENT_API_KEY`         | prod     | unset              | Required `X-API-Key` for skill requests. Unset = open access.    |

See [`cmd/access-ai-agent/README.md`](./access-ai-agent/README.md)
for the A2A skill catalogue and request envelope.

## Shared invariants

- All three Go binaries blank-import the same 200 connector packages
  so the global registry is populated consistently across processes.
  The exact registered count is enforced by
  `internal/services/access/registry_count_test.go`.
- Postgres migrations are serialised across binaries via
  `pg_advisory_lock` (see commit `f9be4be`) so the first binary to
  boot in a cold cluster runs the migration set without racing the
  others.
- Every Go binary shuts down gracefully on SIGINT / SIGTERM with a
  10-second drain watchdog matching the docker / k8s `terminationGracePeriodSeconds`.

See [`../docs/architecture.md`](../docs/architecture.md#12-where-things-run)
for the deployment topology and [`../docker/README.md`](../docker/README.md)
for the container build pattern.
