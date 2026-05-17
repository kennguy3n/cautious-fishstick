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
| `pam-gateway/`                 | `pam-gateway`             | 2222 (SSH) / 8081 (health + SQL WS) / 5432 (PG proxy) / 3306 (MySQL proxy) / 8443 (K8s exec) | PAM data-plane broker. Validates one-shot connect tokens via `ztna-api`, then proxies SSH (short-lived CA-signed cert with credential-injection fallback), `kubectl exec` over WebSocket, and PostgreSQL / MySQL wire-protocol traffic to the target asset. Every channel is teed through the session recorder + command parser + policy evaluator so audit / replay / `allow|deny|step_up` happen on every command. PG / MySQL / K8s listener ports are container-internal — `docker-compose.yml` maps them to host ports `15432` / `13306` / `18443` to avoid colliding with the dev-stack Postgres. |

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

### `pam-gateway` ([cmd/pam-gateway/](./pam-gateway/))

| Variable                              | Required | Default                                | Notes                                                                                                                              |
|---------------------------------------|:--------:|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `PAM_GATEWAY_API_URL`                 | yes      | unset                                  | `ztna-api` base URL (e.g. `http://ztna-api:8080`). Used for token validation, command audit POSTs, and policy evaluation.          |
| `PAM_GATEWAY_API_KEY`                 | prod     | unset                                  | Shared `X-API-Key` the gateway presents on every `/pam/authorize`, `/pam/inject`, `/pam/audit/commands` call to `ztna-api`. Empty value is accepted in dev. |
| `PAM_GATEWAY_SSH_PORT`                | no       | `2222`                                 | SSH listener TCP port (parsed as an integer; no leading colon).                                                                    |
| `PAM_GATEWAY_HEALTH_PORT`             | no       | `8081`                                 | HTTP listener for `/health` and the browser SQL-console WebSocket upgrade.                                                          |
| `PAM_GATEWAY_PG_PORT`                 | no       | unset (listener off)                   | PostgreSQL wire-protocol proxy TCP port. Listener stays off when unset so an SSH-only deployment does not open the extra socket. Compose / Helm set `5432` and map it to host port `15432`. |
| `PAM_GATEWAY_MYSQL_PORT`              | no       | unset (listener off)                   | MySQL / MariaDB wire-protocol proxy TCP port. Off by default; compose / Helm set `3306` and map it to host port `13306`.            |
| `PAM_GATEWAY_K8S_PORT`                | no       | unset (listener off)                   | `kubectl exec` WebSocket bridge TCP port. Off by default; compose / Helm set `8443` and map it to host port `18443`.                |
| `PAM_GATEWAY_K8S_TLS_CERT` / `_TLS_KEY` | no     | unset                                  | Optional TLS material for the K8s listener. Unset = listener serves plaintext WS (acceptable for dev / behind a mesh sidecar).      |
| `PAM_GATEWAY_SSH_HOST_KEY`            | prod     | ephemeral (in-memory)                  | PEM-encoded Ed25519 / RSA host key path. Unset = a fresh key is generated at boot (acceptable for dev; rotates every restart).      |
| `PAM_GATEWAY_SSH_CA_KEY`              | no       | unset                                  | CA private-key path for short-lived SSH user-cert signing. Unset = listener falls back to plaintext credential injection.            |
| `PAM_GATEWAY_SSH_CA_VALIDITY`         | no       | `5m`                                   | TTL for SSH user certs the listener signs (Go duration syntax).                                                                     |
| `PAM_GATEWAY_REPLAY_DIR`              | dev      | `/var/lib/shieldnet/replay`            | Local-disk replay store path. Production deployments override with the S3-backed store via `PAM_S3_BUCKET` / `PAM_S3_REGION`.       |
| `PAM_S3_BUCKET`                       | prod     | unset                                  | S3 bucket for session replay-byte sinks.                                                                                            |
| `PAM_S3_REGION`                       | prod     | unset                                  | S3 region for the replay store.                                                                                                     |
| `GOMEMLIMIT`                          | no       | unset                                  | Helm default sets `460MiB` so the Go runtime collaborates with the cgroup memory limit (512 MiB request).                           |
| `GOGC`                                | no       | `100`                                  | Standard Go runtime GC target.                                                                                                       |

`/health` is unauthenticated and cheap (handler at
`cmd/pam-gateway/main.go:healthHandler`); the docker-compose smoke
job + Kubernetes liveness probe both rely on it.

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
