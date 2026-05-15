# Getting started

This is the five-minute path from `git clone` to a running stack you can poke at. For project context start with [`overview.md`](overview.md); for the deeper service topology see [`architecture.md`](architecture.md).

## Prerequisites

- **Go 1.25+**
- **Docker** with Compose v2
- **Python 3.12+** (only needed if you want to run the AI sidecar tests)
- ~4 GB of free RAM for the local stack

## Clone and test

```bash
git clone https://github.com/kennguy3n/cautious-fishstick.git
cd cautious-fishstick

make test
```

`make test` runs the Go test suite under `-race -timeout=180s`. If it passes, your toolchain is wired correctly.

## Bring the stack up

```bash
make docker-up
```

This shells out to `docker compose up --build --wait`. Compose waits for healthchecks before returning, so when the command exits the full backend is reachable:

| Service                   | Port | Purpose                                             |
|---------------------------|------|-----------------------------------------------------|
| `ztna-api`                | 8080 | Public HTTP API (Gin)                               |
| `access-workflow-engine`  | 8082 | Workflow orchestration host                         |
| `access-ai-agent`         | 8090 | Python A2A skill server                             |
| Postgres                  | 5432 | Application database                                |
| Redis                     | 6379 | Worker queue + staging tables                       |

`access-connector-worker` runs without a Service — it consumes the Redis queue.

## Smoke test

Hit the API health endpoint:

```bash
curl -sS http://localhost:8080/healthz
```

Browse the OpenAPI spec:

```bash
open http://localhost:8080/swagger      # or visit in your browser
```

Tail the running services:

```bash
make docker-logs
```

## Working on the code

Common loops:

```bash
make build         # go build ./...
make test          # go test -race -timeout=180s ./...
make ci            # vet + test + swagger-check + sn360-check + model-check
make lint          # static gates only, no test suite
```

Each Go binary is wired through a shared `internal/pkg/database` helper, so all three services run their migrations against the same Postgres instance Compose provisions. See [`architecture.md`](architecture.md) for the wiring details and [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the full dev loop and PR checklist.

## Tear down

```bash
make docker-down   # docker compose down -v
```

`-v` clears the Postgres and Redis volumes. Drop the flag to keep state between runs.

## Where to go next

- [`overview.md`](overview.md) — what the platform does and how it's structured.
- [`architecture.md`](architecture.md) — service topology, data model, connector contract.
- [`connectors.md`](connectors.md) — capability matrix for all 200 connectors.
- [`sdk.md`](sdk.md) — mobile + desktop SDK contract.
- [`guides/`](guides/) — platform integration walkthroughs.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — how to send a change.
