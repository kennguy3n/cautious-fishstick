# docker/

Container build files for the ShieldNet 360 Access Platform. The
local stack at the repo root (`docker-compose.yml`) and the Helm
chart under `deploy/helm/shieldnet-access/` consume these
Dockerfiles directly — no separate registry workflow.

## Dockerfiles

| File                              | Service                  | Port | Entrypoint                |
|-----------------------------------|--------------------------|:----:|---------------------------|
| `Dockerfile.ztna-api`             | `ztna-api`               | 8080 | `/ztna-api`               |
| `Dockerfile.access-worker`        | `access-connector-worker`| —    | `/access-worker`          |
| `Dockerfile.access-workflow`      | `access-workflow-engine` | 8082 | `/access-workflow`        |
| `../cmd/access-ai-agent/Dockerfile` | `access-ai-agent`      | 8090 | `python main.py`          |

The Python sidecar lives next to its source under
[`cmd/access-ai-agent/`](../cmd/access-ai-agent/) — keeping the
Dockerfile colocated with `requirements.txt` and `main.py` mirrors
the rest of the cmd-binary layout.

## Multi-stage pattern (Go binaries)

All three Go services share the same two-stage layout:

1. **`golang:1.25-alpine AS build`** — pulls module deps in a
   dedicated layer (so a code-only change does not re-download the
   cache), then runs `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`
   into `/out/<binary>`. `CGO_ENABLED=0` is required so the static
   binary can land on distroless.
2. **`gcr.io/distroless/static-debian12:nonroot AS runtime`** —
   copies just the binary, runs as the `nonroot` user, and declares
   `ENTRYPOINT`. No shell, no package manager, no setuid binaries in
   the runtime image.

The `--mount=type=cache` flags require BuildKit (Docker 23+ or
Compose v2 with `DOCKER_BUILDKIT=1`); both `docker compose up
--build` and the CI smoke job enable BuildKit by default.

## Base images

| Stage   | Image                                       | Why                                            |
|---------|---------------------------------------------|------------------------------------------------|
| build   | `golang:1.25-alpine`                        | Smallest Go 1.25 image with the toolchain      |
| runtime | `gcr.io/distroless/static-debian12:nonroot` | No shell, no libc, minimum attack surface      |
| python  | `python:3.12-slim`                          | Stdlib-only A2A server; no native deps needed  |

The Python image is intentionally not distroless: the dispatcher
calls `python -c "import urllib.request, sys; …"` from its
healthcheck so the container needs a working Python runtime.

## Build locally

```bash
docker build -f docker/Dockerfile.ztna-api -t ztna-api .
docker build -f docker/Dockerfile.access-worker -t access-worker .
docker build -f docker/Dockerfile.access-workflow -t access-workflow .
docker build -f cmd/access-ai-agent/Dockerfile -t access-ai-agent cmd/access-ai-agent
```

Or build all four through the compose stack:

```bash
make docker-up      # docker compose up --build --wait
make docker-down    # docker compose down -v
```

## Healthchecks

Each Dockerfile-derived service has a real container healthcheck so
`docker compose up --wait` only returns when the dependency graph is
fully reachable. The Go binaries self-probe in `--healthcheck` mode
(`/ztna-api --healthcheck`, `/access-workflow --healthcheck`); the
worker has no port and therefore no compose-level healthcheck. The
Python agent's healthcheck hits its own `/healthz` route.

See [`../docker-compose.yml`](../docker-compose.yml) for the full
healthcheck wiring and [`../cmd/README.md`](../cmd/README.md) for the
per-binary env-var contract.
