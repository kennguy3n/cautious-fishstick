# shieldnet-access Helm chart

Multi-tenant ZTNA control plane for the ShieldNet Access platform.
Packages the four runtime services into a single chart so operators
can roll out, upgrade, and tune the stack per environment.

## What this chart deploys

| Service                  | Kind       | Port | Public? | Notes                                                |
|--------------------------|------------|------|---------|------------------------------------------------------|
| `ztna-api`               | Deployment | 8080 | Yes     | Public HTTP surface; HPA included                    |
| `access-connector-worker`| Deployment | -    | No      | Headless Redis-queue consumer; no Service            |
| `access-workflow`        | Deployment | 8082 | No      | Cluster-internal webhook engine                      |
| `access-ai-agent`        | Deployment | 8090 | No      | Python A2A skill server                              |

Each Deployment ships with its own ConfigMap, Secret (placeholder
values — replace before production), ServiceAccount, and (where
applicable) Service. Sizing follows the deployment pattern documented
in [`docs/architecture.md`](../../../docs/architecture.md#12-where-things-run):

- API services: `cpu=200m mem=1Gi`, `GOMEMLIMIT=900MiB GOGC=100`
- Worker:       `cpu=2 mem=400Mi`, `GOMEMLIMIT=360MiB GOGC=75`
- AI agent:     sized per model load; defaults assume remote LLM

## Install

```bash
helm install shieldnet-access deploy/helm/shieldnet-access \
  --namespace shieldnet-access \
  --create-namespace \
  --values your-overrides.yaml
```

## Required overrides

The defaults in `values.yaml` ship with `CHANGE_ME` placeholders for
every Secret value. At minimum override:

```yaml
ztnaApi:
  secrets:
    databaseUrl: "postgres://access:REAL@..."
    redisUrl: "redis://..."
    aiAgentApiKey: "<shared-secret-also-on-ai-agent>"

accessWorker:
  secrets:
    databaseUrl: "postgres://access:REAL@..."
    redisUrl: "redis://..."

accessWorkflow:
  secrets:
    databaseUrl: "postgres://access:REAL@..."
    redisUrl: "redis://..."

accessAiAgent:
  secrets:
    apiKey: "<same-secret-as-ztnaApi.aiAgentApiKey>"
    openaiApiKey: "<optional>"
```

For production, replace each `Secret` template with a reference to
External Secrets Operator or sealed-secrets — never commit real
credentials to `values.yaml`.

## Reference patterns

The chart structure follows the conventions established by
`uneycom/ztna-k8s-assets` and `uneycom/shieldnet-agents-k8s-helm`
(read-only reference repos): per-service template files, a shared
`_helpers.tpl`, and `values.yaml` keys grouped by service.

## Alternative: raw Kustomize

For operators who prefer raw manifests over Helm, the same stack is
also shipped as Kustomize-ready YAML at `deploy/k8s/` (apply with
`kubectl apply -k deploy/k8s/`).
