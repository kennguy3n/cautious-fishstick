# deploy/

Kubernetes manifests and Helm chart for the ShieldNet Access
platform. Two equivalent paths:

| Path                  | Tool       | When to use                                                      |
|-----------------------|------------|------------------------------------------------------------------|
| `deploy/k8s/`         | `kubectl` / Kustomize | Quick install on a fresh cluster, GitOps overlays, or CI smoke |
| `deploy/helm/shieldnet-access/` | Helm 3 | Production rollouts; preferred for per-environment value overrides |

## What gets deployed

Four runtime services per `docs/overview.md` §10.2 and
`docs/architecture.md` §11:

- **ztna-api** — public HTTP surface (port 8080). HPA 2–10 replicas.
- **access-connector-worker** — Redis-queue consumer (no Service).
- **access-workflow-engine** — cluster-internal webhook engine (port 8082).
- **access-ai-agent** — Python A2A skill server (port 8090).

Per `docs/overview.md` §10.3, only `ztna-api` is exposed publicly;
the other three live on the cluster-internal network and
authenticate via the shared `ACCESS_AI_AGENT_API_KEY` /
`X-API-Key` header.

## Kustomize quick start

```bash
kubectl apply -k deploy/k8s/
```

Applies the namespace, then every Deployment / Service / ConfigMap /
Secret / HPA in dependency order. The placeholder Secrets ship with
`CHANGE_ME` values — replace before running anywhere real.

## Helm install

```bash
helm install shieldnet-access deploy/helm/shieldnet-access \
  --namespace shieldnet-access \
  --create-namespace \
  --values my-prod-overrides.yaml
```

See `deploy/helm/shieldnet-access/README.md` for the required
overrides and the recommended External Secrets / sealed-secrets
pattern.

## Reference repos

These deployment manifests intentionally mirror the patterns from
two reference-only repos:

- `uneycom/ztna-k8s-assets` — for ArgoCD application + Helm overlay layouts.
- `uneycom/shieldnet-agents-k8s-helm` — for SecurityContext, HPA, and `app.kubernetes.io/*` label conventions.
