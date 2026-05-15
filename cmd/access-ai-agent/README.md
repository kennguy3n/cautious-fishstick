# access-ai-agent

Python A2A skill server that backs the platform's AI capabilities. The Go services (`internal/pkg/aiclient`) talk to this agent over plain JSON via `POST /a2a/invoke`; the agent never speaks to clients directly.

## Skills

| skill_name                  | purpose                                                  |
|-----------------------------|----------------------------------------------------------|
| `access_risk_assessment`    | Score an access request low / medium / high              |
| `access_review_automation`  | Recommend certify / revoke / escalate per pending decision |
| `access_anomaly_detection`  | Surface anomaly observations on a single grant's usage   |
| `connector_setup_assistant` | Generate a connector-setup checklist in natural language |
| `policy_recommendation`     | Recommend access rules from an org-structure summary     |

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r cmd/access-ai-agent/requirements.txt
python cmd/access-ai-agent/main.py --host 127.0.0.1 --port 8765
```

When set, `AGENT_API_KEY` (env var) requires every `/a2a/invoke` request to echo it via the `X-API-Key` header. Leave it empty in development to disable the check.

## Tests

```bash
pytest cmd/access-ai-agent/tests/
```

Each skill has a happy-path test, an error-path test, and a dispatcher end-to-end test exercising the HTTP route.

## See also

- [`docs/architecture.md`](../../docs/architecture.md#9-ai-integration) — how the agent fits into the wider system.
- [`docs/overview.md`](../../docs/overview.md) — what each skill does in product terms.
