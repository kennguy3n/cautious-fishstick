# access-ai-agent

Phase 4 A2A skill server for the cautious-fishstick access platform.
The Go side (`internal/pkg/aiclient`) talks to this agent over plain
JSON via `POST /a2a/invoke`.

## Skills

| skill_name                  | purpose                                                  |
|-----------------------------|----------------------------------------------------------|
| `access_risk_assessment`    | Score an access request low/medium/high                  |
| `access_review_automation`  | Suggest certify/revoke/escalate per pending decision     |
| `access_anomaly_detection`  | Surface anomaly observations on a single grant's usage   |
| `connector_setup_assistant` | Generate a connector-setup checklist in natural language |
| `policy_recommendation`     | Recommend policies from an org-structure summary         |

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r cmd/access-ai-agent/requirements.txt
python cmd/access-ai-agent/main.py --host 127.0.0.1 --port 8765
```

`AGENT_API_KEY` (env var) — when set, every `/a2a/invoke` request
must echo it via the `X-API-Key` header. Empty (the dev default)
disables the check.

## Tests

```bash
pytest cmd/access-ai-agent/tests/
```

Each skill has a happy-path + an error-path test plus a dispatcher
end-to-end test exercising the HTTP route.

## Phase 5 follow-ups

- Replace the deterministic stubs in each skill with an LLM-backed
  reasoner behind the same `run(payload)` signature.
- Wire `access_anomaly_detection` to a real cross-grant baseline
  histogram (Phase 6 access_audit_logs pipeline).
- Swap the stdlib http.server for FastAPI when concurrency demands
  it (the route surface stays the same).
