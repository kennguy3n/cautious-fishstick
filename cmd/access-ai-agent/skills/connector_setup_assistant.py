"""connector_setup_assistant skill.

Guides admins through connector setup in natural language. The Go
side calls this when a connector validation surfaces missing config
or secrets — the agent returns a structured ``next_steps`` array the
admin UI renders as an ordered checklist.

Phase 4 stub: returns a hard-coded checklist keyed off the
connector_kind from the payload. Phase 5 swaps in an LLM-backed
generator that pulls from the connector's published metadata.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from .llm import LLMUnavailable, call_llm, parse_json_response


logger = logging.getLogger(__name__)


KNOWN_KINDS = {
    "okta": [
        "Generate a SCIM API token in Okta admin (Security > API > Tokens).",
        "Set the connector's scim_base_url to https://<your-org>.okta.com/api/v1.",
        "Set the connector's scim_auth_header secret to 'SSWS <token>'.",
        "Verify with a SCIM /Users GET; expect HTTP 200 with a totalResults envelope.",
    ],
    "github": [
        "Create a fine-grained Personal Access Token with org:admin scope.",
        "Set the connector's github_org config to your org slug.",
        "Set the connector's github_token secret to the PAT value.",
        "Verify with `gh auth status` or a /orgs/<org>/members GET; expect 200.",
    ],
    "aws_iam": [
        "Create an IAM user with an inline policy granting iam:Get*, iam:List*, iam:UpdateUser, iam:Attach*.",
        "Generate access keys for the user.",
        "Set the connector's aws_region config and aws_access_key_id / aws_secret_access_key secrets.",
        "Verify with a `aws iam list-users --max-items 1` call; expect 200.",
    ],
    "openziti": [
        "Provision an OpenZiti identity for the access platform with admin role.",
        "Export the identity JWT and set it as the connector's ziti_admin_jwt secret.",
        "Set the connector's ziti_controller_url config to the controller's HTTPS endpoint.",
        "Verify with a `ziti edge list identities --filter \"name=<id>\"` call.",
    ],
}


class SkillError(ValueError):
    """Raised when the payload is malformed."""


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return setup guidance for the supplied connector_kind."""
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    kind = payload.get("connector_kind")
    if not isinstance(kind, str) or not kind:
        raise SkillError("connector_kind is required and must be a string")

    steps: List[str] = KNOWN_KINDS.get(kind.lower(), [])
    if not steps:
        # Fallback path: every connector with a SCIM v2.0 backend
        # supports the same config keys (scim_base_url +
        # scim_auth_header).
        steps = [
            f"Connector kind {kind!r} is not in the curated guide list; using the generic SCIM v2.0 fallback:",
            "Set the connector's scim_base_url config to the provider's SCIM v2 root URL.",
            "Set the connector's scim_auth_header secret to the literal Authorization header value (e.g. 'Bearer <token>').",
            "Verify with a SCIM /Users GET; expect HTTP 200.",
        ]
    deterministic = {
        "explanation": f"Setup guidance for connector kind {kind!r}.",
        "next_steps": steps,
    }

    # Phase 5: ask the LLM for natural-language guidance, parsed
    # into a structured next_steps array. The deterministic
    # checklist is always returned; the LLM result either replaces
    # or augments it depending on whether the user supplied a
    # ``user_question`` (free-text question vs. plain wizard
    # prompt).
    user_question = payload.get("user_question") if isinstance(payload.get("user_question"), str) else ""
    wizard_state = payload.get("wizard_state") if isinstance(payload.get("wizard_state"), dict) else {}
    try:
        llm_out = _llm_assistant(kind, user_question, wizard_state, deterministic)
    except LLMUnavailable as exc:
        logger.debug("llm connector assistant unavailable: %s", exc)
        return deterministic
    return llm_out


# Substrings used to scrub credential-bearing wizard fields before the
# state is sent to the LLM. Connectors commonly use names like
# ``api_key``, ``aws_access_key_id``, ``scim_auth_header``, and
# ``password`` — none of which contain "secret"/"token" — so the
# deny-list has to cover the broader set of patterns.
_SECRET_KEY_SUBSTRINGS = (
    "secret",
    "token",
    "password",
    "key",
    "auth",
    "credential",
)


def _llm_assistant(
    kind: str, user_question: str, wizard_state: Dict[str, Any], baseline: Dict[str, Any]
) -> Dict[str, Any]:
    # Cap free-text input lengths to avoid bloating the prompt or
    # smuggling long prompt-injection payloads from end users.
    if len(user_question) > 1000:
        user_question = user_question[:1000] + "\u2026"
    safe_state = {
        k: v
        for k, v in wizard_state.items()
        if isinstance(k, str) and not any(s in k.lower() for s in _SECRET_KEY_SUBSTRINGS)
    }
    prompt = (
        "Help the admin configure a connector. Respond with strict JSON"
        " {\"explanation\": one-paragraph natural-language answer,"
        " \"next_steps\": ordered array of one-line action strings,"
        " \"wizard_field_hints\": object mapping wizard field name to suggested"
        " value or guidance string}.\n"
        f"connector_kind: {kind}\n"
        f"user_question: {user_question}\n"
        f"wizard_state (secrets stripped): {safe_state}\n"
        f"deterministic_baseline: {baseline['next_steps']}\n"
    )
    result = call_llm(prompt, system="You are a connector-setup assistant.")
    parsed = parse_json_response(result.text)
    explanation = parsed.get("explanation")
    next_steps = parsed.get("next_steps")
    if not isinstance(next_steps, list) or not next_steps:
        raise LLMUnavailable("llm next_steps missing or empty")
    next_steps = [s for s in next_steps if isinstance(s, str) and s.strip()]
    if not next_steps:
        raise LLMUnavailable("llm next_steps had no usable strings")
    out: Dict[str, Any] = {
        "explanation": explanation if isinstance(explanation, str) and explanation.strip() else baseline["explanation"],
        "next_steps": next_steps,
    }
    hints = parsed.get("wizard_field_hints")
    if isinstance(hints, dict):
        out["wizard_field_hints"] = {k: v for k, v in hints.items() if isinstance(k, str)}
    return out
