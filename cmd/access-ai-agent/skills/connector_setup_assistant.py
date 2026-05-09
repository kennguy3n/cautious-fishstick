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

from typing import Any, Dict, List


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
    return {
        "explanation": f"Setup guidance for connector kind {kind!r}.",
        "next_steps": steps,
    }
