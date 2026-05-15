"""access_risk_assessment skill.

Scores an access request (or policy change) on a low / medium / high
scale plus a structured risk_factors list. The Go side wraps every
call with AssessRiskWithFallback (docs/architecture.md §9) so a failure here
defaults to risk_score="medium" and routes the request through
manager_approval.

Phase 4 stub: returns a deterministic, rule-based score from the
payload's flat keys. Phase 5 swaps in an LLM-backed scorer behind
the same ``run(payload)`` signature.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from .llm import LLMUnavailable, call_llm, parse_json_response


logger = logging.getLogger(__name__)


# Roles the platform considers privileged. A request for any of
# these implicitly bumps the score to "high" regardless of the rest
# of the signals.
PRIVILEGED_ROLES = {"admin", "owner", "root", "superuser", "domain_admin"}

# Tags that indicate a production-tier resource. Production access
# bumps the score by one band.
PRODUCTION_TAGS = {"prod", "production", "prd", "tier:1"}

# Allowed risk_score values — the Go side validates the response
# against this set before persisting.
ALLOWED_SCORES = ("low", "medium", "high")


class SkillError(ValueError):
    """Raised when the skill's payload is malformed.

    The A2A dispatcher catches SkillError and returns 400; every
    other exception surfaces as 500 so operators can see the
    traceback in agent logs.
    """


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Score an access request payload.

    Required keys (raises SkillError if missing):
        - role (str): the requested role
        - resource_external_id (str): the target resource

    Optional keys:
        - resource_tags (list[str]): tags on the resource
        - duration_hours (int): requested duration
        - justification (str): the requester's free-text rationale
    """
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")

    role = payload.get("role")
    resource = payload.get("resource_external_id")
    if not role or not isinstance(role, str):
        raise SkillError("role is required and must be a string")
    if not resource or not isinstance(resource, str):
        raise SkillError("resource_external_id is required and must be a string")

    factors: List[str] = []
    score = "low"

    if role.lower() in PRIVILEGED_ROLES:
        factors.append(f"privileged_role:{role.lower()}")
        score = "high"
    else:
        # Bump to medium for any role with "write" / "edit" / "admin"
        # in its name even when not in the strict privileged set.
        lowered = role.lower()
        if any(token in lowered for token in ("write", "edit", "admin", "modify")):
            factors.append(f"write_role:{lowered}")
            score = "medium"

    tags = payload.get("resource_tags") or []
    if isinstance(tags, list):
        prod_hits = [t for t in tags if isinstance(t, str) and t.lower() in PRODUCTION_TAGS]
        if prod_hits:
            factors.append("production_resource")
            score = _bump(score)

    # bool is a subclass of int, so a payload sending
    # ``"duration_hours": True`` would otherwise satisfy isinstance
    # and (since True > 168 is False) silently ignore the field
    # rather than reject it. Reject explicitly so callers cannot
    # smuggle a boolean past validation.
    duration = payload.get("duration_hours")
    if isinstance(duration, bool):
        duration = None
    if isinstance(duration, (int, float)) and duration > 168:  # >1 week
        factors.append("long_duration")
        score = _bump(score)

    justification = payload.get("justification")
    if isinstance(justification, str) and len(justification.strip()) < 10:
        factors.append("weak_justification")

    deterministic = {
        "risk_score": score,
        "risk_factors": factors,
        "reason": f"Phase 4 stub scorer flagged {len(factors)} risk factor(s)",
    }

    # Phase 5: try the LLM scorer, fall back to deterministic on
    # any failure. The deterministic result is also handed to the
    # LLM as ``baseline`` context so the model has the rule-based
    # signals it can corroborate or override.
    try:
        llm_out = _llm_score(payload, deterministic)
    except LLMUnavailable as exc:
        logger.debug("llm risk scoring unavailable: %s", exc)
        return deterministic
    return llm_out


def _llm_score(payload: Dict[str, Any], deterministic: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke the configured LLM and parse its structured response.

    The model is instructed to return JSON with the same schema as
    the deterministic scorer; on any deviation we surface
    :class:`LLMUnavailable` so the caller falls back.
    """
    prompt = _build_prompt(payload, deterministic)
    result = call_llm(
        prompt,
        system=(
            "You are a security risk-scoring assistant. Respond with strict"
            " JSON: {\"risk_score\": one of [low, medium, high], \"risk_factors\":"
            " array of short strings, \"reason\": one sentence}."
        ),
    )
    parsed = parse_json_response(result.text)
    score = parsed.get("risk_score")
    if score not in ALLOWED_SCORES:
        raise LLMUnavailable(f"llm returned unknown risk_score {score!r}")
    factors = parsed.get("risk_factors") or []
    if not isinstance(factors, list):
        raise LLMUnavailable("llm risk_factors is not a list")
    factors = [f for f in factors if isinstance(f, str)]
    reason = parsed.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        reason = deterministic["reason"]
    return {"risk_score": score, "risk_factors": factors, "reason": reason}


def _build_prompt(payload: Dict[str, Any], deterministic: Dict[str, Any]) -> str:
    """Render the LLM prompt without leaking secrets.

    Only fields the deterministic stub already inspected are
    forwarded. Free-text justifications are truncated to 500 chars
    so a malicious requester cannot smuggle a long prompt-injection
    payload through.
    """
    role = payload.get("role")
    resource = payload.get("resource_external_id")
    tags = payload.get("resource_tags") or []
    duration = payload.get("duration_hours")
    justification = payload.get("justification") or ""
    if isinstance(justification, str) and len(justification) > 500:
        justification = justification[:500] + "\u2026"
    return (
        "Score this access request:\n"
        f"role: {role}\n"
        f"resource_external_id: {resource}\n"
        f"resource_tags: {tags}\n"
        f"duration_hours: {duration}\n"
        f"justification: {justification}\n\n"
        f"Deterministic baseline (corroborate or override): {deterministic}\n"
    )


def _bump(score: str) -> str:
    """Increase the score by one band (low → medium → high)."""
    if score == "low":
        return "medium"
    if score == "medium":
        return "high"
    return "high"
