"""access_review_automation skill.

Suggests a per-decision verdict (certify / revoke / escalate) for a
pending access_review_decisions row. The Go side calls this from the
auto-certification path (PHASES Phase 5) and treats the AI's
``decision`` as advisory — the row is still flipped to
``auto_certified=true`` only if the verdict is ``certify`` and a
human reviewer has not already weighed in.

Phase 4 stub: deterministic rule-based decisioning. Phase 5+ swaps
in an LLM-backed reasoner behind the same ``run(payload)`` signature.
"""
from __future__ import annotations

from typing import Any, Dict


class SkillError(ValueError):
    """Raised when the payload is malformed."""


# Decisions the agent is allowed to return. Anything outside this
# set surfaces as a 500 from the dispatcher.
ALLOWED_DECISIONS = ("certify", "revoke", "escalate")


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a (decision, reason) tuple for the supplied grant.

    Required keys:
        - grant_id (str): the grant under review
        - usage_data (dict): the same shape access_anomaly_detection
          consumes
    """
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    grant_id = payload.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        raise SkillError("grant_id is required and must be a string")
    usage = payload.get("usage_data") or {}
    if not isinstance(usage, dict):
        raise SkillError("usage_data must be an object when supplied")

    days = usage.get("days_since_last_use")
    role = (payload.get("role") or "").lower()

    # Stale grants on non-privileged roles are revoke candidates.
    if isinstance(days, (int, float)) and days >= 90 and role not in {"admin", "owner"}:
        return {
            "decision": "revoke",
            "reason": f"Grant unused for {int(days)} days; auto-revoke recommended.",
        }
    # Privileged roles always escalate.
    if role in {"admin", "owner", "root", "superuser"}:
        return {
            "decision": "escalate",
            "reason": "Privileged role requires manual review.",
        }
    # Default: certify (the AI agent's "looks fine" verdict).
    return {
        "decision": "certify",
        "reason": "No anomalies surfaced; grant appears in continuous use.",
    }
