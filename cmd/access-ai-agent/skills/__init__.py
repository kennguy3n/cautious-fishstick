"""Tier-1 skills for the access-ai-agent A2A server.

Each skill is a single function with the signature::

    def run(payload: dict) -> dict

The Go side (internal/pkg/aiclient) calls every skill through the
unified ``POST /a2a/invoke`` endpoint with body
``{"skill_name": "...", "payload": {...}}`` — the dispatcher in
``main.py`` looks up the skill by name and calls ``run(payload)``.

Phase 4 ships stub implementations that return reasonable defaults
so the Go-side fallback path is exercised in dev / test. Real LLM
integration lands in a later phase behind the same function
signature.
"""

from . import access_risk_assessment  # noqa: F401
from . import connector_setup_assistant  # noqa: F401
from . import policy_recommendation  # noqa: F401
from . import access_anomaly_detection  # noqa: F401
from . import access_review_automation  # noqa: F401

__all__ = [
    "access_risk_assessment",
    "connector_setup_assistant",
    "policy_recommendation",
    "access_anomaly_detection",
    "access_review_automation",
]
