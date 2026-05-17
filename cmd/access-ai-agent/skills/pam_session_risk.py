"""pam_session_risk_assessment skill.

Scores a privileged-session request on a low / medium / high scale
plus a structured risk_factors list and a routing recommendation
(``auto_approve`` / ``require_approval`` / ``deny``).

The Go side (``internal/services/pam/session_service.go``) wraps every
call with AssessRiskWithFallback so a failure here defaults to
``risk_score="medium"`` and ``recommendation="require_approval"``,
matching the docs/pam/architecture.md §6 "AI is decision-support, not
critical path" guarantee.

Phase 4 stub: returns a deterministic, rule-based score from the
payload's flat keys. Phase 5 swaps in an LLM-backed scorer behind
the same ``run(payload)`` signature, mirroring the wire-in pattern
in ``access_risk_assessment``.

Input schema (required keys raise SkillError if missing):

    - user_id (str)            : the requester
    - asset_id (str)           : the target asset
    - protocol (str)           : ssh / k8s / postgres / mysql
    - criticality (str)        : low / medium / high (asset's own tag)

Optional keys (deterministic stub silently ignores unknown types):

    - time_of_day (int 0-23)        : local hour the request was made
    - previous_denials (int)        : count of denied requests for this
                                       user/asset combo in the last 30d
    - is_first_access (bool)        : true if user has never accessed
                                       this asset before
    - is_emergency (bool)           : true if requester marked the
                                       session as break-glass
    - working_hours_start (int 0-23): lower bound for "unusual hour"
                                       check (default 6)
    - working_hours_end   (int 0-23): upper bound (default 22)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from .llm import LLMUnavailable, call_llm, parse_json_response


logger = logging.getLogger(__name__)


# Asset criticality bands that imply heightened risk even before the
# request payload's other signals are considered. A "high" criticality
# asset alone routes to require_approval.
HIGH_CRITICALITY = {"high", "critical"}
MEDIUM_CRITICALITY = {"medium"}

# Allowed risk_score / recommendation values — both the Python side
# and the Go side validate against this whitelist before persisting.
ALLOWED_SCORES = ("low", "medium", "high")
ALLOWED_RECOMMENDATIONS = ("auto_approve", "require_approval", "deny")

# Default working-hours window when the payload omits the optional
# overrides. Aligned with docs/pam/proposal.md §6 ("requests outside
# 06:00–22:00 local time are flagged as off-hours").
DEFAULT_WORKING_HOURS_START = 6
DEFAULT_WORKING_HOURS_END = 22

# Per-user/asset denial threshold that flips a request from
# "require_approval" up to "deny" — repeated denials are a strong
# signal that the policy already rejects this combination.
DENIAL_DENY_THRESHOLD = 3


class SkillError(ValueError):
    """Raised when the skill's payload is malformed.

    The A2A dispatcher catches SkillError and returns 400; every
    other exception surfaces as 500 so operators can see the
    traceback in agent logs.
    """


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Score a PAM session request payload.

    See module docstring for the full input contract.
    """
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")

    user_id = payload.get("user_id")
    asset_id = payload.get("asset_id")
    protocol = payload.get("protocol")
    criticality = payload.get("criticality")
    for name, value in (
        ("user_id", user_id),
        ("asset_id", asset_id),
        ("protocol", protocol),
        ("criticality", criticality),
    ):
        if not isinstance(value, str) or not value:
            raise SkillError(f"{name} is required and must be a non-empty string")
    assert isinstance(criticality, str)  # narrow for mypy

    factors: List[str] = []
    score = "low"

    crit = criticality.lower()
    if crit in HIGH_CRITICALITY:
        factors.append(f"high_criticality_asset:{crit}")
        score = "high"
    elif crit in MEDIUM_CRITICALITY:
        factors.append("medium_criticality_asset")
        score = _bump(score)

    # bool is a subclass of int; reject explicitly so a payload of
    # ``"time_of_day": True`` (= 1) cannot mascarade as 1am.
    time_of_day = payload.get("time_of_day")
    if isinstance(time_of_day, bool):
        time_of_day = None
    working_start = _hour_or_default(
        payload.get("working_hours_start"), DEFAULT_WORKING_HOURS_START
    )
    working_end = _hour_or_default(
        payload.get("working_hours_end"), DEFAULT_WORKING_HOURS_END
    )
    if isinstance(time_of_day, (int, float)):
        hour = int(time_of_day)
        if 0 <= hour <= 23 and (hour < working_start or hour >= working_end):
            factors.append(f"unusual_time:{hour:02d}")
            score = _bump(score)

    previous_denials = payload.get("previous_denials")
    if isinstance(previous_denials, bool):
        previous_denials = None
    if isinstance(previous_denials, int) and previous_denials > 0:
        factors.append(f"previous_denials:{previous_denials}")
        if previous_denials >= DENIAL_DENY_THRESHOLD:
            score = "high"
        else:
            score = _bump(score)

    if payload.get("is_first_access") is True:
        factors.append("first_time_asset_access")
        score = _bump(score)

    if payload.get("is_emergency") is True:
        # Break-glass requests always require approval per
        # docs/pam/proposal.md §6 — they get flagged and the
        # recommendation below promotes the band to at least
        # require_approval regardless of score.
        factors.append("emergency_access")
        score = _bump(score)

    recommendation = _recommend(score, factors, previous_denials)
    reason = (
        f"Phase 4 stub PAM scorer flagged {len(factors)} risk factor(s);"
        f" routing to {recommendation}."
    )
    deterministic = {
        "risk_score": score,
        "risk_factors": factors,
        "recommendation": recommendation,
        "reason": reason,
    }

    # Phase 5 LLM scoring: same wire-in as access_risk_assessment.
    try:
        return _llm_score(payload, deterministic)
    except LLMUnavailable as exc:
        logger.debug("llm PAM scoring unavailable: %s", exc)
        return deterministic


def _llm_score(payload: Dict[str, Any], deterministic: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke the configured LLM and parse its structured response.

    The deterministic baseline is handed to the LLM as context so the
    model has the rule-based signals it can corroborate or override.
    On any deviation we surface :class:`LLMUnavailable` so the caller
    falls back to the deterministic result.
    """
    prompt = _build_prompt(payload, deterministic)
    result = call_llm(
        prompt,
        system=(
            "You are a privileged-access risk-scoring assistant."
            " Respond with strict JSON: {\"risk_score\": one of [low,"
            " medium, high], \"risk_factors\": array of short strings,"
            " \"recommendation\": one of [auto_approve, require_approval,"
            " deny], \"reason\": one sentence}."
        ),
    )
    parsed = parse_json_response(result.text)
    score = parsed.get("risk_score")
    if score not in ALLOWED_SCORES:
        raise LLMUnavailable(f"llm returned unknown risk_score {score!r}")
    recommendation = parsed.get("recommendation")
    if recommendation not in ALLOWED_RECOMMENDATIONS:
        raise LLMUnavailable(
            f"llm returned unknown recommendation {recommendation!r}"
        )
    factors = parsed.get("risk_factors") or []
    if not isinstance(factors, list):
        raise LLMUnavailable("llm risk_factors is not a list")
    factors = [f for f in factors if isinstance(f, str)]
    reason = parsed.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        reason = deterministic["reason"]
    return {
        "risk_score": score,
        "risk_factors": factors,
        "recommendation": recommendation,
        "reason": reason,
    }


def _build_prompt(payload: Dict[str, Any], deterministic: Dict[str, Any]) -> str:
    """Render the LLM prompt without leaking secrets.

    Only fields the deterministic stub already inspected are
    forwarded so the model never sees an injected credential or
    long free-text field.
    """
    return (
        "Score this PAM session request:\n"
        f"user_id: {payload.get('user_id')}\n"
        f"asset_id: {payload.get('asset_id')}\n"
        f"protocol: {payload.get('protocol')}\n"
        f"criticality: {payload.get('criticality')}\n"
        f"time_of_day: {payload.get('time_of_day')}\n"
        f"previous_denials: {payload.get('previous_denials')}\n"
        f"is_first_access: {payload.get('is_first_access')}\n"
        f"is_emergency: {payload.get('is_emergency')}\n\n"
        f"Deterministic baseline (corroborate or override): {deterministic}\n"
    )


def _bump(score: str) -> str:
    """Increase the score by one band (low → medium → high)."""
    if score == "low":
        return "medium"
    if score == "medium":
        return "high"
    return "high"


def _hour_or_default(value: Any, default: int) -> int:
    """Coerce the working-hours bound to a sane integer hour.

    Rejects booleans (subclass of int), out-of-range values, and
    non-numerics; falls back to the documented default so a malformed
    payload never causes the unusual-hour check to silently disable.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int) and 0 <= value <= 23:
        return value
    return default


def _recommend(score: str, factors: List[str], previous_denials: Any) -> str:
    """Translate a (score, factors) pair into a routing recommendation.

    Rules — kept narrow so test coverage is exhaustive:

      - 3+ prior denials                                        → deny
      - emergency_access                                        → require_approval (or deny)
      - score == high                                           → require_approval
      - score == medium AND any high-signal factor              → require_approval
      - score == low AND no factors                             → auto_approve
      - default                                                 → require_approval
    """
    if isinstance(previous_denials, int) and previous_denials >= DENIAL_DENY_THRESHOLD:
        return "deny"
    if "emergency_access" in factors:
        return "require_approval"
    if score == "high":
        return "require_approval"
    if score == "low" and not factors:
        return "auto_approve"
    return "require_approval"
