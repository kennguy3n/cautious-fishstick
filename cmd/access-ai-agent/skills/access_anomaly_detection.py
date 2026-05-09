"""access_anomaly_detection skill.

Surfaces structured anomaly observations on a single access grant's
recent usage. The Go side wraps every call with
DetectAnomaliesWithFallback (PROPOSAL §5.3) so a failure here
defaults to an empty list.

Phase 4 stub: deterministic rule-based anomaly detection from the
``usage_data`` payload. Phase 5+ swaps in an LLM- or stats-based
detector behind the same ``run(payload)`` signature.
"""
from __future__ import annotations

from typing import Any, Dict, List


class SkillError(ValueError):
    """Raised when the payload is malformed."""


# Stale-grant threshold — Phase 4 default is 60 days. Phase 5+ will
# pull this from the access_anomaly_detection_config table.
STALE_DAYS_THRESHOLD = 60


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return any anomalies the rule-based stub detects."""
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    grant_id = payload.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        raise SkillError("grant_id is required and must be a string")
    usage = payload.get("usage_data") or {}
    if not isinstance(usage, dict):
        raise SkillError("usage_data must be an object when supplied")

    anomalies: List[Dict[str, Any]] = []

    # Stale-grant signal: days_since_last_use beyond the threshold.
    days = usage.get("days_since_last_use")
    if isinstance(days, (int, float)) and days >= STALE_DAYS_THRESHOLD:
        anomalies.append({
            "kind": "stale_grant",
            "severity": "medium",
            "confidence": min(1.0, 0.5 + float(days - STALE_DAYS_THRESHOLD) / 180.0),
            "reason": f"Grant has not been used for {int(days)} days (threshold {STALE_DAYS_THRESHOLD}).",
        })

    # Geo-unusual signal: usage_data.unusual_geo flag, used by tests
    # to drive the geo branch without modelling a histogram in the
    # stub. Phase 5 replaces this with a real cross-grant baseline.
    if usage.get("unusual_geo"):
        anomalies.append({
            "kind": "geo_unusual",
            "severity": "high",
            "confidence": 0.85,
            "reason": "Grant used from a region outside the user's baseline.",
        })

    # Frequency-spike signal: usage_data.frequency_ratio > 5 means
    # the grant's daily usage is >5x the user's baseline.
    ratio = usage.get("frequency_ratio")
    if isinstance(ratio, (int, float)) and ratio > 5:
        anomalies.append({
            "kind": "frequency_spike",
            "severity": "medium",
            "confidence": 0.75,
            "reason": f"Usage frequency is {ratio:.1f}x the baseline.",
        })

    return {"anomalies": anomalies}
