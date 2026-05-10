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

import logging
from statistics import mean, pstdev
from typing import Any, Dict, Iterable, List


logger = logging.getLogger(__name__)


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

    # Phase 5: cross-grant baseline. When the caller passes a
    # ``baseline_usage_per_day`` (a list of comparable per-grant
    # averages from peers in the same workspace), we compute the
    # workspace mean and standard deviation and flag the grant if
    # its usage is more than ``baseline_threshold_sigma`` (default
    # 2.5) standard deviations above the mean. This is the
    # cross-grant histogram view PROPOSAL §5.3 calls for.
    baseline_series = payload.get("baseline_usage_per_day")
    grant_usage_per_day = usage.get("usage_per_day")
    threshold = payload.get("baseline_threshold_sigma", 2.5)
    spike = _baseline_outlier(baseline_series, grant_usage_per_day, threshold)
    if spike is not None:
        anomalies.append(spike)

    # Off-hours access: count weekday business-hour vs. off-hours
    # access events. >70% off-hours is an anomaly.
    off_pct = usage.get("off_hours_pct")
    if isinstance(off_pct, (int, float)) and off_pct > 0.7:
        anomalies.append({
            "kind": "off_hours_access",
            "severity": "medium",
            "confidence": 0.6,
            "reason": f"{int(off_pct * 100)}% of access events fell outside business hours.",
        })

    # Geographic outlier: explicit list of unique geos. >2 distinct
    # countries in a 24h window is an anomaly.
    geos = usage.get("distinct_countries_24h")
    if isinstance(geos, (int, float)) and geos > 2:
        anomalies.append({
            "kind": "geographic_outlier",
            "severity": "high",
            "confidence": 0.85,
            "reason": f"Grant accessed from {int(geos)} distinct countries in 24h.",
        })

    # Unused high-privilege grant: a grant with privileged role and
    # a stale signal. Higher severity than plain stale_grant since
    # the blast radius is larger.
    is_privileged = bool(payload.get("is_privileged")) or any(
        a["kind"] == "stale_grant" and (payload.get("role", "") in {"admin", "owner", "root"}) for a in anomalies
    )
    if is_privileged and any(a["kind"] == "stale_grant" for a in anomalies):
        anomalies.append({
            "kind": "unused_high_privilege",
            "severity": "high",
            "confidence": 0.9,
            "reason": "Privileged grant has not been used recently; consider revoking.",
        })

    return {"anomalies": anomalies}


def _baseline_outlier(
    baseline_series: Any,
    grant_usage: Any,
    threshold: Any,
) -> Dict[str, Any] | None:
    """Return a baseline-spike anomaly if the grant exceeds peers.

    Returns ``None`` for any malformed input — anomaly detection
    must NEVER raise on bad shape because the Go side wraps every
    call with DetectAnomaliesWithFallback (PROPOSAL §5.3) and
    treats a non-empty ``anomalies`` array as authoritative. A
    spurious anomaly is worse than a missed one in this module.
    """
    if not isinstance(baseline_series, list) or not baseline_series:
        return None
    if not isinstance(grant_usage, (int, float)) or isinstance(grant_usage, bool):
        return None
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or threshold <= 0:
        threshold = 2.5
    samples: List[float] = []
    for v in _iter_numeric(baseline_series):
        samples.append(float(v))
    if len(samples) < 3:
        return None
    mu = mean(samples)
    sigma = pstdev(samples)
    if sigma <= 0:
        return None
    z = (float(grant_usage) - mu) / sigma
    if z < threshold:
        return None
    severity = "high" if z >= threshold + 1 else "medium"
    return {
        "kind": "baseline_spike",
        "severity": severity,
        "confidence": min(0.99, 0.5 + (z - threshold) / 4.0),
        "reason": (
            f"Grant usage ({grant_usage:.1f}/day) is {z:.1f}\u03c3 above"
            f" the workspace mean ({mu:.1f}/day, n={len(samples)})."
        ),
    }


def _iter_numeric(raw: Iterable[Any]) -> Iterable[float]:
    for v in raw:
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            yield float(v)
