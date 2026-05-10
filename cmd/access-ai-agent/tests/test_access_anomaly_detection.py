"""Tests for skills.access_anomaly_detection."""
from __future__ import annotations

import pytest

from skills import access_anomaly_detection as skill


def test_run_flags_stale_grant() -> None:
    result = skill.run({
        "grant_id": "g1",
        "usage_data": {"days_since_last_use": 120},
    })
    kinds = {a["kind"] for a in result["anomalies"]}
    assert "stale_grant" in kinds


def test_run_flags_geo_unusual_when_flag_set() -> None:
    result = skill.run({
        "grant_id": "g1",
        "usage_data": {"unusual_geo": True},
    })
    kinds = {a["kind"] for a in result["anomalies"]}
    assert "geo_unusual" in kinds


def test_run_flags_frequency_spike() -> None:
    result = skill.run({
        "grant_id": "g1",
        "usage_data": {"frequency_ratio": 10.0},
    })
    kinds = {a["kind"] for a in result["anomalies"]}
    assert "frequency_spike" in kinds


def test_run_returns_empty_when_clean() -> None:
    result = skill.run({"grant_id": "g1", "usage_data": {"days_since_last_use": 1}})
    assert result["anomalies"] == []


def test_run_raises_on_missing_grant_id() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({"usage_data": {}})


def test_run_raises_on_non_dict_usage() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({"grant_id": "g1", "usage_data": "nope"})


# Phase 5 — cross-grant baseline + new anomaly types.
def test_baseline_spike_flagged() -> None:
    from skills import access_anomaly_detection as skill
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "baseline_usage_per_day": [1, 2, 1, 2, 3, 2, 1, 2, 1, 2],
        "usage_data": {"usage_per_day": 50},
    })
    assert any(a["kind"] == "baseline_spike" for a in result["anomalies"])


def test_baseline_within_threshold_not_flagged() -> None:
    from skills import access_anomaly_detection as skill
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "baseline_usage_per_day": [10, 11, 9, 10, 12, 11, 10],
        "usage_data": {"usage_per_day": 12},
    })
    assert not any(a["kind"] == "baseline_spike" for a in result["anomalies"])


def test_baseline_with_too_few_samples_skipped() -> None:
    from skills import access_anomaly_detection as skill
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "baseline_usage_per_day": [1, 2],
        "usage_data": {"usage_per_day": 1000},
    })
    assert not any(a["kind"] == "baseline_spike" for a in result["anomalies"])


def test_off_hours_access_flagged() -> None:
    from skills import access_anomaly_detection as skill
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "usage_data": {"off_hours_pct": 0.85},
    })
    assert any(a["kind"] == "off_hours_access" for a in result["anomalies"])


def test_geographic_outlier_flagged() -> None:
    from skills import access_anomaly_detection as skill
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "usage_data": {"distinct_countries_24h": 5},
    })
    assert any(a["kind"] == "geographic_outlier" for a in result["anomalies"])


def test_unused_high_privilege_flagged() -> None:
    from skills import access_anomaly_detection as skill
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "is_privileged": True,
        "usage_data": {"days_since_last_use": 90},
    })
    kinds = [a["kind"] for a in result["anomalies"]]
    assert "stale_grant" in kinds
    assert "unused_high_privilege" in kinds


def test_baseline_with_malformed_input_skipped() -> None:
    from skills import access_anomaly_detection as skill
    # baseline contains booleans (rejected), strings (rejected),
    # leaving fewer than 3 valid samples; should not flag.
    result = skill.run({
        "grant_id": "01H00000000000000000000001",
        "baseline_usage_per_day": [True, "x", None, 1.5],
        "usage_data": {"usage_per_day": 1000},
    })
    assert not any(a["kind"] == "baseline_spike" for a in result["anomalies"])
