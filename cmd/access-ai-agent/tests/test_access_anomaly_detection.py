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
