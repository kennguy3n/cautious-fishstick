"""Tests for skills.pam_session_risk.

Covers the deterministic stub paths (low / medium / high routing,
emergency, denials, unusual time, first-time access), the input
validation (missing keys, wrong types), and the Phase 5 LLM wire-in
(override + fallback).
"""
from __future__ import annotations

import pytest

from skills import llm
from skills import pam_session_risk as skill


def _payload(**overrides):
    base = {
        "user_id": "user-1",
        "asset_id": "asset-1",
        "protocol": "ssh",
        "criticality": "low",
    }
    base.update(overrides)
    return base


def test_run_low_risk_for_low_criticality_business_hours() -> None:
    result = skill.run(_payload(time_of_day=12))
    assert result["risk_score"] == "low"
    assert result["recommendation"] == "auto_approve"
    assert result["risk_factors"] == []


def test_run_high_risk_for_high_criticality_asset() -> None:
    result = skill.run(_payload(criticality="high", time_of_day=12))
    assert result["risk_score"] == "high"
    assert result["recommendation"] == "require_approval"
    assert any(f.startswith("high_criticality_asset") for f in result["risk_factors"])


def test_run_medium_criticality_bumps_score() -> None:
    result = skill.run(_payload(criticality="medium", time_of_day=12))
    assert result["risk_score"] == "medium"
    assert "medium_criticality_asset" in result["risk_factors"]
    assert result["recommendation"] == "require_approval"


def test_run_flags_unusual_time_in_early_morning() -> None:
    result = skill.run(_payload(time_of_day=3))
    assert "unusual_time:03" in result["risk_factors"]
    assert result["risk_score"] == "medium"
    # low + 1 bump => medium, no high-signal factor => require_approval
    assert result["recommendation"] == "require_approval"


def test_run_flags_unusual_time_above_working_hours() -> None:
    result = skill.run(_payload(time_of_day=23))
    assert "unusual_time:23" in result["risk_factors"]


def test_run_respects_custom_working_hours() -> None:
    # custom window 09:00-17:00 puts 18 into unusual territory
    result = skill.run(_payload(
        time_of_day=18, working_hours_start=9, working_hours_end=17,
    ))
    assert "unusual_time:18" in result["risk_factors"]


def test_run_flags_previous_denials_below_threshold() -> None:
    result = skill.run(_payload(previous_denials=1, time_of_day=12))
    assert any(f.startswith("previous_denials") for f in result["risk_factors"])
    assert result["risk_score"] == "medium"


def test_run_denies_on_repeated_previous_denials() -> None:
    result = skill.run(_payload(previous_denials=3, time_of_day=12))
    assert result["risk_score"] == "high"
    assert result["recommendation"] == "deny"


def test_run_flags_first_time_access() -> None:
    result = skill.run(_payload(is_first_access=True, time_of_day=12))
    assert "first_time_asset_access" in result["risk_factors"]
    assert result["risk_score"] == "medium"


def test_run_emergency_always_routes_to_approval() -> None:
    result = skill.run(_payload(is_emergency=True, time_of_day=12))
    assert "emergency_access" in result["risk_factors"]
    assert result["recommendation"] == "require_approval"


def test_run_emergency_with_denials_still_denies() -> None:
    # repeated denials override emergency — the policy already
    # rejected this combination 3+ times before.
    result = skill.run(_payload(
        is_emergency=True, previous_denials=3, time_of_day=12,
    ))
    assert result["recommendation"] == "deny"


def test_run_compound_factors_promote_to_high() -> None:
    result = skill.run(_payload(
        criticality="medium",
        time_of_day=2,
        is_first_access=True,
    ))
    assert result["risk_score"] == "high"
    # high score => require_approval (no denials)
    assert result["recommendation"] == "require_approval"


def test_run_rejects_non_dict_payload() -> None:
    with pytest.raises(skill.SkillError):
        skill.run("nope")  # type: ignore[arg-type]


@pytest.mark.parametrize("missing", ["user_id", "asset_id", "protocol", "criticality"])
def test_run_rejects_missing_required_field(missing: str) -> None:
    payload = _payload()
    payload.pop(missing)
    with pytest.raises(skill.SkillError):
        skill.run(payload)


@pytest.mark.parametrize("missing", ["user_id", "asset_id", "protocol", "criticality"])
def test_run_rejects_empty_required_field(missing: str) -> None:
    payload = _payload()
    payload[missing] = ""
    with pytest.raises(skill.SkillError):
        skill.run(payload)


def test_run_ignores_bool_time_of_day() -> None:
    # bool is a subclass of int — a payload of True must not be
    # treated as hour=1 (which would be flagged as unusual).
    result = skill.run(_payload(time_of_day=True))
    assert all(not f.startswith("unusual_time") for f in result["risk_factors"])


def test_run_ignores_bool_previous_denials() -> None:
    result = skill.run(_payload(previous_denials=True, time_of_day=12))
    assert all(not f.startswith("previous_denials") for f in result["risk_factors"])


def test_run_ignores_oob_working_hours() -> None:
    # nonsense values fall back to defaults; 12 should remain in-window
    result = skill.run(_payload(
        time_of_day=12, working_hours_start=-1, working_hours_end=99,
    ))
    assert all(not f.startswith("unusual_time") for f in result["risk_factors"])


@pytest.fixture
def llm_provider(monkeypatch):
    monkeypatch.setenv("ACCESS_AI_LLM_PROVIDER", "fake_pam_risk")
    yield
    llm.set_test_provider("fake_pam_risk", None)


def test_llm_overrides_deterministic_score(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return (
            '{"risk_score": "high", "risk_factors": ["llm_inferred"],'
            ' "recommendation": "deny", "reason": "test"}'
        )
    llm.set_test_provider("fake_pam_risk", fake)
    result = skill.run(_payload(time_of_day=12))
    assert result["risk_score"] == "high"
    assert result["recommendation"] == "deny"
    assert "llm_inferred" in result["risk_factors"]
    assert result["reason"] == "test"


def test_llm_invalid_json_falls_back(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return "this is not json"
    llm.set_test_provider("fake_pam_risk", fake)
    result = skill.run(_payload(time_of_day=12))
    assert result["risk_score"] == "low"
    assert result["recommendation"] == "auto_approve"


def test_llm_unknown_score_falls_back(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return (
            '{"risk_score": "extreme", "risk_factors": [],'
            ' "recommendation": "deny", "reason": ""}'
        )
    llm.set_test_provider("fake_pam_risk", fake)
    result = skill.run(_payload(time_of_day=12))
    assert result["risk_score"] == "low"


def test_llm_unknown_recommendation_falls_back(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return (
            '{"risk_score": "low", "risk_factors": [],'
            ' "recommendation": "delete", "reason": ""}'
        )
    llm.set_test_provider("fake_pam_risk", fake)
    result = skill.run(_payload(time_of_day=12))
    assert result["recommendation"] == "auto_approve"


def test_no_provider_uses_deterministic(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_AI_LLM_PROVIDER", raising=False)
    result = skill.run(_payload(criticality="high", time_of_day=12))
    assert result["risk_score"] == "high"
    assert "Phase 4 stub" in result["reason"]
