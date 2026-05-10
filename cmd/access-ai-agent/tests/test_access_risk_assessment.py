"""Tests for skills.access_risk_assessment.

Covers the happy path (low/medium/high routing) and the error path
(missing required fields surfaces SkillError → 400 from the
dispatcher).
"""
from __future__ import annotations

import pytest

from skills import access_risk_assessment as skill


def test_run_low_risk_for_simple_viewer_role() -> None:
    result = skill.run({
        "role": "viewer",
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "low"
    assert isinstance(result["risk_factors"], list)


def test_run_high_risk_for_privileged_role() -> None:
    result = skill.run({
        "role": "admin",
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "high"
    assert any(f.startswith("privileged_role") for f in result["risk_factors"])


def test_run_medium_risk_for_write_role() -> None:
    result = skill.run({
        "role": "warehouse_writer",
        "resource_external_id": "snowflake-prod",
    })
    assert result["risk_score"] in {"medium", "high"}


def test_run_bumps_for_production_resource() -> None:
    base = skill.run({
        "role": "viewer",
        "resource_external_id": "host-001",
        "resource_tags": ["prod"],
    })
    assert base["risk_score"] in {"medium", "high"}
    assert "production_resource" in base["risk_factors"]


def test_run_flags_weak_justification() -> None:
    result = skill.run({
        "role": "viewer",
        "resource_external_id": "host-001",
        "justification": "pls",
    })
    assert "weak_justification" in result["risk_factors"]


def test_run_raises_on_missing_role() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({"resource_external_id": "host-001"})


def test_run_raises_on_non_dict_payload() -> None:
    with pytest.raises(skill.SkillError):
        skill.run("nope")  # type: ignore[arg-type]


# Phase 5 — LLM scoring tests. The deterministic stub is exercised
# by the tests above; these cover the LLM wire-in.
import os
import pytest

from skills import llm


@pytest.fixture
def llm_provider(monkeypatch):
    monkeypatch.setenv("ACCESS_AI_LLM_PROVIDER", "fake_risk")
    yield
    llm.set_test_provider("fake_risk", None)


def test_llm_overrides_deterministic_score(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return '{"risk_score": "high", "risk_factors": ["llm_inferred"], "reason": "test"}'
    llm.set_test_provider("fake_risk", fake)
    result = skill.run({
        "role": "viewer",  # deterministic would be low
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "high"
    assert "llm_inferred" in result["risk_factors"]
    assert result["reason"] == "test"


def test_llm_failure_falls_back_to_deterministic(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        raise RuntimeError("model timed out")
    llm.set_test_provider("fake_risk", fake)
    result = skill.run({
        "role": "admin",
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "high"
    assert any(f.startswith("privileged_role") for f in result["risk_factors"])


def test_llm_invalid_json_falls_back(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return "this is not json"
    llm.set_test_provider("fake_risk", fake)
    result = skill.run({
        "role": "viewer",
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "low"


def test_llm_invalid_score_falls_back(llm_provider) -> None:
    def fake(_prompt, _kwargs):
        return '{"risk_score": "extreme", "risk_factors": [], "reason": ""}'
    llm.set_test_provider("fake_risk", fake)
    result = skill.run({
        "role": "viewer",
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "low"


def test_no_provider_uses_deterministic(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_AI_LLM_PROVIDER", raising=False)
    result = skill.run({
        "role": "viewer",
        "resource_external_id": "host-001",
    })
    assert result["risk_score"] == "low"
    assert "stub scorer" in result["reason"]
