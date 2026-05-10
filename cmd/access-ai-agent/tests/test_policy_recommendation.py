"""Tests for skills.policy_recommendation."""
from __future__ import annotations

import pytest

from skills import policy_recommendation as skill


def test_run_returns_recommendations_for_engineering_team() -> None:
    result = skill.run({
        "teams": [
            {"name": "platform-eng", "kind": "engineering"},
        ],
    })
    assert isinstance(result["recommendations"], list)
    assert len(result["recommendations"]) >= 1
    first = result["recommendations"][0]
    assert first["subject_team"] == "platform-eng"
    assert "resource_kind" in first
    # The personalised name must be rewritten to start with the
    # actual team name, not the canned template prefix
    # ("Engineering -> ...").
    assert first["name"].startswith("platform-eng -> ")
    assert not first["name"].startswith("Engineering -> ")


# Regression test: the personalisation logic must work for templates
# whose prefix is an all-caps acronym like "SRE -> ...". The previous
# implementation used ``kind.title()`` which produced "Sre" and so the
# replace silently no-op'd, leaking the canned prefix into the output.
def test_run_personalises_acronym_prefix_templates() -> None:
    result = skill.run({
        "teams": [
            {"name": "core-sre", "kind": "sre"},
        ],
    })
    assert len(result["recommendations"]) == 1
    rec = result["recommendations"][0]
    assert rec["subject_team"] == "core-sre"
    assert rec["name"].startswith("core-sre -> "), (
        f"acronym-prefixed template was not personalised; got name={rec['name']!r}"
    )
    assert not rec["name"].startswith("SRE -> ")


# Regression test: a missing / non-string team name must not break
# personalisation — the template's canned name is returned verbatim.
def test_run_keeps_template_name_when_team_name_missing() -> None:
    result = skill.run({
        "teams": [
            {"kind": "data"},
        ],
    })
    assert len(result["recommendations"]) == 1
    rec = result["recommendations"][0]
    assert rec["name"] == "Data -> warehouse read"
    # subject_team falls back to the template's lowercase kind.
    assert rec["subject_team"] == "data"


def test_run_returns_empty_for_unknown_team_kind() -> None:
    result = skill.run({
        "teams": [
            {"name": "art-team", "kind": "art"},
        ],
    })
    assert result["recommendations"] == []


def test_run_raises_on_missing_teams() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({})


def test_run_raises_on_non_list_teams() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({"teams": "engineering"})


# Phase 5 — LLM-augmented recommendations.
import pytest

from skills import llm as llm_mod


@pytest.fixture
def llm_provider(monkeypatch):
    monkeypatch.setenv("ACCESS_AI_LLM_PROVIDER", "fake_policy")
    yield
    llm_mod.set_test_provider("fake_policy", None)


def test_llm_appends_recommendations(llm_provider) -> None:
    from skills import policy_recommendation as skill
    def fake(_prompt, _kwargs):
        return (
            '{"explanation": "merged", "recommendations": ['
            '{"name": "Engineering -> custom", "subject_team": "engineering",'
            ' "resource_kind": "github_repo", "action": "admin",'
            ' "auto_provision": false, "rationale": "custom rule"}]}'
        )
    llm_mod.set_test_provider("fake_policy", fake)
    result = skill.run({
        "teams": [{"name": "engineering", "kind": "engineering"}],
    })
    names = [r["name"] for r in result["recommendations"]]
    # Deterministic templates still present.
    assert any("github write" in n for n in names)
    # LLM-suggested rec appended.
    assert any("custom" in n for n in names)
    assert result["explanation"] == "merged"


def test_llm_failure_uses_deterministic(llm_provider) -> None:
    from skills import policy_recommendation as skill
    def fake(_prompt, _kwargs):
        raise RuntimeError("model down")
    llm_mod.set_test_provider("fake_policy", fake)
    result = skill.run({
        "teams": [{"name": "engineering", "kind": "engineering"}],
    })
    # Should be the deterministic templates only.
    assert len(result["recommendations"]) >= 1
    assert "Phase 4 stub" in result["explanation"] or "engineering" in result["explanation"].lower()


def test_llm_invalid_recommendations_falls_back(llm_provider) -> None:
    from skills import policy_recommendation as skill
    def fake(_prompt, _kwargs):
        return '{"explanation": "bad", "recommendations": "not a list"}'
    llm_mod.set_test_provider("fake_policy", fake)
    result = skill.run({
        "teams": [{"name": "engineering", "kind": "engineering"}],
    })
    # Falls back to deterministic.
    assert all(isinstance(r, dict) for r in result["recommendations"])
