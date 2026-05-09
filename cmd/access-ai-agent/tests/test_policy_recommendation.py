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
