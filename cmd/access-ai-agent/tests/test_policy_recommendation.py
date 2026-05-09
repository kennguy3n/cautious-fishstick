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
