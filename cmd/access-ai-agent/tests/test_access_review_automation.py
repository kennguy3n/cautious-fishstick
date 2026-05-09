"""Tests for skills.access_review_automation."""
from __future__ import annotations

import pytest

from skills import access_review_automation as skill


def test_run_revokes_stale_grant_on_non_privileged_role() -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": "viewer",
        "usage_data": {"days_since_last_use": 180},
    })
    assert result["decision"] == "revoke"


def test_run_escalates_privileged_role() -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": "admin",
        "usage_data": {"days_since_last_use": 1},
    })
    assert result["decision"] == "escalate"


def test_run_certifies_default() -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": "viewer",
        "usage_data": {"days_since_last_use": 5},
    })
    assert result["decision"] == "certify"


def test_run_raises_on_missing_grant_id() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({"role": "viewer"})
