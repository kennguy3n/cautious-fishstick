"""Tests for skills.access_review_automation."""
from __future__ import annotations

import pytest

from skills import access_review_automation as skill
from skills.access_risk_assessment import PRIVILEGED_ROLES


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


# Regression for the privileged-role guard bug: every privileged role
# in PRIVILEGED_ROLES must escalate even when the grant is also stale,
# i.e. the stale-revoke branch must never overshadow the escalation
# branch for root / superuser / domain_admin (the previous version of
# the skill silently routed those to "revoke").
@pytest.mark.parametrize("role", sorted(PRIVILEGED_ROLES))
def test_run_escalates_stale_privileged_role(role: str) -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": role,
        "usage_data": {"days_since_last_use": 365},
    })
    assert result["decision"] == "escalate", (
        f"role {role!r} with stale usage must escalate, not revoke"
    )


# Mixed-case role names must still match PRIVILEGED_ROLES — the skill
# lower-cases the input before comparing.
def test_run_escalates_mixed_case_privileged_role() -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": "Domain_Admin",
        "usage_data": {"days_since_last_use": 200},
    })
    assert result["decision"] == "escalate"


def test_run_certifies_default() -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": "viewer",
        "usage_data": {"days_since_last_use": 5},
    })
    assert result["decision"] == "certify"


# bool is a subclass of int in Python; the skill must explicitly
# reject bool values for days_since_last_use so a payload like
# {"days_since_last_use": True} does not trip the stale-revoke branch.
def test_run_rejects_bool_days_since_last_use() -> None:
    result = skill.run({
        "grant_id": "g1",
        "role": "viewer",
        "usage_data": {"days_since_last_use": True},
    })
    assert result["decision"] == "certify"


def test_run_raises_on_missing_grant_id() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({"role": "viewer"})
