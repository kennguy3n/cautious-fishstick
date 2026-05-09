"""Tests for skills.connector_setup_assistant."""
from __future__ import annotations

import pytest

from skills import connector_setup_assistant as skill


def test_run_returns_curated_steps_for_known_kind() -> None:
    result = skill.run({"connector_kind": "okta"})
    assert isinstance(result["next_steps"], list) and result["next_steps"]
    assert "scim_base_url" in " ".join(result["next_steps"])


def test_run_returns_generic_fallback_for_unknown_kind() -> None:
    result = skill.run({"connector_kind": "neverheardofit"})
    assert isinstance(result["next_steps"], list) and result["next_steps"]
    # The fallback explicitly mentions the SCIM v2.0 generic route.
    assert "SCIM v2.0" in result["next_steps"][0] or "SCIM" in " ".join(result["next_steps"])


def test_run_raises_on_missing_kind() -> None:
    with pytest.raises(skill.SkillError):
        skill.run({})
