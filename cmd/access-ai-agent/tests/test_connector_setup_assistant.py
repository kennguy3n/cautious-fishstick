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


# Phase 5 — LLM-backed natural-language assistant.
import pytest

from skills import llm as llm_mod


@pytest.fixture
def llm_provider(monkeypatch):
    monkeypatch.setenv("ACCESS_AI_LLM_PROVIDER", "fake_setup")
    yield
    llm_mod.set_test_provider("fake_setup", None)


def test_llm_provides_structured_response(llm_provider) -> None:
    from skills import connector_setup_assistant as skill
    def fake(_prompt, _kwargs):
        return (
            '{"explanation": "Use SAML for Okta", "next_steps": ['
            '"Enable SAML in admin console", "Copy the ACS URL"], '
            '"wizard_field_hints": {"sso_protocol": "saml2"}}'
        )
    llm_mod.set_test_provider("fake_setup", fake)
    result = skill.run({
        "connector_kind": "okta",
        "user_question": "How do I configure SSO?",
        "wizard_state": {"sso_protocol": ""},
    })
    assert result["explanation"] == "Use SAML for Okta"
    assert "Enable SAML in admin console" in result["next_steps"]
    assert result.get("wizard_field_hints", {}).get("sso_protocol") == "saml2"


def test_llm_strips_secret_fields_from_state(llm_provider) -> None:
    from skills import connector_setup_assistant as skill
    captured = {}

    def fake(prompt, _kwargs):
        captured["prompt"] = prompt
        return '{"explanation": "ok", "next_steps": ["step a"]}'

    llm_mod.set_test_provider("fake_setup", fake)
    skill.run({
        "connector_kind": "okta",
        "user_question": "Help",
        "wizard_state": {"github_token": "ghp_secret123", "github_org": "acme"},
    })
    # Token field stripped before sending to the model.
    assert "ghp_secret123" not in captured["prompt"]
    assert "github_token" not in captured["prompt"]
    assert "acme" in captured["prompt"]


def test_llm_failure_uses_deterministic_checklist(llm_provider) -> None:
    from skills import connector_setup_assistant as skill
    def fake(_prompt, _kwargs):
        raise RuntimeError("nope")
    llm_mod.set_test_provider("fake_setup", fake)
    result = skill.run({"connector_kind": "okta"})
    assert any("SCIM API token" in step for step in result["next_steps"])


def test_llm_empty_steps_falls_back(llm_provider) -> None:
    from skills import connector_setup_assistant as skill
    def fake(_prompt, _kwargs):
        return '{"explanation": "x", "next_steps": []}'
    llm_mod.set_test_provider("fake_setup", fake)
    result = skill.run({"connector_kind": "okta"})
    assert any("SCIM API token" in step for step in result["next_steps"])
