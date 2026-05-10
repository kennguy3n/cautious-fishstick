"""Tests for skills.llm shared LLM client.

The Phase 5 wire-in introduces a single dispatcher in skills.llm
that every Tier-1 skill calls into. These tests validate the
provider plumbing in isolation so the per-skill tests can focus on
their own logic.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterator

import pytest

from skills import llm


@pytest.fixture
def restore_env() -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in ("ACCESS_AI_LLM_PROVIDER",)}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_call_llm_unavailable_when_no_provider(restore_env: None) -> None:
    os.environ.pop("ACCESS_AI_LLM_PROVIDER", None)
    with pytest.raises(llm.LLMUnavailable):
        llm.call_llm("hello")


def test_call_llm_unavailable_when_provider_is_stub(restore_env: None) -> None:
    os.environ["ACCESS_AI_LLM_PROVIDER"] = "stub"
    with pytest.raises(llm.LLMUnavailable):
        llm.call_llm("hello")


def test_call_llm_uses_test_provider(restore_env: None) -> None:
    os.environ["ACCESS_AI_LLM_PROVIDER"] = "fake"
    captured: Dict[str, Any] = {}

    def fake(prompt: str, kwargs: Dict[str, Any]) -> str:
        captured["prompt"] = prompt
        captured["kwargs"] = kwargs
        return '{"hello": "world"}'

    llm.set_test_provider("fake", fake)
    try:
        result = llm.call_llm("hello", system="sys", max_tokens=42)
    finally:
        llm.set_test_provider("fake", None)
    assert result.text == '{"hello": "world"}'
    assert captured["prompt"] == "hello"
    assert captured["kwargs"]["system"] == "sys"
    assert captured["kwargs"]["max_tokens"] == 42


def test_call_llm_provider_failure_raises_unavailable(restore_env: None) -> None:
    os.environ["ACCESS_AI_LLM_PROVIDER"] = "fake_fail"

    def fake(_prompt: str, _kwargs: Dict[str, Any]) -> str:
        raise RuntimeError("simulated failure")

    llm.set_test_provider("fake_fail", fake)
    try:
        with pytest.raises(llm.LLMUnavailable):
            llm.call_llm("hi")
    finally:
        llm.set_test_provider("fake_fail", None)


def test_call_llm_provider_empty_string_raises(restore_env: None) -> None:
    os.environ["ACCESS_AI_LLM_PROVIDER"] = "fake_empty"

    def fake(_prompt: str, _kwargs: Dict[str, Any]) -> str:
        return "   "

    llm.set_test_provider("fake_empty", fake)
    try:
        with pytest.raises(llm.LLMUnavailable):
            llm.call_llm("hi")
    finally:
        llm.set_test_provider("fake_empty", None)


def test_parse_json_response_bare() -> None:
    out = llm.parse_json_response('{"a": 1, "b": [2, 3]}')
    assert out == {"a": 1, "b": [2, 3]}


def test_parse_json_response_fenced() -> None:
    out = llm.parse_json_response("```json\n{\"a\": 1}\n```")
    assert out == {"a": 1}


def test_parse_json_response_invalid_raises() -> None:
    with pytest.raises(llm.LLMUnavailable):
        llm.parse_json_response("not json at all")


def test_parse_json_response_non_object_raises() -> None:
    with pytest.raises(llm.LLMUnavailable):
        llm.parse_json_response("[1, 2, 3]")
