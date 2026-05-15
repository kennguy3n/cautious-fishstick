"""Shared LLM client for Tier-1 skills.

Phase 5 swaps the Phase 4 deterministic stubs to LLM-backed
implementations. Every skill calls into this module for two
reasons:

1. The skill is testable WITHOUT a real LLM provider: tests inject
   a stub via ``set_test_provider(...)`` and assert on the
   structured payload the skill returns.

2. Provider selection is driven by the ``ACCESS_AI_LLM_PROVIDER``
   env var (default: ``stub``). When the provider is unset,
   misconfigured, or the network call fails, ``call_llm()`` raises
   :class:`LLMUnavailable`, which the skill catches to fall back to
   its Phase 4 deterministic logic per docs/architecture.md best-effort
   pattern.

The client speaks the OpenAI-compatible ``/v1/chat/completions``
schema — base_url and api_key come from ``ACCESS_AI_LLM_BASE_URL`` /
``ACCESS_AI_LLM_API_KEY``. Provider-specific request shaping (e.g.
Anthropic's ``messages`` API) belongs in a future provider plugin
and is out of scope for the Phase 5 wire-in.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from urllib import error as urlerror
from urllib import request as urlrequest


logger = logging.getLogger(__name__)


# Provider registry — name → callable(prompt, **kwargs) → str.
# Tests register a stub here via ``set_test_provider`` and skill
# code calls ``call_llm`` to dispatch through it.
_TEST_PROVIDERS: Dict[str, Callable[[str, Dict[str, Any]], str]] = {}


class LLMUnavailable(RuntimeError):
    """Raised when no LLM provider is configured or the call failed.

    Skill code MUST treat this as a signal to fall back to its
    Phase 4 deterministic implementation. The Go side will see a
    successful skill response containing the deterministic output
    rather than a 5xx — that is the behaviour docs/architecture.md
    "graceful degradation" promises.
    """


@dataclass
class LLMResult:
    """Structured response from a successful LLM invocation."""

    text: str
    raw: Optional[Dict[str, Any]] = None


def set_test_provider(name: str, fn: Optional[Callable[[str, Dict[str, Any]], str]]) -> None:
    """Install or remove a test provider for ``name``.

    Tests use this to inject a callable that returns canned text
    without hitting the network. Passing ``fn=None`` deregisters
    the provider, which is what the conftest cleanup hook calls.
    """
    if fn is None:
        _TEST_PROVIDERS.pop(name, None)
    else:
        _TEST_PROVIDERS[name] = fn


def _provider_name() -> str:
    return (os.environ.get("ACCESS_AI_LLM_PROVIDER") or "stub").strip().lower()


def call_llm(prompt: str, *, system: Optional[str] = None, max_tokens: int = 512, timeout: float = 10.0) -> LLMResult:
    """Invoke the configured LLM provider with ``prompt``.

    Raises :class:`LLMUnavailable` when no provider is registered,
    the configured provider is the no-op ``stub``, the network call
    failed, or the response could not be parsed.

    Caller responsibilities:
        * Sanitise the prompt — never include raw secrets, tokens,
          or PII. The skill helpers in this module take care of
          this for known fields, but the contract is enforced by
          callers, not us.
        * Validate the returned text matches the skill's expected
          schema before persisting.
    """
    provider = _provider_name()
    fn = _TEST_PROVIDERS.get(provider)
    if fn is not None:
        try:
            text = fn(prompt, {"system": system, "max_tokens": max_tokens, "timeout": timeout})
        except Exception as exc:  # noqa: BLE001 — provider raises must surface as LLMUnavailable
            raise LLMUnavailable(f"test provider {provider!r} raised: {exc}") from exc
        if not isinstance(text, str) or not text.strip():
            raise LLMUnavailable(f"test provider {provider!r} returned empty response")
        return LLMResult(text=text)

    if provider in ("", "stub"):
        raise LLMUnavailable("no LLM provider configured (ACCESS_AI_LLM_PROVIDER unset or 'stub')")

    base_url = os.environ.get("ACCESS_AI_LLM_BASE_URL")
    api_key = os.environ.get("ACCESS_AI_LLM_API_KEY")
    if not base_url or not api_key:
        raise LLMUnavailable("ACCESS_AI_LLM_BASE_URL / ACCESS_AI_LLM_API_KEY not set")
    model = os.environ.get("ACCESS_AI_LLM_MODEL") or "gpt-4o-mini"

    body: Dict[str, Any] = {
        "model": model,
        "messages": (
            [{"role": "system", "content": system}] if system else []
        ) + [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.0,
    }
    req = urlrequest.Request(
        url=base_url.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urlerror.URLError, json.JSONDecodeError, OSError) as exc:
        # Redact only the host from the URL so logs do not leak
        # the api key (it isn't in the URL but defence-in-depth)
        # nor the prompt (which may include resource IDs).
        logger.warning("llm call failed: %s", exc.__class__.__name__)
        raise LLMUnavailable("llm http call failed") from exc

    try:
        text = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMUnavailable("llm response missing choices[0].message.content") from exc
    if not isinstance(text, str) or not text.strip():
        raise LLMUnavailable("llm response content is empty")
    return LLMResult(text=text, raw=payload)


def parse_json_response(text: str) -> Dict[str, Any]:
    """Parse an LLM response as JSON, raising LLMUnavailable on failure.

    Handles both bare-JSON responses and the common case where the
    model wraps its JSON in a ```json ... ``` markdown fence.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Strip leading fence + optional language tag.
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
    try:
        out = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"llm response is not valid JSON: {exc.msg}") from exc
    if not isinstance(out, dict):
        raise LLMUnavailable("llm response is not a JSON object")
    return out
