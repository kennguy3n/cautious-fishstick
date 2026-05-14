"""End-to-end tests for the A2A dispatcher.

The tests exercise main.dispatch directly (no socket round-trip) and
also boot the HTTP server in-process to verify the routing surface.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
import urllib.error
from http import HTTPStatus
from http.server import HTTPServer
from typing import Iterator

import pytest

import main


def test_dispatch_routes_known_skill() -> None:
    status, body = main.dispatch("access_risk_assessment", {
        "role": "viewer",
        "resource_external_id": "host-001",
    })
    assert status == HTTPStatus.OK
    assert body["risk_score"] in {"low", "medium", "high"}


def test_dispatch_unknown_skill_returns_404() -> None:
    status, body = main.dispatch("not_a_skill", {})
    assert status == HTTPStatus.NOT_FOUND
    assert "unknown skill" in body["error"]


def test_dispatch_skill_error_returns_400() -> None:
    status, body = main.dispatch("access_risk_assessment", {})
    assert status == HTTPStatus.BAD_REQUEST
    assert "role" in body["error"]


@pytest.fixture
def running_server() -> Iterator[tuple[str, int]]:
    """Boot the HTTP server on an ephemeral port for the duration of one test."""
    handler_cls = main.build_handler(api_key="")
    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    host, port = httpd.server_address[0], httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    # Tiny settle so the listener is ready when the first urllib
    # request fires. http.server is synchronous so the sleep is
    # informally bounded by the OS scheduler.
    time.sleep(0.05)
    try:
        yield (host, port)
    finally:
        httpd.shutdown()
        httpd.server_close()


def _post(host: str, port: int, body: dict, *, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        url=f"http://{host}:{port}/a2a/invoke",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_http_invoke_known_skill(running_server: tuple[str, int]) -> None:
    host, port = running_server
    status, body = _post(host, port, {
        "skill_name": "policy_recommendation",
        "payload": {"teams": [{"name": "platform-eng", "kind": "engineering"}]},
    })
    assert status == HTTPStatus.OK
    assert isinstance(body["recommendations"], list)


def test_http_healthz(running_server: tuple[str, int]) -> None:
    host, port = running_server
    with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=2) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    assert body["status"] == "ok"


def test_http_unknown_path(running_server: tuple[str, int]) -> None:
    host, port = running_server
    try:
        urllib.request.urlopen(f"http://{host}:{port}/nope", timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == HTTPStatus.NOT_FOUND
        return
    pytest.fail("expected HTTPError 404")


def test_http_missing_skill_name(running_server: tuple[str, int]) -> None:
    host, port = running_server
    status, body = _post(host, port, {"payload": {}})
    assert status == HTTPStatus.BAD_REQUEST
    assert "skill_name" in body["error"]


def test_http_invalid_json(running_server: tuple[str, int]) -> None:
    host, port = running_server
    req = urllib.request.Request(
        url=f"http://{host}:{port}/a2a/invoke",
        data=b"not-json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == HTTPStatus.BAD_REQUEST
        return
    pytest.fail("expected HTTPError 400")


@pytest.fixture
def running_server_with_api_key() -> Iterator[tuple[str, int, str]]:
    """Boot a server that requires an X-API-Key header on /a2a/invoke."""
    api_key = "s3cret-test-key"
    handler_cls = main.build_handler(api_key=api_key)
    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    host, port = httpd.server_address[0], httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    try:
        yield (host, port, api_key)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_http_api_key_required_when_configured(
    running_server_with_api_key: tuple[str, int, str]
) -> None:
    host, port, _ = running_server_with_api_key
    status, body = _post(host, port, {
        "skill_name": "access_risk_assessment",
        "payload": {"role": "viewer", "resource_external_id": "host-001"},
    })
    assert status == HTTPStatus.UNAUTHORIZED
    assert "X-API-Key" in body["error"]


def test_http_api_key_wrong_value_rejected(
    running_server_with_api_key: tuple[str, int, str]
) -> None:
    host, port, _ = running_server_with_api_key
    status, body = _post(
        host,
        port,
        {
            "skill_name": "access_risk_assessment",
            "payload": {"role": "viewer", "resource_external_id": "host-001"},
        },
        headers={"X-API-Key": "obviously-wrong"},
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert "X-API-Key" in body["error"]


def test_http_api_key_correct_value_passes(
    running_server_with_api_key: tuple[str, int, str]
) -> None:
    host, port, key = running_server_with_api_key
    status, body = _post(
        host,
        port,
        {
            "skill_name": "access_risk_assessment",
            "payload": {"role": "viewer", "resource_external_id": "host-001"},
        },
        headers={"X-API-Key": key},
    )
    assert status == HTTPStatus.OK
    assert body["risk_score"] in {"low", "medium", "high"}


def test_resolve_listen_addr_prefers_canonical_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # ACCESS_AI_AGENT_LISTEN_ADDR is the canonical knob the
    # docker-compose stack and Helm chart set; it must win over the
    # legacy AGENT_HOST / AGENT_PORT fallbacks so the agent listens
    # where the compose healthcheck and ztna-api both expect.
    monkeypatch.setenv("ACCESS_AI_AGENT_LISTEN_ADDR", "0.0.0.0:8090")
    monkeypatch.setenv("AGENT_HOST", "ignored")
    monkeypatch.setenv("AGENT_PORT", "1234")
    host, port = main._resolve_listen_addr()
    assert (host, port) == ("0.0.0.0", 8090)


def test_resolve_listen_addr_falls_back_to_legacy_envs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Standalone dev runs (no LISTEN_ADDR set) must keep working at
    # the AGENT_HOST / AGENT_PORT defaults documented in
    # cmd/access-ai-agent/README.md so existing developer scripts
    # don't break.
    monkeypatch.delenv("ACCESS_AI_AGENT_LISTEN_ADDR", raising=False)
    monkeypatch.setenv("AGENT_HOST", "127.0.0.1")
    monkeypatch.setenv("AGENT_PORT", "8765")
    host, port = main._resolve_listen_addr()
    assert (host, port) == ("127.0.0.1", 8765)


def test_resolve_listen_addr_rejects_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A malformed env var fails fast at startup rather than silently
    # falling back — a misconfigured Helm chart should crash-loop
    # rather than serve traffic on an unexpected port.
    monkeypatch.setenv("ACCESS_AI_AGENT_LISTEN_ADDR", "not-a-port")
    with pytest.raises(ValueError):
        main._resolve_listen_addr()


def test_resolve_listen_addr_rejects_non_integer_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCESS_AI_AGENT_LISTEN_ADDR", "0.0.0.0:not-a-number")
    with pytest.raises(ValueError):
        main._resolve_listen_addr()
