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
