"""access-ai-agent — A2A skill server for the access platform.

Per docs/PROPOSAL.md §7.1 and docs/ARCHITECTURE.md §8 the access
platform pushes decision-support requests to a co-located Python
agent over plain JSON. The Go side (``internal/pkg/aiclient``)
hosts the canonical client; this module is the server-side
counterpart.

The HTTP surface is intentionally tiny:

    POST /a2a/invoke
        body: {"skill_name": "<name>", "payload": {...}}
        -> 200 {<skill response>}
        -> 400 {"error": "<reason>"} on malformed payload
        -> 404 {"error": "unknown skill: <name>"}
        -> 500 {"error": "<traceback summary>"} on unhandled exception

    GET /healthz
        -> 200 {"status": "ok"}

The server is built on the standard library's ``http.server`` so the
Phase 4 deployment has zero third-party dependencies — Phase 5 swaps
in FastAPI / starlette behind the same routes if higher concurrency
is needed.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, Tuple

from skills import (
    access_anomaly_detection,
    access_review_automation,
    access_risk_assessment,
    connector_setup_assistant,
    policy_recommendation,
)

# SkillError is the base type the dispatcher catches and returns as
# 400. Each skill module re-exports its own SkillError class; they
# all subclass ValueError so the dispatcher can use a single check.
SkillFn = Callable[[Dict[str, Any]], Dict[str, Any]]

SKILLS: Dict[str, SkillFn] = {
    "access_risk_assessment": access_risk_assessment.run,
    "access_review_automation": access_review_automation.run,
    "access_anomaly_detection": access_anomaly_detection.run,
    "connector_setup_assistant": connector_setup_assistant.run,
    "policy_recommendation": policy_recommendation.run,
}


def dispatch(skill_name: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Run the named skill against payload and return (status, body)."""
    skill = SKILLS.get(skill_name)
    if skill is None:
        return HTTPStatus.NOT_FOUND, {"error": f"unknown skill: {skill_name!r}"}
    try:
        return HTTPStatus.OK, skill(payload)
    except ValueError as e:
        # SkillError subclasses ValueError. Treat any ValueError from
        # a skill as a 400 — the payload was malformed.
        return HTTPStatus.BAD_REQUEST, {"error": str(e)}
    except Exception as e:  # pragma: no cover - defensive catch-all
        logging.exception("skill %s raised", skill_name)
        return HTTPStatus.INTERNAL_SERVER_ERROR, {
            "error": f"unhandled exception in skill {skill_name!r}: {e}",
            "trace": traceback.format_exc(limit=4),
        }


class AgentHandler(BaseHTTPRequestHandler):
    """Tiny http.server handler routing /a2a/invoke and /healthz."""

    server_version = "access-ai-agent/0.1"

    # API key check: when AGENT_API_KEY is set in the environment,
    # every /a2a/invoke request must echo it via X-API-Key. Empty
    # AGENT_API_KEY (the dev default) skips the check.
    expected_api_key: str = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ANN401
        # Route http.server logs through the standard logging module
        # so deployments that pipe stdout to a JSON aggregator see
        # consistent format with the rest of the agent.
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _write_json(self, status: int, body: Dict[str, Any]) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - http.server convention
        if self.path == "/healthz":
            self._write_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"error": f"unknown path: {self.path}"})

    def do_POST(self) -> None:  # noqa: N802 - http.server convention
        if self.path != "/a2a/invoke":
            self._write_json(HTTPStatus.NOT_FOUND, {"error": f"unknown path: {self.path}"})
            return

        if self.expected_api_key:
            got = self.headers.get("X-API-Key", "")
            if got != self.expected_api_key:
                self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "X-API-Key mismatch"})
                return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is not an integer"})
            return
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError as e:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON body: {e}"})
            return
        if not isinstance(body, dict):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "request body must be a JSON object"})
            return

        skill_name = body.get("skill_name")
        payload = body.get("payload") or {}
        if not isinstance(skill_name, str) or not skill_name:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "skill_name is required"})
            return
        if not isinstance(payload, dict):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "payload must be an object"})
            return

        status, response = dispatch(skill_name, payload)
        self._write_json(status, response)


def build_handler(api_key: str) -> type:
    """Bind the API-key expectation onto a fresh handler subclass."""
    cls = type("BoundAgentHandler", (AgentHandler,), {"expected_api_key": api_key})
    return cls


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="access-ai-agent A2A skill server")
    p.add_argument("--host", default=os.environ.get("AGENT_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("AGENT_PORT", "8765")))
    p.add_argument("--log-level", default=os.environ.get("AGENT_LOG_LEVEL", "INFO"))
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    api_key = os.environ.get("AGENT_API_KEY", "")
    handler_cls = build_handler(api_key)
    server = HTTPServer((args.host, args.port), handler_cls)
    logging.info("access-ai-agent listening on %s:%d (skills=%s)", args.host, args.port, sorted(SKILLS.keys()))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("shutdown requested")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
