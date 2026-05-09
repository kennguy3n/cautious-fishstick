"""Shared pytest fixtures for the access-ai-agent test suite.

The conftest inserts the agent's source directory onto sys.path so
the tests can import skills and main without packaging the project.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
