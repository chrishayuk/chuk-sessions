# test_e2e_sandbox_id.py
"""End-to-end tests that verify sandbox-ID propagation in chuk_sessions.

Run these tests with pytest:

    pytest -q test_e2e_sandbox_id.py

They exercise three scenarios:
1.  Explicit sandbox_id passed to SessionManager
2.  sandbox_id supplied via CHUK_SANDBOX_ID env var
3.  Automatically generated sandbox_id when nothing provided

Each test allocates a session then asserts that grid paths are
prefixed with the correct sandbox identifier.
"""

from __future__ import annotations

import os
import re
import asyncio
import uuid

import pytest

from chuk_sessions.session_manager import SessionManager


# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

aio_pytest_mark = pytest.mark.asyncio  # shortcut so we can decorate below


def _is_valid_uuid_segment(segment: str) -> bool:
    """Rough check that a string looks like the 8‑char uuid we expect."""
    return bool(re.fullmatch(r"[0-9a-f]{8}", segment))


async def _assert_prefix_matches(mgr: SessionManager, session_id: str, expected_sandbox: str):
    """Shared checks that canonical prefix and artifact key start with sandbox."""
    # canonical grid prefix
    canonical_prefix = mgr.get_canonical_prefix(session_id)
    assert canonical_prefix == f"grid/{expected_sandbox}/{session_id}/"

    # round‑trip a sample artifact key
    artifact_key = mgr.generate_artifact_key(session_id, "dummy")
    assert artifact_key == f"grid/{expected_sandbox}/{session_id}/dummy"

    # parse and verify components
    parsed = mgr.parse_grid_key(artifact_key)
    assert parsed == {
        "sandbox_id": expected_sandbox,
        "session_id": session_id,
        "artifact_id": "dummy",
        "subpath": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


@aio_pytest_mark
async def test_explicit_sandbox_id():
    """Passing sandbox_id to SessionManager should be honoured."""
    mgr = SessionManager(sandbox_id="explicit‑sandbox")
    session_id = await mgr.allocate_session(user_id="alice")
    await _assert_prefix_matches(mgr, session_id, "explicit‑sandbox")


@aio_pytest_mark
async def test_env_var_sandbox_id(monkeypatch):
    """CHUK_SANDBOX_ID env var should set default sandbox namespace."""
    monkeypatch.setenv("CHUK_SANDBOX_ID", "env‑sandbox")
    # no sandbox_id param → should pick up env var
    mgr = SessionManager()
    assert mgr.sandbox_id == "env‑sandbox"
    session_id = await mgr.allocate_session(user_id="bob")
    await _assert_prefix_matches(mgr, session_id, "env‑sandbox")


@aio_pytest_mark
async def test_auto_generated_sandbox_id(monkeypatch):
    """If nothing is provided, SessionManager auto‑generates a stable id."""
    # Clear env var to ensure auto mode
    monkeypatch.delenv("CHUK_SANDBOX_ID", raising=False)
    auto_mgr = SessionManager()
    auto_id = auto_mgr.sandbox_id

    # Looks like "sandbox‑xxxxxxxx" where x is 8 uuid chars
    assert auto_id.startswith("sandbox-")
    assert _is_valid_uuid_segment(auto_id.split("-", 1)[1])

    session_id = await auto_mgr.allocate_session(user_id="carol")
    await _assert_prefix_matches(auto_mgr, session_id, auto_id)


# ─────────────────────────────────────────────────────────────────────────────
# End of file
# ─────────────────────────────────────────────────────────────────────────────
