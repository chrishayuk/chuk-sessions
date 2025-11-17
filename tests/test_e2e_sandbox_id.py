# test_e2e_sandbox_id.py
"""End-to-end tests that verify sandbox-ID propagation in chuk_sessions.

Run these tests with pytest:

    pytest -q test_e2e_sandbox_id.py

They exercise three scenarios:
1.  Explicit sandbox_id passed to SessionManager
2.  sandbox_id supplied via CHUK_SANDBOX_ID env var
3.  Automatically generated sandbox_id when nothing provided

Each test allocates a session and verifies the sandbox_id is correctly set.
"""

from __future__ import annotations

import re

import pytest

from chuk_sessions.session_manager import SessionManager


# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

aio_pytest_mark = pytest.mark.asyncio  # shortcut so we can decorate below


def _is_valid_uuid_segment(segment: str) -> bool:
    """Rough check that a string looks like the 8‑char uuid we expect."""
    return bool(re.fullmatch(r"[0-9a-f]{8}", segment))


async def _assert_sandbox_matches(
    mgr: SessionManager, session_id: str, expected_sandbox: str
):
    """Verify that the SessionManager has the expected sandbox_id."""
    # Check the manager's sandbox_id attribute
    assert mgr.sandbox_id == expected_sandbox

    # Verify the session was created and is valid
    assert await mgr.validate_session(session_id)

    # Get session info and verify it contains the correct sandbox_id
    session_info = await mgr.get_session_info(session_id)
    assert session_info is not None
    assert session_info["sandbox_id"] == expected_sandbox
    assert session_info["session_id"] == session_id


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


@aio_pytest_mark
async def test_explicit_sandbox_id():
    """Passing sandbox_id to SessionManager should be honoured."""
    mgr = SessionManager(sandbox_id="explicit-sandbox")
    assert mgr.sandbox_id == "explicit-sandbox"

    session_id = await mgr.allocate_session(user_id="alice")
    await _assert_sandbox_matches(mgr, session_id, "explicit-sandbox")


@aio_pytest_mark
async def test_env_var_sandbox_id(monkeypatch):
    """CHUK_SANDBOX_ID env var should set default sandbox namespace."""
    monkeypatch.setenv("CHUK_SANDBOX_ID", "env-sandbox")
    # no sandbox_id param → should pick up env var
    mgr = SessionManager()
    assert mgr.sandbox_id == "env-sandbox"

    session_id = await mgr.allocate_session(user_id="bob")
    await _assert_sandbox_matches(mgr, session_id, "env-sandbox")


@aio_pytest_mark
async def test_auto_generated_sandbox_id(monkeypatch):
    """If nothing is provided, SessionManager auto‑generates a stable id."""
    # Clear env vars to ensure auto mode
    monkeypatch.delenv("CHUK_SANDBOX_ID", raising=False)
    monkeypatch.delenv("CHUK_HOST_SANDBOX_ID", raising=False)

    auto_mgr = SessionManager()
    auto_id = auto_mgr.sandbox_id

    # Looks like "sandbox-xxxxxxxx" where x is 8 uuid chars
    assert auto_id.startswith("sandbox-")
    assert _is_valid_uuid_segment(auto_id.split("-", 1)[1])

    session_id = await auto_mgr.allocate_session(user_id="carol")
    await _assert_sandbox_matches(auto_mgr, session_id, auto_id)


# ─────────────────────────────────────────────────────────────────────────────
# End of file
# ─────────────────────────────────────────────────────────────────────────────
