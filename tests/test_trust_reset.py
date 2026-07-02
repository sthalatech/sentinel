"""Tests for TrustManager.reset and the `sentinel trust reset` CLI command."""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock

import pytest

from sentinel.cli.incidents import main as cli_main
from sentinel.core.audit import AuditLog
from sentinel.core.trust import TrustManager


def test_trust_manager_reset_sets_level_and_records() -> None:
    """reset() sets the level, persists it, and records a trust_reset audit entry."""
    store = MagicMock()
    store.set_trust = MagicMock()
    audit = MagicMock(spec=AuditLog)
    mgr = TrustManager(store, audit, level="A4")

    mgr.demote(reason="failure")
    assert mgr.level == "A3"
    mgr.reset("A4", reason="reviewed", actor="human-cli")

    assert mgr.level == "A4"
    store.set_trust.assert_called_with("A4")
    audit.record_trust_reset.assert_called_once_with("A4", "reviewed", "human-cli")


def test_trust_reset_cli_command_resets_level(monkeypatch, capsys) -> None:
    """`sentinel trust reset A4 --reason ...` calls TrustManager.reset and prints."""
    cfg = MagicMock()
    cfg.trust = MagicMock()
    monkeypatch.setattr("sentinel.cli.incidents._load_config", lambda _path: cfg)
    cli_main(["trust", "reset", "A4", "--reason", "reviewed"])

    cfg.trust.reset.assert_called_once_with("A4", "reviewed", actor="human-cli")
    out = capsys.readouterr().out.strip()
    assert out == "trust reset to A4"


def _ns() -> argparse.Namespace:
    """Return a minimal Namespace to satisfy type hints in helper tests."""
    return argparse.Namespace()


# ---------------------------------------------------------------------------
# reset() input validation: a typo must not silently corrupt the trust level.
# ---------------------------------------------------------------------------


def test_trust_manager_reset_rejects_invalid_level() -> None:
    """reset() raises ValueError for a malformed level rather than storing it."""
    store = MagicMock()
    store.set_trust = MagicMock()
    audit = MagicMock(spec=AuditLog)
    mgr = TrustManager(store, audit, level="A4")

    with pytest.raises(ValueError, match="invalid trust level"):
        mgr.reset("A4x", reason="typo")  # typo: extra char
    # The corrupt value was never stored: level unchanged and no reset recorded.
    # (store.set_trust WAS called once during __init__ for the initial A4, so
    # assert against the bad value rather than "not called".)
    assert mgr.level == "A4"
    assert not any(call.args == ("A4x",) for call in store.set_trust.call_args_list)
    audit.record_trust_reset.assert_not_called()


def test_trust_manager_reset_rejects_bare_letter() -> None:
    """reset() rejects 'A' with no digits (must be A + one or more digits)."""
    store = MagicMock()
    audit = MagicMock(spec=AuditLog)
    mgr = TrustManager(store, audit, level="A4")

    with pytest.raises(ValueError):
        mgr.reset("A", reason="missing digits")
    with pytest.raises(ValueError):
        mgr.reset("B4", reason="wrong letter")
    with pytest.raises(ValueError):
        mgr.reset("4", reason="no letter")
    assert mgr.level == "A4"


def test_trust_manager_reset_accepts_valid_levels() -> None:
    """reset() accepts any well-formed level (A1, A2, ...)."""
    store = MagicMock()
    store.set_trust = MagicMock()
    audit = MagicMock(spec=AuditLog)
    mgr = TrustManager(store, audit, level="A4")

    mgr.reset("A1", reason="floor")
    assert mgr.level == "A1"
    mgr.reset("A12", reason="high")
    assert mgr.level == "A12"
