"""Tests for TrustManager.reset and the `sentinel trust reset` CLI command."""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock

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
