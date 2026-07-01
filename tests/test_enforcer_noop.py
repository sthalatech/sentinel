"""Tests for NoopEnforcer."""

from __future__ import annotations

from sentinel.core.incident import Decision
from sentinel.plugins.enforcers.noop import NoopEnforcer


def test_noop_enforcer_always_allow() -> None:
    """NoopEnforcer returns ALLOW for any action."""
    enforcer = NoopEnforcer()
    assert enforcer.authorize("anything") == Decision.ALLOW
