"""Tests for MockRemediator."""

from __future__ import annotations

from datetime import UTC, datetime

from core.incident import Decision, Incident, IncidentStatus, Result
from plugins.remediators.mock import MockRemediator


def make_incident() -> Incident:
    """Build a deterministic incident for remediation tests."""
    return Incident(
        id="inc-1",
        source="test",
        source_ref="ref",
        status=IncidentStatus.REMEDIATING,
        trust_level_at_open="A4",
        attempts=1,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={},
    )


class _FixedEnforcer:
    """Enforcer stub returning a configured decision."""

    def __init__(self, decision: Decision) -> None:
        self._decision = decision

    def authorize(self, action: str) -> Decision:
        return self._decision


def test_success_by_default() -> None:
    """MockRemediator succeeds when enforcer allows and configured to succeed."""
    remediator = MockRemediator()
    result = remediator.remediate(make_incident(), _FixedEnforcer(Decision.ALLOW))
    assert result == Result(success=True, summary="mock remediation completed")


def test_forced_failure() -> None:
    """MockRemediator can be forced to fail."""
    remediator = MockRemediator(success=False, summary="boom")
    result = remediator.remediate(make_incident(), _FixedEnforcer(Decision.ALLOW))
    assert result == Result(success=False, summary="boom")


def test_enforcer_deny() -> None:
    """Deny decision yields a denied result."""
    remediator = MockRemediator()
    result = remediator.remediate(make_incident(), _FixedEnforcer(Decision.DENY))
    assert result == Result(success=False, summary="denied by enforcer")


def test_enforcer_require_approval() -> None:
    """Require approval decision yields an approval-required result."""
    remediator = MockRemediator()
    result = remediator.remediate(make_incident(), _FixedEnforcer(Decision.REQUIRE_APPROVAL))
    assert result == Result(success=False, summary="approval required")
