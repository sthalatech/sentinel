"""Mock remediator for tests and quickstarts."""

from __future__ import annotations

from core.incident import Decision, Incident, Result
from interfaces.enforcer import Enforcer


class MockRemediator:
    """Remediation stub whose result is configurable."""

    def __init__(self, success: bool = True, summary: str = "mock remediation completed") -> None:
        self._success = success
        self._summary = summary

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Authorize with the enforcer and return the configured result."""
        decision = enforcer.authorize("mock.remediate")
        if decision == Decision.DENY:
            return Result(success=False, summary="denied by enforcer")
        if decision == Decision.REQUIRE_APPROVAL:
            return Result(success=False, summary="approval required")
        return Result(success=self._success, summary=self._summary)
