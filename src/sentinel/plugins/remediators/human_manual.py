"""Skeleton remediator that blocks on a human resolving the incident."""

from __future__ import annotations

from sentinel.core.incident import Incident, Result
from sentinel.interfaces.enforcer import Enforcer
from sentinel.interfaces.notifier import Notifier
from sentinel.interfaces.remediator import Remediator


class HumanManualRemediator(Remediator):
    """Wait for a human to resolve the incident before continuing."""

    def __init__(self, notifier: Notifier) -> None:
        self._notifier = notifier

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Escalate to a human and poll until the incident resolves."""
        raise NotImplementedError(
            "block on a human resolving the incident; use the provided "
            "notifier to escalate, then poll state_store for status change"
        )
