"""IssueTracker protocol: mirror incident lifecycle into an external tracker."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import Incident


class IssueTracker(Protocol):
    """An issue tracker mirrors the incident state machine, idempotently."""

    def create(self, incident: Incident) -> str:
        """Create the mirrored issue; return its external ref id."""
        ...

    def comment(self, incident: Incident, body: str) -> None:
        """Append a comment to the mirrored issue."""
        ...

    def sync_status(self, incident: Incident) -> None:
        """Assert the tracker state matches the incident status."""
        ...
