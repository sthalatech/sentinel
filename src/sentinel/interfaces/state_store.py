"""StateStore protocol: persist incidents, trust level, audit trail."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import Incident


class StateStore(Protocol):
    """The single source of truth for incidents."""

    def get(self, incident_id: str) -> Incident | None:
        """Return one incident by id, or None if unknown."""
        ...

    def put(self, incident: Incident) -> None:
        """Upsert an incident by id."""
        ...

    def list(self) -> list[Incident]:
        """Return all known incidents."""
        ...
