"""Verifier protocol: re-run the check that found the problem."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import Incident


class Verifier(Protocol):
    """A verifier confirms an incident is actually resolved."""

    def verify(self, incident: Incident) -> bool:
        """Return True if the original failure no longer occurs."""
        ...
