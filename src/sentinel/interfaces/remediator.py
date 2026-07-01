"""Remediator protocol: fix an incident, gated by an enforcer."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import Incident, Result


class Remediator(Protocol):
    """A remediator attempts to fix one incident."""

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Attempt remediation; the enforcer gates each tool call."""
        ...


from sentinel.interfaces.enforcer import Enforcer  # noqa: E402,F401  (cycle-safe for typing)
