"""Enforcer protocol: authorize a proposed tool action before it runs."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import Decision


class Enforcer(Protocol):
    """An enforcer gates each tool call the active remediator makes."""

    def authorize(self, action: str) -> Decision:
        """Return ALLOW, DENY, or REQUIRE_APPROVAL for a named action."""
        ...
