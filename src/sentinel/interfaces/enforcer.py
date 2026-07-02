"""Enforcer protocol: authorize a proposed tool action before it runs."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import Decision


class Enforcer(Protocol):
    """An enforcer gates each tool call the active remediator makes."""

    def authorize(self, action: str) -> Decision:
        """Return ALLOW, DENY, or REQUIRE_APPROVAL for a named action."""
        ...

    def allowed_actions(self, trust_level: str) -> list[str]:
        """Return the actions permitted without approval at a trust level.

        Remediators that restrict the tool surface *before* a run (rather than
        gating each call mid-run) use this to render their toolset allowlist.
        """
        ...
