"""Notifier protocol: escalate an event to a human."""

from __future__ import annotations

from typing import Protocol

from sentinel.core.incident import EscalationEvent


class Notifier(Protocol):
    """A notifier delivers escalation events fire-and-forget."""

    def notify(self, event: EscalationEvent) -> None:
        """Send the event; failures must not block the loop."""
        ...
