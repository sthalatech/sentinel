"""Zero-setup notifier that prints escalations to stdout."""

from __future__ import annotations

from core.incident import EscalationEvent


class StdoutNotifier:
    """Print the escalation event (incident id + reason) to stdout."""

    def __init__(self) -> None:
        pass

    def notify(self, event: EscalationEvent) -> None:
        """Send the event to stdout."""
        print(f"ESCALATED incident={event.incident.id} reason={event.reason}")
