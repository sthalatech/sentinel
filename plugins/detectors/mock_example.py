"""Configurable detector for quickstart examples and tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from core.incident import Incident, IncidentStatus


class MockDetector:
    """Return a configured list of Incident objects on every detect call."""

    def __init__(
        self,
        incidents: list[Incident] | None = None,
        count: int = 0,
        factory: Callable[[int], Incident] | None = None,
    ) -> None:
        self._incidents = incidents or []
        if count and factory:
            self._incidents = [factory(i) for i in range(count)]

    def detect(self) -> list[Incident]:
        """Return the configured incidents."""
        return self._incidents


def default_mock_incident(index: int = 0) -> Incident:
    """Build a single default incident for quickstarts."""
    now = datetime.now(UTC)
    return Incident(
        id=f"mock-{index}",
        source="mock_detector",
        source_ref="default",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=0,
        detected_at=now,
        resolved_at=None,
        context={"note": "default mock incident"},
    )
