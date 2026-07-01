"""Tests for MockDetector."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel.core.incident import Incident, IncidentStatus
from sentinel.plugins.detectors.mock_example import MockDetector, default_mock_incident


def test_returns_configured_incidents() -> None:
    """MockDetector returns incidents supplied at construction."""
    now = datetime.now(UTC)
    incident = Incident(
        id="x-1",
        source="test",
        source_ref="r",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=0,
        detected_at=now,
        resolved_at=None,
        context={},
    )
    detector = MockDetector(incidents=[incident])
    assert detector.detect() == [incident]


def test_factory_count() -> None:
    """MockDetector builds incidents from count + factory."""
    detector = MockDetector(count=2, factory=default_mock_incident)
    incidents = detector.detect()
    assert len(incidents) == 2
    assert incidents[0].id == "mock-0"
    assert incidents[1].id == "mock-1"
