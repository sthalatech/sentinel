"""Skeleton detector that compares two data sources for divergence."""

from __future__ import annotations

from core.incident import Incident
from interfaces.detector import Detector


class DataReconciliationDetector(Detector):
    """Compare rows from two datasources and emit incidents on divergence."""

    def __init__(
        self,
        left_dsn: str,
        right_dsn: str,
        query: str,
        tolerance: float = 0.0,
    ) -> None:
        self.left_dsn = left_dsn
        self.right_dsn = right_dsn
        self.query = query
        self.tolerance = tolerance

    def detect(self) -> list[Incident]:
        """Return incidents for rows that differ beyond the tolerance."""
        raise NotImplementedError(
            "wire two data sources and a reconciliation query; "
            "emit incidents for rows that differ beyond tolerance"
        )
