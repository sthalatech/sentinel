"""Detector protocol: find problems, cheaply and deterministically."""

from __future__ import annotations

from typing import Protocol

from core.incident import Incident


class Detector(Protocol):
    """A detector finds incidents without side effects or LLM calls."""

    def detect(self) -> list[Incident]:
        """Return incidents currently observable by this detector."""
        ...
