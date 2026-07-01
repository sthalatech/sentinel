"""Orchestrator protocol: run the loop and handle backoff/signals."""

from __future__ import annotations

from typing import Protocol

from core.engine import SentinelConfig


class Orchestrator(Protocol):
    """An orchestrator drives run_once on a schedule with retry/backoff."""

    def schedule(self, cfg: SentinelConfig) -> None:
        """Begin invoking run_once on the configured cadence."""
        ...

    def retry(self, cfg: SentinelConfig) -> None:
        """Re-run the loop after a failure, applying backoff."""
        ...

    def wait_signal(self, key: str, timeout: float) -> bool:
        """Block until a named signal arrives or timeout elapses."""
        ...
