"""Timer-based orchestrator with exponential backoff for sentinel."""

from __future__ import annotations

import logging
import threading
from typing import Any

from sentinel.core.engine import SentinelConfig, run_once

logger = logging.getLogger(__name__)


class SimpleLoopOrchestrator:
    """Run run_once on a fixed interval, backing off on unhandled errors."""

    def __init__(
        self,
        interval: float = 60.0,
        initial_backoff: float = 1.0,
        max_backoff: float = 300.0,
        backoff_factor: float = 2.0,
    ) -> None:
        self._interval = interval
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._backoff_factor = backoff_factor
        self._backoff = initial_backoff
        self._stop = threading.Event()
        self._timer: threading.Timer | None = None
        self._signals: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def schedule(self, cfg: SentinelConfig) -> None:
        """Begin invoking run_once on the configured cadence."""
        if self._stop.is_set():
            raise RuntimeError("orchestrator already stopped")
        self._tick(cfg)

    def retry(self, cfg: SentinelConfig) -> None:
        """Re-run the loop after a failure, applying backoff."""
        self._wait(self._backoff)
        self._backoff = min(self._backoff * self._backoff_factor, self._max_backoff)
        if not self._stop.is_set():
            self.schedule(cfg)

    def wait_signal(self, key: str, timeout: float) -> bool:
        """Block until a named signal arrives or timeout elapses."""
        with self._lock:
            event = self._signals.setdefault(key, threading.Event())
        return event.wait(timeout)

    def signal(self, key: str) -> None:
        """Fire a named signal so any waiter can proceed."""
        with self._lock:
            event = self._signals.setdefault(key, threading.Event())
        event.set()

    def stop(self) -> None:
        """Stop the loop cleanly and cancel any pending timer."""
        self._stop.set()
        timer = self._timer
        if timer is not None:
            timer.cancel()

    def _tick(self, cfg: SentinelConfig) -> None:
        """Run one pass and schedule the next invocation."""
        if self._stop.is_set():
            return
        try:
            run_once(cfg)
            self._backoff = self._initial_backoff
        except Exception:
            logger.exception("run_once failed; retrying with backoff")
            self.retry(cfg)
            return
        if not self._stop.is_set():
            self._timer = threading.Timer(self._interval, self._tick, args=(cfg,))
            self._timer.daemon = True
            self._timer.start()

    def _wait(self, delay: float) -> None:
        """Sleep unless stopped early."""
        self._stop.wait(min(delay, self._max_backoff))


def _noop(*args: Any, **kwargs: Any) -> None:
    """Placeholder no-op for type stubs."""
    pass
