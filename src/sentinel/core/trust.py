"""Global trust level and demotion rules."""

from __future__ import annotations

from typing import Protocol

from .audit import AuditLog

MIN_LEVEL = 1
DEFAULT_LEVEL = "A4"


class TrustManager:
    """Holds one global trust level; demotes on failures, resets on review."""

    def __init__(
        self, state_store: TrustStore, audit: AuditLog, level: str = DEFAULT_LEVEL
    ) -> None:
        self._store = state_store
        self._audit = audit
        self._level = level
        self._store.set_trust(level)

    @property
    def level(self) -> str:
        """Current global trust level."""
        return self._level

    def is_locked_down(self) -> bool:
        """True when trust has fallen to the minimum (lockdown)."""
        return self._level == f"A{MIN_LEVEL}"

    def demote(self, reason: str) -> None:
        """Drop one global trust level, floored at the minimum."""
        num = int(self._level.lstrip("A")) if self._level.startswith("A") else MIN_LEVEL
        new_num = max(num - 1, MIN_LEVEL)
        self._level = f"A{new_num}"
        self._store.set_trust(self._level)
        self._audit.record_demotion(self._level, reason)

    def reset(self, level: str, reason: str, actor: str = "human-cli") -> None:
        """Set trust to an explicit level after human review."""
        self._level = level
        self._store.set_trust(level)
        self._audit.record_trust_reset(level, reason, actor)


class TrustStore(Protocol):
    """Protocol for persisting the global trust level."""

    def set_trust(self, level: str) -> None:
        """Persist the global trust level."""
        ...

    def get_trust(self) -> str:
        """Return the stored global trust level."""
        ...
