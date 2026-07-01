"""Enforcer that always allows actions and warns about lack of real gating."""

from __future__ import annotations

import logging

from core.incident import Decision

logger = logging.getLogger(__name__)


class NoopEnforcer:
    """Always returns Decision.ALLOW; logs a one-time construction warning."""

    def __init__(self) -> None:
        logger.warning("NoopEnforcer active: no real enforcement is applied")

    def authorize(self, action: str) -> Decision:
        """Authorize any action."""
        return Decision.ALLOW
