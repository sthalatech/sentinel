"""Notifier that POSTs escalation events to a URL via stdlib urllib."""

from __future__ import annotations

import json
import logging
from urllib import error, request

from core.incident import EscalationEvent

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """POST JSON escalation events to a configured URL."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self._url = url
        self._timeout = timeout

    def notify(self, event: EscalationEvent) -> None:
        """POST the event; failures are logged, never raised."""
        payload = json.dumps(
            {
                "incident_id": event.incident.id,
                "reason": event.reason,
            }
        ).encode()
        req = request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except error.URLError as exc:
            logger.warning("webhook failed: %s", exc)
