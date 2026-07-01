"""Slack notifier using an Incoming Webhook and only stdlib HTTP."""

from __future__ import annotations

import json
import logging
from urllib.error import URLError
from urllib.request import Request, urlopen

from core.incident import EscalationEvent
from interfaces.notifier import Notifier
from interfaces.secret_provider import SecretProvider

logger = logging.getLogger(__name__)


class SlackNotifier(Notifier):
    """Fire-and-forget escalation notifications to a Slack webhook."""

    def __init__(
        self, secret_provider: SecretProvider, webhook_env: str = "SLACK_WEBHOOK_URL"
    ) -> None:
        self._secret_provider = secret_provider
        self._webhook_env = webhook_env

    def notify(self, event: EscalationEvent) -> None:
        """Send a short escalation message to the configured Slack webhook."""
        try:
            url = self._secret_provider.get(self._webhook_env)
            payload = {
                "text": (f"🚨 sentinel/{event.incident.id} escalated: {event.reason}"),
            }
            data = json.dumps(payload).encode("utf-8")
            request = Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=30) as response:
                response.read()
        except (RuntimeError, OSError, URLError) as exc:
            logger.warning("Slack notify failed for %s: %s", event.incident.id, exc)
