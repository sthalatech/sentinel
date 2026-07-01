"""Tests for the Slack webhook notifier using a local fake server."""

from __future__ import annotations

import json
import queue
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from core.incident import EscalationEvent, Incident, IncidentStatus
from plugins.notifiers.slack import SlackNotifier
from plugins.secret_providers.env_provider import EnvSecretProvider


class FakeSlackHandler(BaseHTTPRequestHandler):
    """Record incoming webhook POSTs."""

    calls: queue.Queue[dict] = queue.Queue()

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        FakeSlackHandler.calls.put(json.loads(raw))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"ok")


def _incident() -> Incident:
    return Incident(
        id="inc-2",
        source="probe",
        source_ref="disk/usage",
        status=IncidentStatus.ESCALATED,
        trust_level_at_open="A4",
        attempts=2,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={"disk_percent": 98},
    )


def test_notify_posts_json_with_id_and_reason() -> None:
    FakeSlackHandler.calls = queue.Queue()
    server = HTTPServer(("127.0.0.1", 0), FakeSlackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/webhook"

    try:
        secrets = EnvSecretProvider({"SLACK_WEBHOOK_URL": url})
        notifier = SlackNotifier(secrets)
        event = EscalationEvent(_incident(), reason="trust-locked")
        notifier.notify(event)

        body = FakeSlackHandler.calls.get(timeout=1)
        assert "inc-2" in body["text"]
        assert "trust-locked" in body["text"]
        assert "🚨" in body["text"]
    finally:
        server.shutdown()


def test_notify_does_not_raise_on_refused_connection() -> None:
    secrets = EnvSecretProvider({"SLACK_WEBHOOK_URL": "http://127.0.0.1:1/webhook"})
    notifier = SlackNotifier(secrets)
    event = EscalationEvent(_incident(), reason="unresolved")
    notifier.notify(event)
