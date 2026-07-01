"""Tests for StdoutNotifier and WebhookNotifier."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from sentinel.core.incident import EscalationEvent, Incident, IncidentStatus
from sentinel.plugins.notifiers.stdout import StdoutNotifier
from sentinel.plugins.notifiers.webhook import WebhookNotifier


def make_event() -> EscalationEvent:
    """Build a deterministic escalation event."""
    incident = Incident(
        id="inc-1",
        source="test",
        source_ref="ref-1",
        status=IncidentStatus.ESCALATED,
        trust_level_at_open="A4",
        attempts=1,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={},
    )
    return EscalationEvent(incident, reason="unresolved")


class _WebhookHandler(BaseHTTPRequestHandler):
    """Capture POST bodies in a shared list."""

    received: list[bytes] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        _WebhookHandler.received.append(body)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def test_stdout_prints(capsys) -> None:
    """StdoutNotifier writes the incident id and reason."""
    notifier = StdoutNotifier()
    event = make_event()
    notifier.notify(event)
    captured = capsys.readouterr()
    assert f"incident={event.incident.id}" in captured.out
    assert "reason=unresolved" in captured.out


def test_webhook_posts_json() -> None:
    """WebhookNotifier posts the expected JSON to a local server."""
    _WebhookHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _WebhookHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        notifier = WebhookNotifier(f"http://127.0.0.1:{port}/hook", timeout=2.0)
        notifier.notify(make_event())
    finally:
        server.shutdown()
    assert len(_WebhookHandler.received) == 1
    payload = json.loads(_WebhookHandler.received[0])
    assert payload == {"incident_id": "inc-1", "reason": "unresolved"}


def test_webhook_swallows_connection_error() -> None:
    """WebhookNotifier does not raise on a refused connection."""
    notifier = WebhookNotifier("http://127.0.0.1:1/hook", timeout=0.5)
    notifier.notify(make_event())
