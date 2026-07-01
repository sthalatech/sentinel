"""Tests for the GitHub Issues tracker using a local fake server."""

from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from core.incident import Incident, IncidentStatus
from plugins.issue_trackers.github_issues import GitHubIssues
from plugins.secret_providers.env_provider import EnvSecretProvider


class FakeGitHubHandler(BaseHTTPRequestHandler):
    """Record requests and return canned GitHub issue responses."""

    calls: queue.Queue[dict[str, Any]] = queue.Queue()
    next_number: int = 42
    fail_next_create: bool = False
    fail_all: bool = False

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length:
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)
        return {}

    def do_POST(self) -> None:
        if self.fail_all:
            self._respond(500, {"message": "explosion"})
            return
        body = self._read_body()
        FakeGitHubHandler.calls.put({"method": "POST", "path": self.path, "body": body})
        if self.path.endswith("/issues"):
            if self.fail_next_create:
                self.fail_next_create = False
                self._respond(500, {"message": "create failed"})
                return
            FakeGitHubHandler.next_number += 1
            self._respond(201, {"number": FakeGitHubHandler.next_number})
        elif self.path.endswith("/comments"):
            self._respond(201, {"id": 7})

    def do_PATCH(self) -> None:
        if self.fail_all:
            self._respond(500, {"message": "explosion"})
            return
        body = self._read_body()
        FakeGitHubHandler.calls.put({"method": "PATCH", "path": self.path, "body": body})
        self._respond(200, {"number": self.path.rsplit("/", 1)[-1]})


def _make_tracker(base_url: str) -> GitHubIssues:
    secrets = EnvSecretProvider({"GITHUB_TOKEN": "fake-token"})
    return GitHubIssues(repo="acme/widgets", secret_provider=secrets, base_url=base_url)


def _incident(status: IncidentStatus = IncidentStatus.DETECTED) -> Incident:
    return Incident(
        id="inc-1",
        source="probe",
        source_ref="host-9/cpu",
        status=status,
        trust_level_at_open="A4",
        attempts=1,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={"cpu_percent": 99.9, "threshold": 80},
    )


def test_create_stores_external_ref() -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_next_create = False
    FakeGitHubHandler.fail_all = False

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident()
        ref = tracker.create(incident)
        assert ref == "acme/widgets#42"
        assert incident.external_refs["issue"] == "acme/widgets#42"

        call = FakeGitHubHandler.calls.get(timeout=1)
        assert call["method"] == "POST"
        assert call["path"] == "/repos/acme/widgets/issues"
        assert call["body"]["title"] == "sentinel/inc-1"
        assert "cpu_percent" in call["body"]["body"]
    finally:
        server.shutdown()


def test_comment_posts() -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_all = False

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident()
        incident.external_refs["issue"] = "acme/widgets#7"
        tracker.comment(incident, "Attempt 1: rebooted service")

        call = FakeGitHubHandler.calls.get(timeout=1)
        assert call["method"] == "POST"
        assert call["path"] == "/repos/acme/widgets/issues/7/comments"
        assert call["body"]["body"] == "Attempt 1: rebooted service"
    finally:
        server.shutdown()


def test_sync_status_resolves_to_closed() -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_all = False

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident(IncidentStatus.RESOLVED)
        incident.external_refs["issue"] = "acme/widgets#5"
        tracker.sync_status(incident)

        call = FakeGitHubHandler.calls.get(timeout=1)
        assert call["method"] == "PATCH"
        assert call["path"] == "/repos/acme/widgets/issues/5"
        assert call["body"]["state"] == "closed"
    finally:
        server.shutdown()


def test_sync_status_opens_unresolved() -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_all = False

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident(IncidentStatus.REMEDIATING)
        incident.external_refs["issue"] = "acme/widgets#3"
        tracker.sync_status(incident)

        call = FakeGitHubHandler.calls.get(timeout=1)
        assert call["method"] == "PATCH"
        assert call["body"]["state"] == "open"
    finally:
        server.shutdown()


def test_sync_status_creates_when_no_ref() -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_all = False

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident()
        tracker.sync_status(incident)

        create = FakeGitHubHandler.calls.get(timeout=1)
        assert create["method"] == "POST"
        assert create["path"] == "/repos/acme/widgets/issues"
        patch = FakeGitHubHandler.calls.get(timeout=1)
        assert patch["method"] == "PATCH"
        assert incident.external_refs["issue"] == "acme/widgets#42"
    finally:
        server.shutdown()


def test_sync_status_idempotent() -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_all = False

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident(IncidentStatus.RESOLVED)
        incident.external_refs["issue"] = "acme/widgets#9"
        tracker.sync_status(incident)
        tracker.sync_status(incident)

        call_one = FakeGitHubHandler.calls.get(timeout=1)
        call_two = FakeGitHubHandler.calls.get(timeout=1)
        assert call_one["body"]["state"] == "closed"
        assert call_two["body"]["state"] == "closed"
    finally:
        server.shutdown()


def test_sync_status_logs_on_server_error(caplog: Any) -> None:
    FakeGitHubHandler.next_number = 41
    FakeGitHubHandler.calls = queue.Queue()
    FakeGitHubHandler.fail_all = True

    server = HTTPServer(("127.0.0.1", 0), FakeGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        tracker = _make_tracker(base_url)
        incident = _incident()
        with caplog.at_level(logging.WARNING):
            tracker.sync_status(incident)
        assert "GitHub sync_status failed" in caplog.text
    finally:
        server.shutdown()
