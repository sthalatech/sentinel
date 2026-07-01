"""Tests for ShelleyRemediator using a fake injected client (no live server)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from sentinel.core.incident import Incident, IncidentStatus
from sentinel.plugins.remediators.shelley import (
    ShelleyRemediator,
    _parse_status_directive,
)


class _FakeClient:
    """In-memory ShelleyClient recording calls and returning canned messages."""

    def __init__(self, agent_messages: list[dict[str, Any]]) -> None:
        self._agent_messages = agent_messages
        self.chat_calls: list[tuple[str, str | None]] = []
        self.read_calls: list[str] = []
        self._next_id = 0

    def chat(self, prompt: str, conversation_id: str | None = None) -> str:
        """Record the call; mint a new id when none is given."""
        self.chat_calls.append((prompt, conversation_id))
        if conversation_id is not None:
            return conversation_id
        self._next_id += 1
        return f"conv-{self._next_id}"

    def read_until_done(self, conversation_id: str, timeout: float) -> list[dict[str, Any]]:
        """Return the canned agent messages for this conversation."""
        del timeout
        self.read_calls.append(conversation_id)
        return self._agent_messages


def _make_incident() -> Incident:
    """Return a fresh detected incident for remediator tests."""
    from datetime import UTC, datetime

    return Incident(
        id="inc-1",
        source="test",
        source_ref="ref-1",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=0,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={},
    )


def _secrets() -> MagicMock:
    """Return a minimal secret-provider mock."""
    return MagicMock()


def test_creates_one_conversation_per_incident_id() -> None:
    """A first remediate() mints a conversation and stores the ref."""
    client = _FakeClient(agent_messages=[{"type": "agent", "text": "done", "end_of_turn": True}])
    rem = ShelleyRemediator(api_url="x", secret_provider=_secrets(), client=client)
    incident = _make_incident()

    result = rem.remediate(incident, enforcer=MagicMock())

    assert client.chat_calls == [(_first_prompt(client, incident), None)]
    assert incident.external_refs["conversation"] == "conv-1"
    assert result.success is True


def _first_prompt(client: _FakeClient, incident: Incident) -> str:
    """Return the prompt captured on the first chat call."""
    del incident
    return client.chat_calls[0][0]


def test_second_remediate_resumes_not_recreates() -> None:
    """A second remediate() reuses the stored conversation ref, not a new one."""
    client = _FakeClient(agent_messages=[{"type": "agent", "text": "done", "end_of_turn": True}])
    rem = ShelleyRemediator(api_url="x", secret_provider=_secrets(), client=client)
    incident = _make_incident()
    rem.remediate(incident, enforcer=MagicMock())
    first_id = incident.external_refs["conversation"]

    rem.remediate(incident, enforcer=MagicMock())

    assert incident.external_refs["conversation"] == first_id
    # second chat call resumes with the stored id, not None
    assert client.chat_calls[1][1] == first_id


def test_bridge_tool_invokes_apply_status_change() -> None:
    """A set_incident_status directive in the agent reply writes engine state."""
    agent_text = (
        "I tried a restart. " 'set_incident_status {"status": "resolved", "reason": "restarted ok"}'
    )
    client = _FakeClient(
        agent_messages=[{"type": "agent", "text": agent_text, "end_of_turn": True}]
    )
    store = MagicMock()
    audit = MagicMock()
    tracker = MagicMock()
    store.get.return_value = _make_incident()
    rem = ShelleyRemediator(
        api_url="x",
        secret_provider=_secrets(),
        client=client,
        state_store=store,
        audit=audit,
        issue_tracker=tracker,
    )
    incident = _make_incident()

    rem.remediate(incident, enforcer=MagicMock())

    store.put.assert_called()
    audit.record_status_change.assert_called_once()
    _args, _kwargs = audit.record_status_change.call_args
    assert _args[1] == IncidentStatus.RESOLVED
    assert _args[3] == "agent"


def test_parse_status_directive_extracts_valid_statuses() -> None:
    """_parse_status_directive pulls valid statuses and ignores junk."""
    text = 'noise set_incident_status {"status": "paused", "reason": "waiting"} more'
    pairs = _parse_status_directive(text)
    assert pairs == [(IncidentStatus.PAUSED, "waiting")]


def test_parse_status_directive_ignores_unknown_status() -> None:
    """An unknown status string yields no directive."""
    text = 'set_incident_status {"status": "destroyed", "reason": "x"}'
    assert _parse_status_directive(text) == []
