"""Tests for SqliteStateStore and SqliteAuditSink."""

from __future__ import annotations

from datetime import UTC, datetime

from core.audit import AuditEntry
from core.incident import Incident, IncidentStatus
from plugins.state_stores.sqlite_store import SqliteAuditSink, SqliteStateStore


def make_incident(idx: int, detected_at: datetime) -> Incident:
    """Build a deterministic incident for round-trip tests."""
    return Incident(
        id=f"inc-{idx}",
        source="test",
        source_ref=f"ref-{idx}",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=0,
        detected_at=detected_at,
        resolved_at=None,
        context={"key": idx},
        external_refs={"tracker": f"issue-{idx}"},
    )


def test_round_trip_incident() -> None:
    """Put and retrieve an incident with full fidelity."""
    store = SqliteStateStore(":memory:")
    now = datetime.now(UTC)
    incident = make_incident(1, now)
    store.put(incident)
    loaded = store.get(incident.id)
    assert loaded is not None
    assert loaded.id == incident.id
    assert loaded.status == IncidentStatus.DETECTED
    assert loaded.detected_at == now
    assert loaded.external_refs == {"tracker": "issue-1"}
    store.close()


def test_trust_get_set() -> None:
    """Trust level defaults and persists through set/get."""
    store = SqliteStateStore(":memory:")
    assert store.get_trust() == "A4"
    store.set_trust("A2")
    assert store.get_trust() == "A2"
    store.close()


def test_list_ordering() -> None:
    """list() returns incidents sorted by detected_at."""
    store = SqliteStateStore(":memory:")
    base = datetime.now(UTC)
    one = make_incident(1, base)
    two = make_incident(2, base.replace(microsecond=base.microsecond + 5000))
    store.put(two)
    store.put(one)
    ids = [i.id for i in store.list()]
    assert ids == ["inc-1", "inc-2"]
    store.close()


def test_audit_sink_append() -> None:
    """Audit entries are appended in order."""
    store = SqliteStateStore(":memory:")
    sink = SqliteAuditSink(store)
    entry = AuditEntry(
        seq=1,
        ts="2024-01-01T00:00:00+00:00",
        incident_id="inc-1",
        kind="status_change",
        actor="test",
        payload={"status": "resolved"},
        prev_hash="0" * 64,
        hash="a" * 64,
    )
    sink.append(entry)
    rows = store._conn.execute("SELECT seq, kind FROM audit ORDER BY seq").fetchall()
    assert rows == [(1, "status_change")]
    store.close()
