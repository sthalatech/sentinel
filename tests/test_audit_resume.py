"""Tests for AuditLog resuming its hash chain after a process restart."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel.core.audit import AuditLog
from sentinel.core.incident import Incident, IncidentStatus, Result
from sentinel.plugins.state_stores.sqlite_store import SqliteAuditSink, SqliteStateStore


def _make_incident() -> Incident:
    """Return a minimal incident for audit tests."""
    return Incident(
        id="inc-1",
        source="test",
        source_ref="ref-1",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=1,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={},
    )


def test_audit_log_resumes_chain_after_restart() -> None:
    """A new AuditLog over the same sink continues seq/prev_hash without error."""
    store = SqliteStateStore(":memory:")
    sink = SqliteAuditSink(store)

    first_log = AuditLog(sink)
    first_entry = first_log.record(_make_incident(), Result(success=True, summary="ok"))

    second_log = AuditLog(sink)
    second_entry = second_log.record(_make_incident(), Result(success=False, summary="no"))

    assert second_entry.seq == first_entry.seq + 1
    assert second_entry.prev_hash == first_entry.hash


def test_audit_log_starts_fresh_on_empty_sink() -> None:
    """A new AuditLog over an empty sink starts at seq 1 with the zero hash."""
    store = SqliteStateStore(":memory:")
    log = AuditLog(SqliteAuditSink(store))
    entry = log.record(_make_incident(), Result(success=True, summary="ok"))
    assert entry.seq == 1
    assert entry.prev_hash == "0" * 64
