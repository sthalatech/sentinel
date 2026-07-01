"""Append-only, tamper-evident audit log writer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sentinel.core.incident import Incident, IncidentStatus, Result


class AuditSink(Protocol):
    """Storage backend for the append-only audit log."""

    def append(self, entry: AuditEntry) -> None:
        """Persist one audit entry in order."""


@dataclass
class AuditEntry:
    """A single immutable record in the audit chain."""

    seq: int
    ts: str
    incident_id: str
    kind: str
    actor: str
    payload: dict[str, object]
    prev_hash: str
    hash: str


def _hash_entry(
    seq: int,
    ts: str,
    incident_id: str,
    kind: str,
    actor: str,
    payload: dict[str, object],
    prev_hash: str,
) -> str:
    """Return sha256 over the entry's canonical fields."""
    blob = json.dumps(
        {
            "seq": seq,
            "ts": ts,
            "incident_id": incident_id,
            "kind": kind,
            "actor": actor,
            "payload": payload,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(blob).hexdigest()


class AuditLog:
    """Hash-chained audit log; each entry references the previous hash."""

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink
        self._seq = 0
        self._prev = "0" * 64

    def _next(
        self, incident_id: str, kind: str, actor: str, payload: dict[str, object]
    ) -> AuditEntry:
        self._seq += 1
        ts = datetime.now(UTC).isoformat()
        h = _hash_entry(self._seq, ts, incident_id, kind, actor, payload, self._prev)
        entry = AuditEntry(self._seq, ts, incident_id, kind, actor, payload, self._prev, h)
        self._prev = h
        return entry

    def record(self, incident: Incident, result: Result) -> AuditEntry:
        """Record a remediation attempt result."""
        payload = {
            "success": result.success,
            "summary": result.summary,
            "attempts": incident.attempts,
        }
        entry = self._next(incident.id, "remediation", "engine", payload)
        self._sink.append(entry)
        return entry

    def record_status_change(
        self, incident_id: str, status: IncidentStatus, reason: str, actor: str
    ) -> AuditEntry:
        """Record a status transition written through apply_status_change."""
        entry = self._next(
            incident_id, "status_change", actor, {"status": status.value, "reason": reason}
        )
        self._sink.append(entry)
        return entry

    def record_demotion(self, new_level: str, reason: str) -> AuditEntry:
        """Record a global trust demotion."""
        entry = self._next(
            "trust", "demotion", "engine", {"new_level": new_level, "reason": reason}
        )
        self._sink.append(entry)
        return entry
