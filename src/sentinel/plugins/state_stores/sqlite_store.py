"""SQLite-backed persistence for incidents, trust level, and audit entries."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime
from typing import Any

from sentinel.core.audit import AuditEntry
from sentinel.core.incident import Incident, IncidentStatus


class SqliteStateStore:
    """Persist incidents and the global trust level in one sqlite database."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create the tables used by incidents, meta, and audit."""
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def get(self, incident_id: str) -> Incident | None:
        """Return one incident by id, or None if unknown."""
        row = self._conn.execute(
            "SELECT json FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            return None
        return _decode(row[0])

    def put(self, incident: Incident) -> None:
        """Upsert an incident by id."""
        with self._conn:
            self._conn.execute(
                "INSERT INTO incidents (id, json) VALUES (?, ?) "
                "ON CONFLICT(id) DO UPDATE SET json = excluded.json",
                (incident.id, _encode(incident)),
            )

    def list(self) -> list[Incident]:
        """Return all known incidents ordered by detection time."""
        rows = self._conn.execute(
            "SELECT json FROM incidents ORDER BY json_extract(json, '$.detected_at')"
        ).fetchall()
        return [_decode(row[0]) for row in rows]

    def set_trust(self, level: str) -> None:
        """Persist the global trust level."""
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('trust_level', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (level,),
            )

    def get_trust(self) -> str:
        """Return the stored global trust level, defaulting to A4."""
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'trust_level'").fetchone()
        return row[0] if row else "A4"

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()


class SqliteAuditSink:
    """Append-only sqlite sink for the hash-chained audit log."""

    def __init__(self, store: SqliteStateStore) -> None:
        self._store = store

    def append(self, entry: AuditEntry) -> None:
        """Persist one audit entry in order."""
        with self._store._conn:
            self._store._conn.execute(
                """
                INSERT INTO audit (seq, ts, incident_id, kind, actor, payload, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.seq,
                    entry.ts,
                    entry.incident_id,
                    entry.kind,
                    entry.actor,
                    json.dumps(entry.payload, sort_keys=True, separators=(",", ":")),
                    entry.prev_hash,
                    entry.hash,
                ),
            )


def _encode(incident: Incident) -> str:
    """Serialize an incident to JSON with enum/datetime handling."""
    payload: dict[str, Any] = asdict(incident)
    payload["status"] = incident.status.value
    payload["detected_at"] = incident.detected_at.isoformat()
    payload["resolved_at"] = incident.resolved_at.isoformat() if incident.resolved_at else None
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _decode(raw: str) -> Incident:
    """Deserialize JSON back into an Incident dataclass."""
    payload = json.loads(raw)
    resolved_raw = payload.get("resolved_at")
    return Incident(
        id=payload["id"],
        source=payload["source"],
        source_ref=payload["source_ref"],
        status=IncidentStatus(payload["status"]),
        trust_level_at_open=payload["trust_level_at_open"],
        attempts=payload["attempts"],
        detected_at=datetime.fromisoformat(payload["detected_at"]),
        resolved_at=datetime.fromisoformat(resolved_raw) if resolved_raw else None,
        context=payload.get("context", {}),
        external_refs=payload.get("external_refs", {}),
    )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""
