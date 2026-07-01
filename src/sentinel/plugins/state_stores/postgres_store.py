"""Skeleton state store backed by PostgreSQL."""

from __future__ import annotations

from sentinel.core.incident import Incident
from sentinel.interfaces.state_store import StateStore


class PostgresStateStore(StateStore):
    """Mirror SqliteStateStore behavior on a Postgres database."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def get(self, incident_id: str) -> Incident | None:
        """Return one incident by id, or None if unknown."""
        raise NotImplementedError(
            "install psycopg (extras: postgres) and implement the same "
            "schema as sqlite_store using SQL"
        )

    def put(self, incident: Incident) -> None:
        """Upsert an incident by id."""
        raise NotImplementedError(
            "install psycopg (extras: postgres) and implement the same "
            "schema as sqlite_store using SQL"
        )

    def list(self) -> list[Incident]:
        """Return all known incidents."""
        raise NotImplementedError(
            "install psycopg (extras: postgres) and implement the same "
            "schema as sqlite_store using SQL"
        )

    def set_trust(self, level: str) -> None:
        """Persist the global trust level."""
        raise NotImplementedError(
            "install psycopg (extras: postgres) and implement the same "
            "schema as sqlite_store using SQL"
        )

    def get_trust(self) -> str:
        """Return the stored global trust level."""
        raise NotImplementedError(
            "install psycopg (extras: postgres) and implement the same "
            "schema as sqlite_store using SQL"
        )
