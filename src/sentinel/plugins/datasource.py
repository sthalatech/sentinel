"""DataSource abstraction shared by the data-reconciliation loop.

The reconciliation detector, verifier, and the ``reconcile_table_write``
remediation backend all need to read (and, for the backend, write) a target
table as ``{row_id: comparable-value}``. Keeping that behind a small Protocol
means the loop can later be pointed at Postgres, an HTTP API, or anything else
by supplying a different concrete ``DataSource`` — without touching the
detector, verifier, or tool handler. Today only one concrete implementation is
needed: ``SqliteTableSource``, which reads a named table via a configurable key
column and hashes the remaining columns into the comparable value. It works
against a plain ``sqlite3`` connection (no new dependency).

Scope: ``write_row`` only supports single-non-key-column tables — the
``expected`` value it writes is verbatim only for one column (a hash otherwise),
so multi-column reconciliation is refused until an explicit value mapping lands.
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Protocol


class DataSource(Protocol):
    """Extension point for whatever real system a target points at later."""

    def snapshot(self) -> dict[str, str]:
        """Return ``{row_id: comparable-value-or-hash}`` for one target."""
        ...

    def write_row(self, row_id: str, expected: str) -> int:
        """Reconcile one row; return the number of rows actually updated."""
        ...


def _hash_row(columns: dict[str, object]) -> str:
    """Return a stable short hash of a row's column->value mapping.

    The hash is order-independent (keys are sorted) so two rows with the same
    column values compare equal regardless of dict iteration order. Used as the
    comparable value when the source has more than one non-key column; a single
    non-key column is used verbatim so expected/actual diffs stay readable.
    """
    blob = ",".join(f"{k}={columns[k]!r}" for k in sorted(columns))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


class SqliteTableSource:
    """Read (and reconcile-write) one table from a sqlite database as a DataSource.

    ``snapshot()`` returns ``{key_value: comparable}`` for every row, where the
    comparable value is either the sole non-key column verbatim or a stable hash
    of all non-key columns. ``write_row()`` updates exactly one row's non-key
    columns from a ``expected`` value previously produced by ``snapshot()``.

    Only ``sqlite3`` is used — no new dependency, works against ``:memory:`` and
    temp files alike, so the loop is exercisable in CI without live infra.
    """

    def __init__(self, connection: sqlite3.Connection, table: str, key_column: str) -> None:
        self._conn = connection
        self._table = self._validate_identifier(table)
        self._key_column = self._validate_identifier(key_column)

    @staticmethod
    def _validate_identifier(name: str) -> str:
        """Fail closed on any identifier that is not a bare SQL identifier.

        Table/column names are interpolated into SQL (sqlite has no server-side
        parameter binding for identifiers), so reject anything that is not a
        simple ``[A-Za-z_][A-Za-z0-9_]*`` token. This is the fail-closed guard
        that keeps the reconcile backend from ever executing arbitrary SQL.
        """
        if not name or not name.replace("_", "").isalnum() or name[0].isdigit():
            raise ValueError(f"unsafe SQL identifier: {name!r}")
        return name

    def snapshot(self) -> dict[str, str]:
        """Return ``{key_value: comparable}`` for every row in the table."""
        cols = self._non_key_columns()
        select = ", ".join(cols)
        rows = self._conn.execute(
            f"SELECT {self._key_column}, {select} FROM {self._table}"
        ).fetchall()
        out: dict[str, str] = {}
        for row in rows:
            key = str(row[0])
            values = dict(zip(cols, row[1:], strict=True))
            out[key] = values[cols[0]] if len(cols) == 1 else _hash_row(values)
        return out

    def _non_key_columns(self) -> list[str]:
        """Return the table's non-key column names, fail closed if none exist."""
        info = self._conn.execute(f"PRAGMA table_info({self._table})").fetchall()
        cols = [r[1] for r in info if r[1] != self._key_column]
        if not cols:
            raise ValueError(f"{self._table!r} has no non-key columns to reconcile")
        return cols

    def write_row(self, row_id: str, expected: str) -> int:
        """Reconcile exactly one row: set its non-key column from ``expected``.

        ``expected`` is the comparable value produced by a source ``snapshot()``.
        For a single non-key column it is written verbatim. For multiple non-key
        columns a bare hash is not reversible, so the write is refused (fail
        closed) — multi-column reconciliation must extend this with an explicit
        value mapping, which is out of scope for the single-row idempotent fix.

        Returns the number of rows actually updated (0 if ``row_id`` does not
        exist — a no-op, not an error). A live trial showed a real model can
        hallucinate a row_id on its first call; returning the rowcount lets the
        handler tell the model "no row matched, try again with the right id"
        instead of falsely confirming a fix that changed nothing.
        """
        cols = self._non_key_columns()
        if len(cols) != 1:
            raise ValueError(
                "reconcile_table_write supports single non-key-column tables only; "
                f"{self._table!r} has {len(cols)}"
            )
        col = cols[0]
        with self._conn:
            cur = self._conn.execute(
                f"UPDATE {self._table} SET {col} = ? WHERE {self._key_column} = ?",
                (expected, row_id),
            )
            return int(cur.rowcount or 0)
