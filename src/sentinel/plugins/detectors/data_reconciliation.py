"""Detector that reconciles two data sources row-by-row and emits one incident
per mismatched target.

Each target is a ``(source, target, table, key_column)`` triple: ``source`` is
the canonical/expected ``DataSource`` and ``target`` is the live ``DataSource``
being reconciled. ``detect()`` snapshots both, compares row-by-row, and emits
ONE incident per target with any mismatches — never one incident per row — so
the engine opens a single remediation conversation per target rather than a
flood. The incident's ``context`` carries a bounded list of per-row mismatches
shaped exactly like ``reconcile_table_write``'s schema (``{table, row_id,
expected}``) so the remediator can iterate and fix them with the tool that
already exists.

Incident ids are DETERMINISTIC per target (a stable hash of
``data_reconciliation:<target_name>``), so an ongoing, still-unresolved mismatch
maps to the same incident id on every ``detect()`` tick — the state store
updates the existing incident instead of spawning a new one each run.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentinel.core.incident import Incident, IncidentStatus
from sentinel.interfaces.secret_provider import SecretProvider
from sentinel.plugins.datasource import DataSource, SqliteTableSource

#: Max per-row mismatches embedded directly in the incident context. A huge
#: table must not blow up the incident payload; the full count is carried in
#: ``total_mismatch_count`` so the loop still knows the scope.
MAX_EMBEDDED_MISMATCHES = 50


@dataclass(frozen=True)
class ReconciliationTarget:
    """One named reconciliation check: expected ``source`` vs live ``target``."""

    name: str
    source: DataSource
    target: DataSource
    table: str
    key_column: str


def target_incident_id(name: str) -> str:
    """Return a deterministic incident id for a reconciliation target name.

    Stable across runs (a hash of ``data_reconciliation:<name>``) so a still-
    unresolved mismatch keeps the same incident id on every detect() tick and
    the state store upserts rather than spawns duplicates.
    """
    digest = hashlib.sha256(f"data_reconciliation:{name}".encode()).hexdigest()[:16]
    return f"data_recon-{digest}"


def _mismatches(source: DataSource, target: DataSource) -> list[dict[str, str]]:
    """Return per-row mismatches ``{row_id, expected}`` where target differs.

    A row present in the source but missing from the target is a mismatch whose
    ``expected`` is the source value (the remediator writes it). A row present
    only in the target (extra, uncanonical row) is reported with an empty
    ``expected`` — the loop surfaces it but the narrow reconcile tool does not
    delete, matching its no-shell contract.
    """
    expected = source.snapshot()
    actual = target.snapshot()
    out: list[dict[str, str]] = []
    for row_id, want in expected.items():
        if actual.get(row_id) != want:
            out.append({"row_id": row_id, "expected": want})
    for row_id in actual.keys() - expected.keys():
        out.append({"row_id": row_id, "expected": ""})
    return out


class DataReconciliationDetector:
    """Compare a list of reconciliation targets and emit one incident per mismatch."""

    def __init__(self, targets: list[ReconciliationTarget]) -> None:
        self._targets = list(targets)

    def detect(self) -> list[Incident]:
        """Return one incident per target whose source/target snapshots differ."""
        incidents: list[Incident] = []
        for target in self._targets:
            mismatches = _mismatches(target.source, target.target)
            if not mismatches:
                continue
            incidents.append(self._incident_for(target, mismatches))
        return incidents

    def _incident_for(
        self, target: ReconciliationTarget, mismatches: list[dict[str, str]]
    ) -> Incident:
        """Build the single incident for one mismatched target (bounded context)."""
        embedded = mismatches[:MAX_EMBEDDED_MISMATCHES]
        rows = [
            {"table": target.table, "row_id": m["row_id"], "expected": m["expected"]}
            for m in embedded
        ]
        now = datetime.now(UTC)
        return Incident(
            id=target_incident_id(target.name),
            source="data_reconciliation",
            source_ref=target.name,
            status=IncidentStatus.DETECTED,
            trust_level_at_open="A4",
            attempts=0,
            detected_at=now,
            resolved_at=None,
            context={
                "target_name": target.name,
                "table": target.table,
                "key_column": target.key_column,
                "mismatches": rows,
                "total_mismatch_count": len(mismatches),
            },
            external_refs={},
        )


def _open_sqlite(path: str) -> Any:
    """Open a sqlite3 connection; imported here so tests can monkeypatch it."""
    import sqlite3

    return sqlite3.connect(path, check_same_thread=False)


def load_targets_from_config(
    config_path: str, secrets: SecretProvider
) -> list[ReconciliationTarget]:
    """Load reconciliation targets from a YAML config (no secrets in the repo).

    The YAML references connection details by ENV-VARIABLE NAME; the raw
    credential is never checked into the repo. Example shape (see
    ``governance/reconciliation_targets.example.yaml``)::

        targets:
          - name: orders_vs_warehouse
            table: orders
            key_column: order_id
            source_db_path_env: SOURCE_DB_PATH
            target_db_path_env: TARGET_DB_PATH

    This keeps the no-secrets-in-repo pattern: only env-var *names* are stored;
    the actual paths/credentials are resolved at runtime via ``secrets.get``.
    """
    import pathlib

    import yaml

    data = yaml.safe_load(pathlib.Path(config_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise ValueError("reconciliation config must be a mapping with a 'targets' list")
    targets: list[ReconciliationTarget] = []
    for entry in data["targets"]:
        targets.append(_target_from_entry(entry, secrets))
    return targets


def _target_from_entry(entry: dict[str, Any], secrets: SecretProvider) -> ReconciliationTarget:
    """Build one ReconciliationTarget from a parsed config entry."""
    name = entry["name"]
    table = entry["table"]
    key_column = entry["key_column"]
    source_path = secrets.get(entry["source_db_path_env"])
    target_path = secrets.get(entry["target_db_path_env"])
    source = SqliteTableSource(_open_sqlite(source_path), table, key_column)
    target = SqliteTableSource(_open_sqlite(target_path), table, key_column)
    return ReconciliationTarget(
        name=name, source=source, target=target, table=table, key_column=key_column
    )
