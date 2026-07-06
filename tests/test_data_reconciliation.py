"""End-to-end tests for the data-reconciliation loop: detector -> reconcile -> verify.

Uses temp sqlite files with deliberately seeded mismatches — the project's own
zero-required-infra default, not a live-infra exception. Covers: a real
mismatch is detected with correct row-level context, no false positive when in
sync, stable incident.id across repeated detect() calls, the bounded/truncated
case, reconcile_table_write actually fixes a row when called with valid args
and refuses anything malformed, and an end-to-end test proving the loop closes.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import pytest

from sentinel.plugins.datasource import SqliteTableSource
from sentinel.plugins.detectors.data_reconciliation import (
    MAX_EMBEDDED_MISMATCHES,
    DataReconciliationDetector,
    ReconciliationTarget,
    load_targets_from_config,
    target_incident_id,
)
from sentinel.plugins.remediators.hermes_mcp_tools import (
    default_specs,
    reconcile_table_write_backend,
)
from sentinel.plugins.secret_providers.env_provider import EnvSecretProvider
from sentinel.plugins.verifiers.data_reconciliation import (
    DataReconciliationVerifier,
)


def _make_table(path: str, table: str, rows: dict[str, str]) -> sqlite3.Connection:
    """Create a single-column reconcilable table at ``path`` seeded with rows."""
    conn = sqlite3.connect(path, check_same_thread=False)
    with conn:
        conn.execute(f"CREATE TABLE {table} (id TEXT PRIMARY KEY, status TEXT)")
        for k, v in rows.items():
            conn.execute(f"INSERT INTO {table} (id, status) VALUES (?, ?)", (k, v))
    return conn


def _target(
    source_conn: sqlite3.Connection,
    target_conn: sqlite3.Connection,
    *,
    name: str = "orders_vs_warehouse",
    table: str = "orders",
    key_column: str = "id",
) -> ReconciliationTarget:
    """Build a ReconciliationTarget over two connections with a shared table."""
    return ReconciliationTarget(
        name=name,
        source=SqliteTableSource(source_conn, table, key_column),
        target=SqliteTableSource(target_conn, table, key_column),
        table=table,
        key_column=key_column,
    )


# ---------------------------------------------------------------------------
# Part A: SqliteTableSource
# ---------------------------------------------------------------------------


def test_snapshot_single_non_key_column_uses_value_verbatim() -> None:
    """A single non-key column's value is the comparable (no hash), so the
    detector can embed a readable ``expected`` and the remediator can write it."""
    conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "pending"})
    src = SqliteTableSource(conn, "orders", "id")
    assert src.snapshot() == {"o1": "shipped", "o2": "pending"}
    conn.close()


def test_snapshot_multiple_non_key_columns_hashes_stably() -> None:
    """Multiple non-key columns collapse to an order-independent stable hash."""
    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE t (id TEXT PRIMARY KEY, a TEXT, b TEXT)")
        conn.execute("INSERT INTO t (id, a, b) VALUES ('x', '1', '2')")
    src = SqliteTableSource(conn, "t", "id")
    snap = src.snapshot()
    assert set(snap) == {"x"}
    # Same data inserted in a different column order must hash equal.
    conn2 = sqlite3.connect(":memory:")
    with conn2:
        conn2.execute("CREATE TABLE t (id TEXT PRIMARY KEY, b TEXT, a TEXT)")
        conn2.execute("INSERT INTO t (id, b, a) VALUES ('x', '2', '1')")
    src2 = SqliteTableSource(conn2, "t", "id")
    assert src2.snapshot() == snap
    conn.close()
    conn2.close()


def test_source_rejects_unsafe_identifiers() -> None:
    """Identifiers that are not bare SQL tokens are refused (fail closed)."""
    conn = sqlite3.connect(":memory:")
    with pytest.raises(ValueError):
        SqliteTableSource(conn, "orders; DROP TABLE x", "id")
    with pytest.raises(ValueError):
        SqliteTableSource(conn, "orders", "id; --")
    conn.close()


# ---------------------------------------------------------------------------
# Part B: DataReconciliationDetector
# ---------------------------------------------------------------------------


def test_detect_finds_mismatch_with_row_level_context() -> None:
    """A real mismatch is detected with {table, row_id, expected} context."""
    src_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "pending"})
    tgt_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "paid"})
    det = DataReconciliationDetector([_target(src_conn, tgt_conn)])
    incidents = det.detect()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.source == "data_reconciliation"
    assert inc.source_ref == "orders_vs_warehouse"
    assert inc.context["table"] == "orders"
    assert inc.context["key_column"] == "id"
    assert inc.context["total_mismatch_count"] == 1
    assert inc.context["mismatches"] == [{"table": "orders", "row_id": "o2", "expected": "pending"}]
    src_conn.close()
    tgt_conn.close()


def test_detect_no_false_positive_when_in_sync() -> None:
    """Identical snapshots produce no incident."""
    src_conn = _make_table(":memory:", "orders", {"o1": "shipped"})
    tgt_conn = _make_table(":memory:", "orders", {"o1": "shipped"})
    det = DataReconciliationDetector([_target(src_conn, tgt_conn)])
    assert det.detect() == []
    src_conn.close()
    tgt_conn.close()


def test_detect_emits_one_incident_per_target_not_per_row() -> None:
    """Many mismatched rows in one target yield ONE incident, not many."""
    src_conn = _make_table(":memory:", "orders", {"o1": "a", "o2": "b", "o3": "c"})
    tgt_conn = _make_table(":memory:", "orders", {"o1": "X", "o2": "Y", "o3": "Z"})
    det = DataReconciliationDetector([_target(src_conn, tgt_conn)])
    incidents = det.detect()
    assert len(incidents) == 1
    assert incidents[0].context["total_mismatch_count"] == 3
    assert len(incidents[0].context["mismatches"]) == 3
    src_conn.close()
    tgt_conn.close()


def test_detect_incident_id_is_deterministic_across_runs() -> None:
    """An ongoing, still-unresolved mismatch keeps the SAME incident.id on
    every detect() tick, so the state store upserts rather than spawns new."""
    src_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "pending"})
    tgt_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "paid"})
    det = DataReconciliationDetector([_target(src_conn, tgt_conn)])
    first = det.detect()
    second = det.detect()
    assert len(first) == 1 and len(second) == 1
    assert first[0].id == second[0].id
    assert first[0].id == target_incident_id("orders_vs_warehouse")
    # Different target names produce different ids.
    assert target_incident_id("other") != first[0].id
    src_conn.close()
    tgt_conn.close()


def test_detect_bounded_mismatch_list_with_total_count() -> None:
    """A huge table embeds at most MAX_EMBEDDED_MISMATCHES rows; the full
    count is carried in total_mismatch_count so the payload can't blow up."""
    big = {f"o{i}": f"v{i}" for i in range(MAX_EMBEDDED_MISMATCHES + 20)}
    wrong = {k: f"BAD-{i}" for i, k in enumerate(big)}
    src_conn = _make_table(":memory:", "orders", big)
    tgt_conn = _make_table(":memory:", "orders", wrong)
    det = DataReconciliationDetector([_target(src_conn, tgt_conn)])
    inc = det.detect()[0]
    assert inc.context["total_mismatch_count"] == MAX_EMBEDDED_MISMATCHES + 20
    assert len(inc.context["mismatches"]) == MAX_EMBEDDED_MISMATCHES
    src_conn.close()
    tgt_conn.close()


def test_load_targets_from_config_resolves_env_var_names() -> None:
    """The YAML references env-var NAMES (no secrets in repo); the loader
    resolves the actual paths at runtime via the SecretProvider."""
    with tempfile.TemporaryDirectory() as d:
        src_path = Path(d) / "source.db"
        tgt_path = Path(d) / "target.db"
        _make_table(str(src_path), "orders", {"o1": "shipped"}).close()
        _make_table(str(tgt_path), "orders", {"o1": "paid"}).close()
        cfg = Path(d) / "targets.yaml"
        cfg.write_text(
            "targets:\n"
            "  - name: orders_vs_warehouse\n"
            "    table: orders\n"
            "    key_column: id\n"
            "    source_db_path_env: SRC_DB\n"
            "    target_db_path_env: TGT_DB\n",
            encoding="utf-8",
        )
        env = {"SRC_DB": str(src_path), "TGT_DB": str(tgt_path)}
        targets = load_targets_from_config(str(cfg), EnvSecretProvider(environ=env))
        assert len(targets) == 1
        assert targets[0].name == "orders_vs_warehouse"
        assert targets[0].table == "orders"


def test_load_targets_from_config_requires_secret_present() -> None:
    """A referenced env var that is missing fails closed (KeyError), not silently."""
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "targets.yaml"
        cfg.write_text(
            "targets:\n"
            "  - name: t\n"
            "    table: orders\n"
            "    key_column: id\n"
            "    source_db_path_env: MISSING\n"
            "    target_db_path_env: ALSO_MISSING\n",
            encoding="utf-8",
        )
        with pytest.raises(KeyError):
            load_targets_from_config(str(cfg), EnvSecretProvider(environ={}))


# ---------------------------------------------------------------------------
# Part C: reconcile_table_write backend
# ---------------------------------------------------------------------------


def test_reconcile_backend_writes_valid_row() -> None:
    """reconcile_table_write writes ``expected`` to the target row/key."""
    src_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "pending"})
    tgt_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "paid"})
    target = _target(src_conn, tgt_conn)
    handler = reconcile_table_write_backend({"orders": target.target})
    out = handler(table="orders", row_id="o2", expected="pending")
    assert "reconciled" in out
    assert tgt_conn.execute("SELECT status FROM orders WHERE id='o2'").fetchone()[0] == "pending"
    src_conn.close()
    tgt_conn.close()


def test_reconcile_backend_refuses_unknown_table() -> None:
    """The handler refuses any table not registered (fail closed; no arbitrary write)."""
    tgt_conn = _make_table(":memory:", "orders", {"o1": "x"})
    handler = reconcile_table_write_backend({"orders": SqliteTableSource(tgt_conn, "orders", "id")})
    out = handler(table="secret_table", row_id="o1", expected="x")
    assert "refused" in out
    tgt_conn.close()


def test_reconcile_backend_refuses_malformed_args() -> None:
    """Missing required kwargs surfaces a clear failure rather than executing."""
    tgt_conn = _make_table(":memory:", "orders", {"o1": "x"})
    handler = reconcile_table_write_backend({"orders": SqliteTableSource(tgt_conn, "orders", "id")})
    out = handler(table="orders")  # type: ignore[call-arg]  # missing row_id/expected
    assert "refused" in out  # malformed args are refused at the handler boundary
    # The row is untouched.
    assert tgt_conn.execute("SELECT status FROM orders WHERE id='o1'").fetchone()[0] == "x"
    tgt_conn.close()


def test_reconcile_backend_has_no_shell_or_sql_surface() -> None:
    """The default spec admits ONLY {table, row_id, expected} — no command/SQL."""
    schema = default_specs["reconcile_table_write"].schema
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"table", "row_id", "expected"}
    assert set(schema["required"]) == {"table", "row_id", "expected"}


# ---------------------------------------------------------------------------
# Part D: DataReconciliationVerifier
# ---------------------------------------------------------------------------


def test_verifier_false_while_mismatched_true_after_fix() -> None:
    """verify() returns False while a mismatch remains, True once it's gone."""
    src_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "pending"})
    tgt_conn = _make_table(":memory:", "orders", {"o1": "shipped", "o2": "paid"})
    target = _target(src_conn, tgt_conn)
    det = DataReconciliationDetector([target])
    ver = DataReconciliationVerifier([target])
    inc = det.detect()[0]
    assert ver.verify(inc) is False
    # Fix the row via the same backend.
    reconcile_table_write_backend({"orders": target.target})(
        table="orders", row_id="o2", expected="pending"
    )
    assert ver.verify(inc) is True
    src_conn.close()
    tgt_conn.close()


def test_verifier_fail_closed_for_unknown_target() -> None:
    """An incident whose target_name is unknown to the verifier fails closed."""
    from datetime import UTC, datetime

    from sentinel.core.incident import Incident, IncidentStatus

    inc = Incident(
        id="x",
        source="data_reconciliation",
        source_ref="ghost",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=0,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={"target_name": "does_not_exist"},
    )
    assert DataReconciliationVerifier(targets=[]).verify(inc) is False


# ---------------------------------------------------------------------------
# End-to-end: the loop actually closes
# ---------------------------------------------------------------------------


def _enforcer_allowing(actions: list[str]) -> Any:
    """Build a fixed Enforcer stub allowing exactly ``actions`` for any trust."""
    from tests.test_hermes_remediator import (  # noqa: PLC0415
        _config_docker,
        _docker_ok,
        _FixedEnforcer,
        _FixedTrust,
    )

    return _FixedEnforcer(actions), _FixedTrust("A4"), _docker_ok, _config_docker


def test_end_to_end_detect_remediate_verify_closes_the_loop(tmp_path) -> None:
    """End-to-end through HermesRemediator.remediate(), NOT the backend directly.

    Seed a mismatch -> detect() -> incident -> HermesRemediator.remediate() with
    a fake Hermes client whose run() DISPATCHES to the registered handler (the
    way a real Hermes tool call would) -> verify() returns True -> fresh detect()
    empty. This is the test that proves the loop closes through the real wiring
    path (build_spec_set -> wire_backend -> register_action_tools -> dispatch),
    not just that each component works in isolation.
    """
    from sentinel.plugins.remediators.hermes import HermesRemediator
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set
    from tests.test_hermes_remediator import (  # noqa: PLC0415
        FakeClient,
        _RecordingRegistrar,
    )

    src_path = str(tmp_path / "source.db")
    tgt_path = str(tmp_path / "target.db")
    src_conn = _make_table(src_path, "orders", {"o1": "shipped", "o2": "pending", "o3": "closed"})
    tgt_conn = _make_table(tgt_path, "orders", {"o1": "shipped", "o2": "paid", "o3": "open"})

    target = _target(src_conn, tgt_conn)
    detector = DataReconciliationDetector([target])
    verifier = DataReconciliationVerifier([target])

    # 1. Detect: a mismatch exists.
    incidents = detector.detect()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.context["total_mismatch_count"] == 2

    # 2. Verify before remediation: still mismatched.
    assert verifier.verify(inc) is False

    # 3. Remediate THROUGH THE REMEDIATOR (not the backend directly): build the
    #    real wired spec set (build_spec_set -> wire_backend), register it with
    #    the remediator, and have the fake client dispatch one reconcile_table_write
    #    tool call per embedded mismatch to the registered handler.
    reg = _RecordingRegistrar()
    client = FakeClient(registrar=reg)
    enforcer, trust, docker_ok, config_docker = _enforcer_allowing(["reconcile_table_write"])
    client.tool_calls_to_simulate = [
        {"name": "reconcile_table_write", "arguments": m} for m in inc.context["mismatches"]
    ]
    remediator = HermesRemediator(
        lambda: client,
        enforcer,
        trust,
        docker_check=docker_ok,
        config_loader=config_docker,
        spec_set=build_spec_set({"orders": target.target}),
        registrar=reg,
    )
    result = remediator.remediate(inc, enforcer)
    assert result.success is True, result.summary
    assert result.breach is False

    # 4. The dispatching fake actually invoked the wired handler for each
    #    mismatch (proving wire_backend was called on the real path): the rows
    #    in the target DB now match the source.
    assert verifier.verify(inc) is True

    # 5. And a fresh detect() now finds nothing.
    assert detector.detect() == []
    src_conn.close()
    tgt_conn.close()


def test_end_to_end_without_wiring_the_loop_does_not_close(tmp_path) -> None:
    """Regression for the gap this work closes: if wire_backend() is NEVER called
    (the spec set is default_specs with the _refuse placeholder), the loop must
    NOT close. The dispatching fake runs the placeholder handler, the row stays
    un-fixed, and verify() returns False. A fake that returned a canned success
    regardless of the handler could not catch this — which is how the missing
    wire_backend call got past the last report."""
    from sentinel.plugins.remediators.hermes import HermesRemediator
    from sentinel.plugins.remediators.hermes_mcp_tools import default_specs
    from tests.test_hermes_remediator import (  # noqa: PLC0415
        FakeClient,
        _RecordingRegistrar,
    )

    src_path = str(tmp_path / "source.db")
    tgt_path = str(tmp_path / "target.db")
    src_conn = _make_table(src_path, "orders", {"o1": "shipped", "o2": "pending"})
    tgt_conn = _make_table(tgt_path, "orders", {"o1": "shipped", "o2": "paid"})

    target = _target(src_conn, tgt_conn)
    detector = DataReconciliationDetector([target])
    verifier = DataReconciliationVerifier([target])
    inc = detector.detect()[0]
    assert verifier.verify(inc) is False

    reg = _RecordingRegistrar()
    client = FakeClient(registrar=reg)
    enforcer, trust, docker_ok, config_docker = _enforcer_allowing(["reconcile_table_write"])
    client.tool_calls_to_simulate = [
        {"name": "reconcile_table_write", "arguments": m} for m in inc.context["mismatches"]
    ]
    # default_specs (NOT build_spec_set): the reconcile handler is the _refuse
    # placeholder, exactly the pre-fix wiring state.
    remediator = HermesRemediator(
        lambda: client,
        enforcer,
        trust,
        docker_check=docker_ok,
        config_loader=config_docker,
        spec_set=default_specs,
        registrar=reg,
    )
    result = remediator.remediate(inc, enforcer)
    # The run itself succeeds (the placeholder returned a string, not a breach),
    # but the row was NOT reconciled, so verification must still fail.
    assert result.success is True
    assert verifier.verify(inc) is False  # loop did NOT close — gap is visible
    # And the placeholder handler's refusal shows up in the recorded tool result,
    # proving the dispatching fake actually called the (un-wired) handler rather
    # than pretending success.
    convo = json.loads(inc.external_refs["conversation"])
    tool_contents = [m["content"] for m in convo if m.get("role") == "tool"]
    assert any("refused" in c for c in tool_contents), tool_contents
    src_conn.close()
    tgt_conn.close()


# ---------------------------------------------------------------------------
# Live-trial regression: a real model can hallucinate a row_id on its first
# call. write_row must report that nothing changed (0 rows) so the handler tells
# the model "no row matched" instead of falsely confirming a fix.
# ---------------------------------------------------------------------------


def test_reconcile_handler_reports_no_op_when_row_id_does_not_exist(tmp_path) -> None:
    """A hallucinated row_id updates 0 rows; the handler must say so, not
    'reconciled'. Otherwise the model believes the fix landed and stops."""
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO orders VALUES ('o1','paid')")
    conn.commit()
    spec = build_spec_set({"orders": SqliteTableSource(conn, "orders", "id")})
    # Real dispatch shape: one positional dict.
    out = spec["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "nope", "expected": "shipped"}
    )
    assert "no row matched" in out, out
    # And the real row is untouched.
    assert conn.execute("SELECT status FROM orders WHERE id='o1'").fetchone()[0] == "paid"
    conn.close()


def test_write_row_returns_rowcount_for_real_fix(tmp_path) -> None:
    """write_row returns the number of rows actually updated (1 for a real fix)."""
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO orders VALUES ('o1','paid')")
    conn.commit()
    src = SqliteTableSource(conn, "orders", "id")
    assert src.write_row("o1", "shipped") == 1
    assert src.write_row("missing", "shipped") == 0
    conn.close()


# ---------------------------------------------------------------------------
# Second-live-trial finding A: the real HermesAIAgentClient runs run_conversation
# (and therefore the reconcile tool handler) in a WORKER thread for the
# per-incident timeout. A sqlite3 connection is bound to its creating thread, so
# a handler running in the worker raises "SQLite objects created in a thread can
# only be used in that same thread". Callers must open connections with
# check_same_thread=False. This test pins that cross-thread write works.
# ---------------------------------------------------------------------------


def test_sqlite_source_write_works_across_threads(tmp_path) -> None:
    """A check_same_thread=False connection lets the reconcile handler write
    from a worker thread — the shape the real Hermes client runs handlers in."""
    import threading

    conn = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO orders VALUES ('o2','paid')")
    conn.commit()
    src = SqliteTableSource(conn, "orders", "id")
    err: list[str] = []

    def _worker() -> None:
        try:
            changed = src.write_row("o2", "shipped")
            assert changed == 1
        except Exception as exc:  # noqa: BLE001
            err.append(repr(exc))

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    assert not err, err
    assert conn.execute("SELECT status FROM orders WHERE id='o2'").fetchone()[0] == "shipped"
    conn.close()
