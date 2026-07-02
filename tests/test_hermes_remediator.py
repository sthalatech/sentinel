"""Tests for HermesRemediator (fake/injected client; no live Hermes in CI).

The fakes here are deliberately NOT shaped to the implementation's assumptions.
``FakeClient.list_tools`` returns whatever Hermes's real
``model_tools.get_tool_definitions`` would register for the given toolsets
against a real per-action tool registry built via ``hermes_mcp_tools`` — so a
denied action's underlying operation is genuinely unreachable, not merely
absent from a hand-picked list.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinel.core.incident import Incident, IncidentStatus
from sentinel.core.trust import TrustStore
from sentinel.interfaces.enforcer import Enforcer
from sentinel.plugins.remediators.hermes import (
    DEFAULT_ACTIONS,
    HermesRemediator,
    HermesRunResult,
)
from sentinel.plugins.remediators.hermes_mcp_tools import (
    default_specs,
    register_action_tools,
    toolset_for,
    toolsets_for_actions,
)


class _RecordingRegistrar:
    """Minimal ToolRegistrar recording registrations in an in-memory registry.

    Mirrors the shape of Hermes's ``tools.registry.registry.register``: a tool
    name is registered under a toolset with a schema + handler. Crucially it
    KEEPS the handler (Hermes's real registry does too — it dispatches to it on
    tool calls), so a fake client can simulate real tool dispatch: the model
    calls a tool, the registry routes the call to the registered handler. A fake
    that throws the handler away cannot catch a "handler never wired" gap, which
    is exactly how the missing ``wire_backend`` call got past the last report.
    """

    def __init__(self) -> None:
        self._by_toolset: dict[str, list[str]] = {}
        self._handlers: dict[str, Any] = {}

    def register(
        self,
        name: str,
        toolset: str,
        schema: dict[str, Any],
        handler: Any,
        description: str = "",
        **_kwargs: Any,
    ) -> None:
        """Record one tool under a toolset and KEEP its handler (dispatch shape)."""
        del schema, description
        self._by_toolset.setdefault(toolset, [])
        if name not in self._by_toolset[toolset]:
            self._by_toolset[toolset].append(name)
        self._handlers[name] = handler

    def tools_for(self, enabled_toolsets: list[str]) -> list[str]:
        """Return tool names for the enabled toolsets (registry-level filter)."""
        out: list[str] = []
        for ts in enabled_toolsets:
            out.extend(self._by_toolset.get(ts, []))
        return out

    def handler_for(self, name: str) -> Any:
        """Return the registered handler for a tool name (None if unregistered)."""
        return self._handlers.get(name)

    def invoke(self, name: str, arguments: dict[str, Any]) -> str:
        """Dispatch a tool call to its registered handler the way Hermes does.

        If no handler is registered (or a placeholder ``_refuse`` handler is),
        the call returns the handler's refusal string rather than executing —
        so a handler-wiring gap shows up as an un-fixed row, not a silent pass.
        """
        handler = self._handlers.get(name)
        if handler is None:
            return f"{name}: no handler registered"
        return str(handler(**arguments))


@dataclass
class FakeClient:
    """Records calls; ``list_tools`` reflects the real per-action registry.

    Optionally simulates REAL tool dispatch: if ``tool_calls_to_simulate`` is
    set, ``run`` dispatches each ``{name, arguments}`` to the registrar's
    registered handler (gated by ``tool_allowlist``) and appends the OpenAI-shaped
    assistant/tool messages the real Hermes run would produce — so the post-run
    audit AND any verifier observe the actual handler outcome, not a canned
    string. This is what lets a test catch a "handler never wired" gap: if
    ``wire_backend`` was never called, the registered handler is the fail-closed
    ``_refuse`` placeholder, the row stays un-fixed, and the verifier returns
    False. A fake that returns a canned ``run_result`` regardless of the handler
    cannot catch that class of gap.
    """

    registrar: _RecordingRegistrar
    run_result: HermesRunResult = field(
        default_factory=lambda: HermesRunResult(final_response="fixed", messages=[])
    )
    calls: list[dict[str, Any]] = field(default_factory=list)
    #: Optional tool calls the simulated "model" makes during run(); each entry
    #: is {"name": str, "arguments": dict}. Dispatched to the real handler.
    tool_calls_to_simulate: list[dict[str, Any]] = field(default_factory=list)

    def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
        """Return the real tool names registered for the given toolsets."""
        return self.registrar.tools_for(enabled_toolsets)

    def run(
        self,
        message: str,
        *,
        enabled_toolsets: list[str],
        tool_allowlist: set[str] | None,
        skip_memory: bool,
        conversation_history: list[dict[str, Any]] | None,
    ) -> HermesRunResult:
        """Record the call and, if simulating dispatch, run the real handlers."""
        self.calls.append(
            {
                "message": message,
                "enabled_toolsets": list(enabled_toolsets),
                "tool_allowlist": set(tool_allowlist) if tool_allowlist else None,
                "skip_memory": skip_memory,
                "conversation_history": conversation_history,
            }
        )
        if not self.tool_calls_to_simulate:
            return self.run_result
        return self._run_with_dispatch(tool_allowlist)

    def _run_with_dispatch(self, tool_allowlist: set[str] | None) -> HermesRunResult:
        """Simulate a real Hermes turn that invokes tools through the registry.

        Builds the OpenAI-shaped assistant message with ``tool_calls`` and a
        ``tool`` role message per call holding the handler's real result string —
        the exact shape Hermes writes (verified in
        hermes-agent/message_sanitization.py) and that the post-run audit scans.
        A call to a tool not in ``tool_allowlist`` is recorded anyway (the audit
        flags it as a breach), matching the fail-open scenario it must catch.
        """
        allow = tool_allowlist if tool_allowlist is not None else set()
        tool_calls: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []
        for i, call in enumerate(self.tool_calls_to_simulate):
            name = call["name"]
            args = call.get("arguments", {})
            tool_calls.append(
                {
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)},
                }
            )
            result = self.registrar.invoke(name, args) if name in allow else "blocked"
            tool_results.append({"role": "tool", "tool_call_id": f"call_{i}", "content": result})
        assistant = {"role": "assistant", "content": None, "tool_calls": tool_calls}
        messages = [assistant, *tool_results]
        return HermesRunResult(final_response="remediated", messages=messages)


class _FixedEnforcer(Enforcer):
    """Enforcer stub exposing a configured allowed_actions surface."""

    def __init__(self, allowed: list[str]) -> None:
        self._allowed = allowed

    def authorize(self, action: str) -> Any:  # noqa: D401 - test stub
        """Test stub; not used by HermesRemediator."""
        del action
        return None

    def allowed_actions(self, trust_level: str) -> list[str]:
        """Return the configured allowed surface."""
        del trust_level
        return list(self._allowed)


class _FixedTrust(TrustStore):
    """TrustStore stub returning a configured level."""

    def __init__(self, level: str) -> None:
        self._level = level

    def set_trust(self, level: str) -> None:
        """Persist the global trust level."""
        self._level = level

    def get_trust(self) -> str:
        """Return the stored global trust level."""
        return self._level


def _make_incident() -> Incident:
    """Build a deterministic incident for remediator tests."""
    return Incident(
        id="inc-1",
        source="test",
        source_ref="ref-1",
        status=IncidentStatus.REMEDIATING,
        trust_level_at_open="A4",
        attempts=1,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={"disk_percent": 98},
    )


def _make_factory(client: FakeClient):
    """Return a client_factory closure capturing the fake."""

    def _factory() -> FakeClient:
        return client

    return _factory


def _docker_ok() -> bool:
    return True


def _config_docker() -> dict[str, Any]:
    return {"terminal": {"backend": "docker"}}


def _fresh_registry() -> tuple[_RecordingRegistrar, FakeClient]:
    """Build a fresh per-action registry + client (clean slate per test)."""
    reg = _RecordingRegistrar()
    register_action_tools(reg, default_specs)
    return reg, FakeClient(registrar=reg)


def test_construction_refuses_without_docker() -> None:
    """Constructing HermesRemediator without Docker raises HermesRefusedError."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    _reg, client = _fresh_registry()
    try:
        HermesRemediator(
            _make_factory(client),
            _FixedEnforcer(["restart_workflow"]),
            _FixedTrust("A4"),
            docker_check=lambda: False,
            config_loader=_config_docker,
        )
        raise AssertionError("expected HermesRefusedError when Docker is down")
    except HermesRefusedError as exc:
        assert "Docker daemon is not running" in str(exc)


def test_construction_refuses_with_non_docker_backend() -> None:
    """A non-docker terminal backend is refused (no silent degrade to local)."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    _reg, client = _fresh_registry()
    try:
        HermesRemediator(
            _make_factory(client),
            _FixedEnforcer(["restart_workflow"]),
            _FixedTrust("A4"),
            docker_check=_docker_ok,
            config_loader=lambda: {"terminal": {"backend": "local"}},
        )
        raise AssertionError("expected HermesRefusedError for local backend")
    except HermesRefusedError as exc:
        assert "terminal.backend is not 'docker'" in str(exc)


def test_adversarial_restart_allowed_rollback_denied_no_shell() -> None:
    """The user's adversarial scenario, against the per-action tool design.

    Trust level allows ``restart_workflow`` but NOT ``roll_back_deployment``.
    Both were routed through the ``terminal`` toolset under the old design,
    which handed the model a shell. Under per-action toolsets, the model's
    tool listing is exactly ``['restart_workflow']`` — no ``terminal``, no
    ``process``, no surface capable of ``kubectl rollout undo``. The denied
    action's tool is not merely absent from a curated list; its toolset was
    never enabled, so the registry cannot surface it.
    """
    reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),  # NOT roll_back_deployment
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001

    call = client.calls[0]
    enabled = call["enabled_toolsets"]
    listed = client.list_tools(enabled)
    assert enabled == [toolset_for("restart_workflow")]
    assert listed == ["restart_workflow"]
    # The shell primitive that would have enabled roll_back_deployment's op:
    assert "terminal" not in listed
    assert "process" not in listed
    assert "roll_back_deployment" not in listed
    # And the rollback toolset was never enabled, so its tool is unreachable:
    assert client.list_tools([toolset_for("roll_back_deployment")]) == ["roll_back_deployment"]
    assert toolset_for("roll_back_deployment") not in enabled


def test_a4_full_surface_lists_exactly_allowed_actions() -> None:
    """A full A4 surface lists exactly the allowed action tool names."""
    allowed = ["restart_workflow", "reconcile_table_write", "clear_cache", "retry_webhook"]
    _reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(allowed),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    listed = client.list_tools(client.calls[0]["enabled_toolsets"])
    assert set(listed) == set(allowed)


def test_tool_surface_leak_is_refused() -> None:
    """If an extra tool surfaces beyond the allow-list, remediation is refused.

    Models a real registry leak: a stray shell tool registered under the
    restart_workflow toolset. The same-vocabulary surface check refuses because
    the listing is not exactly the allowed set.
    """
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    reg, client = _fresh_registry()
    # Inject a leak: a shell tool mis-registered under the restart toolset.
    reg.register(
        name="terminal",
        toolset=toolset_for("restart_workflow"),
        schema={},
        handler=lambda **_k: "shell",
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    try:
        rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
        raise AssertionError("expected HermesRefusedError on tool-surface leak")
    except HermesRefusedError as exc:
        assert "terminal" in str(exc)


def test_missing_allowed_tool_is_refused() -> None:
    """An allowed action whose tool fails to register is refused (fail closed)."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    reg, client = _fresh_registry()
    # Sabotage: drop the restart_workflow registration so it won't surface.
    reg._by_toolset.pop(toolset_for("restart_workflow"), None)  # noqa: SLF001
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    try:
        rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
        raise AssertionError("expected HermesRefusedError for missing allowed tool")
    except HermesRefusedError as exc:
        assert "missing from Hermes listing" in str(exc)


def test_unknown_allowed_action_refused() -> None:
    """An action not in the known action set is refused before the run."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    _reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow", "delete_database"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    try:
        rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
        raise AssertionError("expected HermesRefusedError for unknown action")
    except HermesRefusedError as exc:
        assert "delete_database" in str(exc)


def test_resume_replays_conversation_history() -> None:
    """A second attempt on the same incident replays the stored history."""
    _reg, client = _fresh_registry()
    client.run_result = HermesRunResult(
        final_response="done",
        messages=[{"role": "assistant", "content": "done"}],
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    inc = _make_incident()
    rem.remediate(inc, rem._enforcer)  # noqa: SLF001
    assert "conversation" in inc.external_refs
    stored = json.loads(inc.external_refs["conversation"])
    assert stored == [{"role": "assistant", "content": "done"}]
    client.calls.clear()
    rem.remediate(inc, rem._enforcer)  # noqa: SLF001
    assert client.calls[0]["conversation_history"] == stored


def test_lockdown_runs_with_empty_toolset() -> None:
    """At A1 lockdown (no allowed actions) the run still happens with no tools."""
    _reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer([]),
        _FixedTrust("A1"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.success is True
    assert client.calls[0]["enabled_toolsets"] == []
    assert client.list_tools([]) == []


def test_stateless_flags_passed_to_run() -> None:
    """skip_memory=True is wired in (genuinely stateless per-incident runs)."""
    _reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert client.calls[0]["skip_memory"] is True
    assert client.calls[0]["enabled_toolsets"] == [toolset_for("restart_workflow")]


def test_default_actions_shape() -> None:
    """The default action set covers the governance ladder's actions."""
    assert "restart_workflow" in DEFAULT_ACTIONS
    assert "reconcile_table_write" in DEFAULT_ACTIONS
    assert "roll_back_deployment" in DEFAULT_ACTIONS
    # Every action maps to its own per-action toolset (1:1, no sharing).
    assert toolsets_for_actions(list(DEFAULT_ACTIONS)) == [toolset_for(a) for a in DEFAULT_ACTIONS]


def test_invoke_time_whitelist_blocks_denied_action_tool() -> None:
    """Defense in depth: even if a denied action's tool leaked into the listing,
    the per-run tool-name allowlist passed to client.run blocks it at invoke
    time. This mirrors Hermes's real ``set_thread_tool_whitelist`` gate checked
    in ``agent_runtime_helpers`` before every tool execution.
    """
    _reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),  # NOT roll_back_deployment
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    allowlist = client.calls[0]["tool_allowlist"]
    assert allowlist == {"restart_workflow"}
    # The denied action's tool name is not in the allowlist a real client would
    # hand to set_thread_tool_whitelist -> its invocation would be blocked.
    assert "roll_back_deployment" not in allowlist
    assert "terminal" not in allowlist


def test_lockdown_passes_none_allowlist() -> None:
    """A1 lockdown (no allowed actions) passes tool_allowlist=None (no gate)."""
    _reg, client = _fresh_registry()
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer([]),
        _FixedTrust("A1"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert client.calls[0]["tool_allowlist"] is None


def test_post_run_audit_catches_pre_call_gate_fail_open() -> None:
    """Adversarial: simulate Hermes's pre-call gate failing OPEN and confirm
    the post-run message-history audit catches a denied tool invocation.

    Verified in the real hermes-agent v0.18.0 package: both model_tools.py
    (~line 1059) and agent/tool_executor.py (~line 418) wrap
    get_pre_tool_call_block_message in `try/except Exception` that sets
    block_message=None on any error, so the tool executes. To simulate that
    fail-open we inject a message history in which the model invoked
    roll_back_deployment (denied) and terminal (a shell primitive) despite the
    allowlist being {'restart_workflow'}. The post-run scan must flag both as a
    policy-enforcement breach (Result.breach=True), distinguishable from an
    ordinary failed fix.
    """
    _reg, client = _fresh_registry()
    # Simulate a fail-open: the gate let through a denied action's tool call
    # AND a shell primitive. This is the OpenAI tool_call shape Hermes writes
    # (verified in hermes-agent/message_sanitization.py).
    client.run_result = HermesRunResult(
        final_response="attempted rollback",
        messages=[
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "roll_back_deployment",
                            "arguments": '{"deployment":"api"}',
                        },
                    },
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": '{"command":"kubectl rollout undo deployment/api"}',
                        },
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "rolled back"},
            {"role": "tool", "tool_call_id": "call_2", "content": "undone"},
        ],
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),  # NOT roll_back_deployment
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.breach is True
    assert result.success is False
    assert "roll_back_deployment" in result.summary
    assert "terminal" in result.summary
    assert "breach" in result.summary


def test_post_run_audit_clean_when_only_allowed_tools_invoked() -> None:
    """No breach when the history contains only allowlisted tool calls."""
    _reg, client = _fresh_registry()
    client.run_result = HermesRunResult(
        final_response="restarted",
        messages=[
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "restart_workflow",
                            "arguments": '{"workflow_id":"w-1"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "restarted"},
        ],
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.breach is False
    assert result.success is True


def test_post_run_audit_fail_closed_on_unparseable_tool_call() -> None:
    """A tool_call with no parseable name is treated as a breach (fail-closed)."""
    _reg, client = _fresh_registry()
    client.run_result = HermesRunResult(
        final_response="hmm",
        messages=[
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {}},
                ],
            }
        ],
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.breach is True
    assert result.success is False


def test_per_action_toolset_names_are_unique() -> None:
    """No two actions share a toolset — the core guarantee of the redesign."""
    toolsets = [toolset_for(a) for a in DEFAULT_ACTIONS]
    assert len(toolsets) == len(set(toolsets))


# ---------------------------------------------------------------------------
# Real backend wiring: wire_backend()/build_spec_set() must actually be called
# by the construction path, and a dispatching fake must land in the wired op.
# ---------------------------------------------------------------------------


def test_construction_registers_real_reconcile_handler_not_placeholder() -> None:
    """The wiring gap this closes: build_spec_set() (which calls wire_backend)
    replaces the fail-closed _refuse placeholder for reconcile_table_write with
    the real backend, and HermesRemediator.__init__ registers THAT set against
    the tool registry. Before this fix __init__ never called wire_backend at all,
    so the registry held the placeholder and every reconcile call refused."""
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    # default_specs['reconcile_table_write'].handler IS the _refuse placeholder:
    # it refuses when called (the fail-closed default before any backend wired).
    default_handler = default_specs["reconcile_table_write"].handler
    assert "refused" in default_handler(table="t", row_id="r", expected="x")

    # build_spec_set with a targets map wires the REAL backend instead.
    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
        conn.execute("INSERT INTO orders VALUES ('o1','paid')")
    targets = {"orders": SqliteTableSource(conn, "orders", "id")}
    wired = build_spec_set(targets)
    assert wired["reconcile_table_write"].handler is not default_handler

    # Construct the remediator against a recording registrar and confirm the
    # REAL handler (not the placeholder) is what the registry dispatches to.
    reg = _RecordingRegistrar()
    client = FakeClient(registrar=reg)
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["reconcile_table_write"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
        spec_set=wired,
        registrar=reg,
    )
    out = reg.invoke(
        "reconcile_table_write", {"table": "orders", "row_id": "o1", "expected": "shipped"}
    )
    assert "reconciled" in out, out  # real backend ran, not the refusal
    assert conn.execute("SELECT status FROM orders WHERE id='o1'").fetchone()[0] == "shipped"
    conn.close()
    # The remediator stored exactly that wired spec set.
    assert (
        rem._spec_set["reconcile_table_write"].handler is wired["reconcile_table_write"].handler
    )  # noqa: SLF001


def test_construction_without_targets_leaves_refuse_placeholder_fail_closed() -> None:
    """Forgetting to supply reconcile targets fails closed (placeholder stays),
    never a silent no-op that pretends to succeed."""
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    spec_set = build_spec_set()  # no targets -> placeholder stays
    out = spec_set["reconcile_table_write"].handler(table="orders", row_id="o1", expected="x")
    assert "refused" in out
