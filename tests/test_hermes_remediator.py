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

        Hermes's ``ToolRegistry.run`` dispatches as ``handler(args_dict)`` — ONE
        positional dict, not bare kwargs (verified in tools/registry.py and
        tools/mcp_tool.py's dispatch-interface docstring). Dispatching the same
        way here is what catches a handler-signature bug like ``def _h(**kwargs)``
        that crashes on real dispatch but passes a kwargs-calling fake. A
        handler-wiring gap (placeholder) shows up as a refusal string, not a
        silent pass.
        """
        handler = self._handlers.get(name)
        if handler is None:
            return f"{name}: no handler registered"
        return str(handler(arguments))


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
        timeout_s: float | None = None,
    ) -> HermesRunResult:
        """Record the call and, if simulating dispatch, run the real handlers.

        ``timeout_s`` is accepted to match the real ``HermesClient.run`` contract
        (HermesRemediator passes its per-incident bound) but not enforced here —
        the fake is synchronous and never hangs; the timeout behavior is tested
        directly against a fake that sleeps.
        """
        self.calls.append(
            {
                "message": message,
                "enabled_toolsets": list(enabled_toolsets),
                "tool_allowlist": set(tool_allowlist) if tool_allowlist else None,
                "skip_memory": skip_memory,
                "conversation_history": conversation_history,
                "timeout_s": timeout_s,
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


# ---------------------------------------------------------------------------
# Live-trial regressions: real Hermes dispatches handler(args_dict) (ONE
# positional dict), and the post-run audit must distinguish a denied tool that
# was BLOCKED at invoke time (defense-in-depth worked) from one that fail-opened
# and actually ran. Both were found by the first live run against a real Hermes
# instance (openai/gpt-oss-20b:free via OpenRouter) — impossible to catch with a
# kwargs-calling fake or an audit that ignored tool results.
# ---------------------------------------------------------------------------


def test_reconcile_handler_accepts_hermes_positional_dict_dispatch() -> None:
    """Hermes's ToolRegistry.run calls handler(args_dict) — one positional dict,
    NOT handler(**kwargs). A ``def _h(**kwargs)`` handler crashes on real
    dispatch with "takes 0 positional arguments but 1 was given". The wired
    backend must accept the positional dict the real registry passes."""
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
        conn.execute("INSERT INTO orders VALUES ('o1','paid')")
    spec = build_spec_set({"orders": SqliteTableSource(conn, "orders", "id")})
    # Real dispatch shape: one positional dict.
    out = spec["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "o1", "expected": "shipped"}
    )
    assert "reconciled" in out, out
    assert conn.execute("SELECT status FROM orders WHERE id='o1'").fetchone()[0] == "shipped"
    conn.close()


def test_refuse_handler_accepts_hermes_positional_dict_dispatch() -> None:
    """The fail-closed placeholder must also accept the positional-dict shape so
    a real Hermes run returns the refusal string, not a crash."""
    from sentinel.plugins.remediators.hermes_mcp_tools import default_specs

    out = default_specs["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "o1", "expected": "x"}
    )
    assert "refused" in out


def test_audit_treats_invoke_time_block_as_not_a_breach() -> None:
    """A denied tool that the per-thread whitelist BLOCKED at invoke time (the
    result carries the denial marker) is NOT a fail-open breach — the gate
    worked. The post-run audit must not flag it. This is the false-positive the
    first live run surfaced: the model tried search_files/skills_list/terminal,
    all were blocked, but the old audit cried breach."""
    from sentinel.plugins.remediators.hermes import (
        _WHITELIST_DENIAL_MARKER,
        _tool_call_violations,
    )

    messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "search_files", "arguments": "{}"},
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {"name": "reconcile_table_write", "arguments": "{}"},
                },
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call_1",
            "content": f"Tool 'search_files' {_WHITELIST_DENIAL_MARKER}",
        },
        {
            "role": "tool",
            "tool_call_id": "call_2",
            "content": "reconcile_table_write: reconciled orders:o1",
        },
    ]
    # search_files was blocked (denial marker) -> not a breach. reconcile ran
    # and is in the allowlist -> not a breach. Zero violations.
    assert _tool_call_violations(messages, {"reconcile_table_write"}) == set()


def test_audit_flags_fail_open_when_denied_tool_actually_ran() -> None:
    """A denied tool whose result lacks the denial marker actually executed
    (the pre-call gate failed open) — that IS a breach and must be flagged."""
    from sentinel.plugins.remediators.hermes import _tool_call_violations

    messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "terminal", "arguments": '{"command":"rm -rf /"}'},
                },
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call_1",
            "content": "deleted everything",
        },  # no denial marker -> ran
    ]
    assert _tool_call_violations(messages, {"reconcile_table_write"}) == {"terminal"}


def test_audit_fail_closed_when_denied_call_has_no_matching_result() -> None:
    """A denied tool_call with no matching tool result at all is a violation —
    we cannot prove it was blocked, so fail closed."""
    from sentinel.plugins.remediators.hermes import _tool_call_violations

    messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_9",
                    "type": "function",
                    "function": {"name": "terminal", "arguments": "{}"},
                }
            ],
        },
        # no tool result for call_9
    ]
    assert _tool_call_violations(messages, set()) == {"terminal"}


# ---------------------------------------------------------------------------
# Second-live-trial hardening: (1) per-incident timeout under 90s that returns
# a Result (not a raw exception) so the engine's attempts/escalation path
# handles it; (2) refuse a hallucinated row_id against the incident's mismatch
# set and list the valid ids. Both are validated against a REAL Hermes instance
# + real model in scripts/live_hermes_trial.py (second trial). These unit tests
# pin the contract the live run depends on.
# ---------------------------------------------------------------------------


def test_run_timeout_under_90s_is_default_and_enforced() -> None:
    """The default per-incident timeout is under 90s, and __init__ refuses any
    value >= 90 or <= 0 — a hung model call must never hold the tick open."""
    from sentinel.plugins.remediators.hermes import DEFAULT_RUN_TIMEOUT_S, HermesRefusedError

    assert 0 < DEFAULT_RUN_TIMEOUT_S < 90
    _reg, client = _fresh_registry()
    # >= 90 is refused.
    for bad in (90, 120, 0, -1):
        try:
            HermesRemediator(
                _make_factory(client),
                _FixedEnforcer(["restart_workflow"]),
                _FixedTrust("A4"),
                docker_check=_docker_ok,
                config_loader=_config_docker,
                run_timeout_s=float(bad),
            )
            raise AssertionError(f"expected refusal for run_timeout_s={bad}")
        except HermesRefusedError as exc:
            assert "run_timeout_s" in str(exc)


def test_timeout_returns_result_not_raise() -> None:
    """A client.run that raises TimeoutError is converted to a FAILED Result —
    never a raw exception — so core/engine.py's attempts/escalation path handles
    a hang (verify stays False -> demote/escalate), and the tick never crashes.
    """
    _reg, client = _fresh_registry()

    class _HangClient:
        def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
            return self.registrar.tools_for(enabled_toolsets)

        def run(
            self,
            message,
            *,
            enabled_toolsets,
            tool_allowlist,
            skip_memory,
            conversation_history,
            timeout_s,
        ):
            raise TimeoutError("hung")

        registrar = _reg

    rem = HermesRemediator(
        lambda: _HangClient(),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.success is False
    assert result.breach is False
    assert "timed out" in result.summary


def test_real_client_run_thread_timeout_raises_timeout_error() -> None:
    """The real HermesAIAgentClient.run raises TimeoutError when run_conversation
    exceeds timeout_s (thread-join based, since run_conversation has no native
    cancel). This is what remediate() catches and turns into a Result. Skipped
    where hermes_cli isn't installed (CI); exercised for real in the live trial."""
    import importlib
    import time as _time

    try:
        importlib.import_module("hermes_cli")
    except ImportError:
        import pytest

        pytest.skip("hermes_cli not installed (CI); live-trial covers this")

    from sentinel.plugins.remediators.hermes_mcp_tools import HermesAIAgentClient

    class _SlowAgent:
        def run_conversation(self, *, user_message, conversation_history):
            _time.sleep(2.0)
            return {"response": "late", "messages": []}

    client = HermesAIAgentClient(lambda: _SlowAgent())
    try:
        client.run(
            "x",
            enabled_toolsets=[],
            tool_allowlist=None,
            skip_memory=True,
            conversation_history=None,
            timeout_s=0.2,
        )
        raise AssertionError("expected TimeoutError")
    except TimeoutError as exc:
        assert "0.2s" in str(exc)


def test_reconcile_refuses_hallucinated_row_id_lists_valid_ids() -> None:
    """Fix 3: a row_id not in the incident's mismatch set is refused BEFORE the
    write, with the valid row_ids listed — a real correction path, not a blind
    'nothing changed'. First trial's model hallucinated row_id='ضغط' and got a
    no-op; this collapses the correction to one turn."""
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
        conn.executemany("INSERT INTO orders VALUES (?,?)", [("o1", "paid"), ("o2", "paid")])
    targets = {"orders": SqliteTableSource(conn, "orders", "id")}
    valid = {"orders": {"o2": "shipped"}}  # row_id -> canonical expected
    spec = build_spec_set(targets, valid)
    # Real dispatch shape (positional dict). A hallucinated id is refused.
    out = spec["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "o99", "expected": "shipped"}
    )
    assert "refused" in out, out
    assert "o2" in out, out  # valid id listed
    assert "o99" in out, out
    # And nothing was written.
    assert conn.execute("SELECT status FROM orders WHERE id='o2'").fetchone()[0] == "paid"
    conn.close()


def test_reconcile_accepts_valid_row_id_writes_it() -> None:
    """A row_id that IS in the mismatch set is written normally."""
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
        conn.execute("INSERT INTO orders VALUES ('o2','paid')")
    targets = {"orders": SqliteTableSource(conn, "orders", "id")}
    valid = {"orders": {"o2": "shipped"}}
    spec = build_spec_set(targets, valid)
    out = spec["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "o2", "expected": "shipped"}
    )
    assert "reconciled" in out, out
    assert conn.execute("SELECT status FROM orders WHERE id='o2'").fetchone()[0] == "shipped"
    conn.close()


def test_reconcile_no_valid_set_falls_back_to_write_rowcount_guard() -> None:
    """Without a valid_row_ids set wired, the handler still guards via write_row
    rowcount (back-compat for callers that wire targets but not the mismatch
    set)."""
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
        conn.execute("INSERT INTO orders VALUES ('o2','paid')")
    spec = build_spec_set({"orders": SqliteTableSource(conn, "orders", "id")})
    out = spec["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "missing", "expected": "shipped"}
    )
    assert "no row matched" in out, out
    conn.close()


# ---------------------------------------------------------------------------
# Second-live-trial finding #4: HTTP 402 (provider billing/credits exhausted)
# aborts the Hermes turn with completed=False/failed=True and the error in
# final_response. The real client must raise on that shape (not return it as a
# successful result) so remediate() records a FAILED Result — otherwise a
# billing failure is silently recorded as success=True (fail-open). The live
# trial caught this when the OpenRouter account hit 402 mid-run.
# ---------------------------------------------------------------------------


def test_abort_returns_failed_result_not_success() -> None:
    """A client.run that raises RuntimeError (Hermes aborted: 402/401/content
    policy/max-retries) is converted to a FAILED Result, never success=True and
    never a raw exception — so the engine's attempts/escalation path handles a
    provider billing failure instead of the tick crashing or recording a fake
    success."""
    _reg, client = _fresh_registry()

    class _AbortClient:
        def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
            return self.registrar.tools_for(enabled_toolsets)

        def run(
            self,
            message,
            *,
            enabled_toolsets,
            tool_allowlist,
            skip_memory,
            conversation_history,
            timeout_s,
        ):
            raise RuntimeError("hermes run aborted (not completed): HTTP 402 credits")

        registrar = _reg

    rem = HermesRemediator(
        lambda: _AbortClient(),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.success is False
    assert result.breach is False
    assert "aborted" in result.summary
    assert "402" in result.summary


def test_real_client_raises_on_completed_false_abort() -> None:
    """The real HermesAIAgentClient.run raises RuntimeError when run_conversation
    returns completed=False / failed=True (non-retryable abort), instead of
    returning the error string as a successful HermesRunResult. Skipped where
    hermes_cli isn't installed (CI); exercised for real in the live trial."""
    import importlib

    try:
        importlib.import_module("hermes_cli")
    except ImportError:
        import pytest

        pytest.skip("hermes_cli not installed (CI); live-trial covers this")

    from sentinel.plugins.remediators.hermes_mcp_tools import HermesAIAgentClient

    class _AbortAgent:
        def run_conversation(self, *, user_message, conversation_history):
            return {
                "final_response": "HTTP 402: credits exhausted",
                "messages": [],
                "completed": False,
                "failed": True,
                "error": "HTTP 402: credits exhausted",
            }

    client = HermesAIAgentClient(lambda: _AbortAgent())
    try:
        client.run(
            "x",
            enabled_toolsets=[],
            tool_allowlist=None,
            skip_memory=True,
            conversation_history=None,
            timeout_s=10.0,
        )
        raise AssertionError("expected RuntimeError on completed=False abort")
    except RuntimeError as exc:
        assert "aborted" in str(exc)
        assert "402" in str(exc)


# ---------------------------------------------------------------------------
# Second-live-trial finding #5: the free model returned EMPTY content after
# exhausting retries ("No fallback providers configured"). Hermes marked that
# turn done with final_response="⚠️ No reply..." and NO tool_calls. The
# remediator would have recorded success=True for a turn that did nothing — a
# fail-open. A no-tool-call + empty/no-reply turn must be a FAILED Result.
# ---------------------------------------------------------------------------


def test_noop_empty_response_returns_failed_result_not_success() -> None:
    """A turn with no tool_calls and an empty final_response is a no-op, not a
    success — the engine must escalate, not record a fake successful fix."""
    _reg, client = _fresh_registry()
    client.run_result = HermesRunResult(
        final_response="", messages=[{"role": "assistant", "content": ""}]
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.success is False
    assert result.breach is False
    assert "no tool call" in result.summary


def test_noop_hermes_no_reply_marker_returns_failed_result() -> None:
    """Hermes's 'No reply' marker (empty content after retries) is a no-op."""
    _reg, client = _fresh_registry()
    client.run_result = HermesRunResult(
        final_response="⚠️ No reply: the model returned empty content after retries.",
        messages=[{"role": "assistant", "content": ""}],
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    result = rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert result.success is False
    assert result.breach is False


def test_real_response_with_tool_call_is_still_success() -> None:
    """A turn that called an allowed tool and produced content is a real success
    (the noop guard must not false-positive on a normal turn)."""
    _reg, client = _fresh_registry()
    client.run_result = HermesRunResult(
        final_response="restarted workflow w-1",
        messages=[
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {
                            "name": "restart_workflow",
                            "arguments": '{"workflow_id":"w-1"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "restarted"},
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
    assert result.success is True
    assert result.breach is False


# ---------------------------------------------------------------------------
# Second-live-trial finding #6: the model wrote a WRONG expected value
# ("shipped SDR") to a VALID row_id ("o2"); the handler accepted it (row_id was
# in the mismatch set, expected was a string) and the remediator recorded
# success=True, but verify()=False because "shipped SDR" != "shipped". The
# handler must refuse an expected that does not match the canonical value.
# ---------------------------------------------------------------------------


def test_reconcile_refuses_wrong_expected_for_valid_row_id() -> None:
    """A valid row_id with a WRONG expected value is refused before the write,
    with the canonical expected stated — so the model corrects in one turn
    instead of corrupting the row (second-trial finding #6)."""
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.remediators.hermes_mcp_tools import build_spec_set

    conn = sqlite3.connect(":memory:")
    with conn:
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
        conn.execute("INSERT INTO orders VALUES ('o2','paid')")
    targets = {"orders": SqliteTableSource(conn, "orders", "id")}
    valid = {"orders": {"o2": "shipped"}}  # canonical expected is "shipped"
    spec = build_spec_set(targets, valid)
    out = spec["reconcile_table_write"].handler(
        {"table": "orders", "row_id": "o2", "expected": "shipped SDR"}
    )
    assert "refused" in out, out
    assert "shipped" in out, out  # canonical value stated
    assert "shipped SDR" in out, out
    # And the row was NOT corrupted.
    assert conn.execute("SELECT status FROM orders WHERE id='o2'").fetchone()[0] == "paid"
    conn.close()
