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
    name is registered under a toolset with a schema + handler. ``list_tools``
    then returns the registered tool names for the enabled toolsets only —
    exactly what ``model_tools.get_tool_definitions(enabled_toolsets=[...])``
    does on real Hermes.
    """

    def __init__(self) -> None:
        self._by_toolset: dict[str, list[str]] = {}

    def register(
        self,
        name: str,
        toolset: str,
        schema: dict[str, Any],
        handler: Any,
        description: str = "",
        **_kwargs: Any,
    ) -> None:
        """Record one tool under a toolset (Hermes registry.register shape)."""
        del schema, handler, description
        self._by_toolset.setdefault(toolset, [])
        if name not in self._by_toolset[toolset]:
            self._by_toolset[toolset].append(name)

    def tools_for(self, enabled_toolsets: list[str]) -> list[str]:
        """Return tool names for the enabled toolsets (registry-level filter)."""
        out: list[str] = []
        for ts in enabled_toolsets:
            out.extend(self._by_toolset.get(ts, []))
        return out


@dataclass
class FakeClient:
    """Records calls; ``list_tools`` reflects the real per-action registry."""

    registrar: _RecordingRegistrar
    run_result: HermesRunResult = field(
        default_factory=lambda: HermesRunResult(final_response="fixed", messages=[])
    )
    calls: list[dict[str, Any]] = field(default_factory=list)

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
        """Record the call (incl. the per-tool-name allowlist) and return canned."""
        self.calls.append(
            {
                "message": message,
                "enabled_toolsets": list(enabled_toolsets),
                "tool_allowlist": set(tool_allowlist) if tool_allowlist else None,
                "skip_memory": skip_memory,
                "conversation_history": conversation_history,
            }
        )
        return self.run_result


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


def test_per_action_toolset_names_are_unique() -> None:
    """No two actions share a toolset — the core guarantee of the redesign."""
    toolsets = [toolset_for(a) for a in DEFAULT_ACTIONS]
    assert len(toolsets) == len(set(toolsets))
