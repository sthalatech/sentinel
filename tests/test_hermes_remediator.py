"""Tests for HermesRemediator (fake/injected client; no live Hermes in CI)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinel.core.incident import Incident, IncidentStatus
from sentinel.core.trust import TrustStore
from sentinel.interfaces.enforcer import Enforcer
from sentinel.plugins.remediators.hermes import (
    DEFAULT_ACTION_TOOLSETS,
    HermesRemediator,
    HermesRunResult,
)


@dataclass
class FakeClient:
    """Records calls and returns canned tool listings / run results.

    ``toolset_to_tools`` maps a Hermes toolset to the *real tool names* Hermes
    registers for it (e.g. ``terminal`` -\u003e ``["process", "terminal"]``), so
    tests exercise the same tool-name-vs-action-name translation the production
    ``_verify_tool_surface`` must perform against a live Hermes.
    """

    toolset_to_tools: dict[str, list[str]] = field(default_factory=dict)
    run_result: HermesRunResult = field(
        default_factory=lambda: HermesRunResult(final_response="fixed", messages=[])
    )
    calls: list[dict[str, Any]] = field(default_factory=list)

    def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
        """Return the real tool names Hermes registers for the given toolsets."""
        out: list[str] = []
        for ts in enabled_toolsets:
            out.extend(self.toolset_to_tools.get(ts, []))
        return out

    def run(
        self,
        message: str,
        *,
        enabled_toolsets: list[str],
        skip_memory: bool,
        conversation_history: list[dict[str, Any]] | None,
    ) -> HermesRunResult:
        """Record the call and return the canned run result."""
        self.calls.append(
            {
                "message": message,
                "enabled_toolsets": list(enabled_toolsets),
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


def test_construction_refuses_without_docker() -> None:
    """Constructing HermesRemediator without Docker raises HermesRefusedError."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    client = FakeClient()
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

    client = FakeClient()
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


def test_allowed_actions_translate_from_real_tool_names() -> None:
    """A legitimate A4 run passes: Hermes lists real tool names, not action names.

    Hermes's ``list_tools`` returns tool names (``process``, ``patch``, ...) which
    ``_verify_tool_surface`` must translate back to governance actions. With only
    the terminal+file toolsets enabled, the listing exposes no action outside the
    intended surface, so remediation proceeds.
    """
    client = FakeClient(
        toolset_to_tools={
            "terminal": ["process", "terminal"],
            "file": ["patch", "read_file", "search_files", "write_file"],
        }
    )
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow", "clear_cache", "reconcile_table_write"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001 - test access
    call = client.calls[0]
    listed = client.list_tools(call["enabled_toolsets"])
    # The listing is real tool names, not action names — the bug would have
    # refused this run because {process, terminal, patch, ...} - allowed != empty.
    assert set(listed) == {
        "process",
        "terminal",
        "patch",
        "read_file",
        "search_files",
        "write_file",
    }
    assert "roll_back_deployment" not in listed  # action name never appears


def test_tool_surface_leak_is_refused() -> None:
    """A leaked toolset is refused in action-space.

    Only ``terminal`` is enabled, but Hermes also serves a ``file`` tool
    (``patch``). Translating the listing into actions unlocks
    ``reconcile_table_write``, which is not intended by the terminal-only
    surface — so remediation is refused.
    """
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    client = FakeClient(
        toolset_to_tools={
            # Realistic registry leak: a file tool mis-registered under the
            # terminal toolset, so it surfaces even when only terminal is enabled.
            "terminal": ["process", "terminal", "patch"],
        }
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
        assert "reconcile_table_write" in str(exc)


def test_unknown_tool_name_fails_closed() -> None:
    """An unrecognized Hermes tool name is refused (fail-closed surface check)."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    client = FakeClient(
        toolset_to_tools={
            "terminal": ["process", "terminal", "browser_navigate"],
        }
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
        raise AssertionError("expected HermesRefusedError for unknown tool")
    except HermesRefusedError as exc:
        assert "unrecognized Hermes tools" in str(exc)
        assert "browser_navigate" in str(exc)


def test_resume_replays_conversation_history() -> None:
    """A second attempt on the same incident replays the stored history."""
    client = FakeClient(
        toolset_to_tools={"terminal": ["process", "terminal"]},
        run_result=HermesRunResult(
            final_response="done",
            messages=[{"role": "assistant", "content": "done"}],
        ),
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
    client = FakeClient(toolset_to_tools={})
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


def test_stateless_flags_passed_to_run() -> None:
    """skip_memory=True is wired in (genuinely stateless per-incident runs)."""
    client = FakeClient(toolset_to_tools={"terminal": ["process", "terminal"]})
    rem = HermesRemediator(
        _make_factory(client),
        _FixedEnforcer(["restart_workflow"]),
        _FixedTrust("A4"),
        docker_check=_docker_ok,
        config_loader=_config_docker,
    )
    rem.remediate(_make_incident(), rem._enforcer)  # noqa: SLF001
    assert client.calls[0]["skip_memory"] is True
    assert "terminal" in client.calls[0]["enabled_toolsets"]


def test_default_action_toolsets_shape() -> None:
    """The default action->toolset mapping covers the governance ladder's actions."""
    assert DEFAULT_ACTION_TOOLSETS["restart_workflow"] == "terminal"
    assert DEFAULT_ACTION_TOOLSETS["reconcile_table_write"] == "file"
