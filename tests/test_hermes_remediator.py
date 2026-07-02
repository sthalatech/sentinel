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
    """Records calls and returns canned tool listings / run results."""

    toolset_to_actions: dict[str, list[str]] = field(default_factory=dict)
    run_result: HermesRunResult = field(
        default_factory=lambda: HermesRunResult(final_response="fixed", messages=[])
    )
    calls: list[dict[str, Any]] = field(default_factory=list)

    def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
        """Return the action-tools registered for the given toolsets."""
        out: list[str] = []
        for ts in enabled_toolsets:
            out.extend(self.toolset_to_actions.get(ts, []))
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


def test_denied_action_absent_from_tool_listing() -> None:
    """An action outside allowed_actions is genuinely absent from Hermes's listing."""
    client = FakeClient(
        toolset_to_actions={
            "terminal": ["restart_workflow", "clear_cache"],
            "file": ["reconcile_table_write"],
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
    # roll_back_deployment (terminal toolset) is denied and must NOT appear.
    assert "roll_back_deployment" not in listed
    assert set(listed) == {
        "restart_workflow",
        "clear_cache",
        "reconcile_table_write",
    }


def test_tool_surface_leak_is_refused() -> None:
    """If a denied action leaks into Hermes's listing, remediation is refused."""
    from sentinel.plugins.remediators.hermes import HermesRefusedError

    client = FakeClient(
        toolset_to_actions={
            "terminal": ["restart_workflow", "roll_back_deployment"],
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
        assert "roll_back_deployment" in str(exc)


def test_resume_replays_conversation_history() -> None:
    """A second attempt on the same incident replays the stored history."""
    client = FakeClient(
        toolset_to_actions={"terminal": ["restart_workflow"]},
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
    client = FakeClient(toolset_to_actions={})
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
    client = FakeClient(toolset_to_actions={"terminal": ["restart_workflow"]})
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
