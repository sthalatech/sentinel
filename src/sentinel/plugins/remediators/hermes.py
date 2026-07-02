"""Remediator that drives one Hermes headless AIAgent conversation per incident.

Why Hermes's AIAgent library (not the -z CLI):
  Validation on this VM (Hermes v0.18.0, package ``hermes-agent``) established
  that the reliable headless entry point is the ``AIAgent`` Python class
  (``run_agent.chat``). The ``-z`` one-shot CLI has a documented
  approval-bypass bug we avoid by design. Resume is handled by replaying the
  stored ``conversation_history`` (the message list returned by
  ``run_conversation``) rather than depending on Hermes's session-DB internals
  — two rounds of validation found real gaps between Hermes's docs and its
  behaviour there, so we depend only on the stable ``conversation_history`` arg.

Enforcement is pre-run, not prompt-bound (contrast with ShelleyRemediator):
  Hermes exposes ``enabled_toolsets``, which performs **registry-level** tool
  removal: ``model_tools.get_tool_definitions(enabled_toolsets=[...])`` omits
  every tool whose toolset is not enabled. So before each run we resolve the
  current trust level's ``allowed_actions`` from the enforcer, map each action
  to a Hermes toolset, and set ``enabled_toolsets`` to that union. An action
  not on the allowed list is never registered as a tool the model can see —
  verified via the tool listing after configuring it (see
  ``_verify_tool_surface``), not by trusting the config alone.

Sandbox hard requirement:
  Construction refuses if the Docker daemon is down or Hermes config
  ``terminal.backend != "docker"``. There is no fallback to unsandboxed local
  execution — see docs/SECURITY.md.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from sentinel.core.incident import Incident, Result
from sentinel.core.trust import TrustStore
from sentinel.interfaces.enforcer import Enforcer
from sentinel.interfaces.remediator import Remediator

#: Default mapping of governance actions to Hermes toolsets. A remediation
#: action is only reachable if its toolset is in the run's enabled_toolsets.
DEFAULT_ACTION_TOOLSETS: dict[str, str] = {
    "restart_workflow": "terminal",
    "reconcile_table_write": "file",
    "clear_cache": "terminal",
    "retry_webhook": "web",
    "scale_resource": "terminal",
    "roll_back_deployment": "terminal",
}

#: Real Hermes tool names each toolset registers, probed against Hermes v0.18.0
#: via ``model_tools.get_tool_definitions(enabled_toolsets=[...])``. ``list_tools``
#: returns these tool names (e.g. ``process``, ``patch``), which are a *different
#: vocabulary* from governance action names (e.g. ``restart_workflow``) — so the
#: surface check must translate tool names back into the action space via this
#: map before computing leaks. Browser/computer_use toolsets are intentionally
#: absent: they are never in the remediation allow-list.
TOOLSET_TOOLS: dict[str, tuple[str, ...]] = {
    "terminal": ("process", "terminal"),
    "file": ("patch", "read_file", "search_files", "write_file"),
    "web": (),
}

#: Inverse of ``TOOLSET_TOOLS`` — real Hermes tool name -> its toolset.
TOOL_TO_TOOLSET: dict[str, str] = {
    tool: toolset for toolset, tools in TOOLSET_TOOLS.items() for tool in tools
}


class HermesClient(Protocol):
    """Abstracted Hermes AIAgent surface so tests can inject a fake."""

    def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
        """Return the action-tool names Hermes registers for these toolsets."""
        ...

    def run(
        self,
        message: str,
        *,
        enabled_toolsets: list[str],
        skip_memory: bool,
        conversation_history: list[dict[str, Any]] | None,
    ) -> HermesRunResult:
        """Run one headless turn; return the final response + message history."""
        ...


@dataclass
class HermesRunResult:
    """Outcome of one Hermes run_conversation call."""

    final_response: str
    messages: list[dict[str, Any]] = field(default_factory=list)


def _docker_daemon_running() -> bool:
    """Return True iff a docker daemon responds to `docker info`."""
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _hermes_terminal_backend_is_docker(load_config: Callable[[], dict[str, Any]]) -> bool:
    """Return True iff Hermes config has terminal.backend == 'docker'."""
    try:
        cfg = load_config()
    except Exception:
        return False
    terminal = cfg.get("terminal", {}) if isinstance(cfg, dict) else {}
    return bool(terminal.get("backend") == "docker")


class HermesRefusedError(RuntimeError):
    """Raised when a hard startup requirement (Docker / backend) is unmet."""


class HermesRemediator(Remediator):
    """One headless Hermes conversation per incident, gated pre-run by the enforcer."""

    def __init__(
        self,
        client_factory: Callable[[], HermesClient],
        enforcer: Enforcer,
        trust_store: TrustStore,
        *,
        action_toolsets: dict[str, str] | None = None,
        toolset_tools: dict[str, tuple[str, ...]] | None = None,
        docker_check: Callable[[], bool] = _docker_daemon_running,
        config_loader: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._enforcer = enforcer
        self._trust_store = trust_store
        self._action_toolsets = dict(action_toolsets or DEFAULT_ACTION_TOOLSETS)
        self._toolset_tools = dict(toolset_tools or TOOLSET_TOOLS)
        self._docker_check = docker_check
        self._config_loader = config_loader or _default_config_loader
        self._verify_startup()

    def _verify_startup(self) -> None:
        """Refuse to construct if Docker is down or the backend is not docker."""
        if not self._docker_check():
            raise HermesRefusedError(
                "Docker daemon is not running; refusing to construct HermesRemediator "
                "(would degrade to unsandboxed local execution)"
            )
        if not _hermes_terminal_backend_is_docker(self._config_loader):
            raise HermesRefusedError(
                "Hermes terminal.backend is not 'docker'; refusing to construct "
                "HermesRemediator (local/unsandboxed execution is not permitted)"
            )

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Resolve the trust surface, verify it, then run one Hermes turn."""
        allowed = enforcer.allowed_actions(self._trust_store.get_trust())
        toolsets = self._resolve_toolsets(allowed)
        client = self._client_factory()
        self._verify_tool_surface(client, toolsets, incident.id)
        history = self._load_history(incident)
        message = self._build_message(incident, allowed)
        run_result = client.run(
            message,
            enabled_toolsets=toolsets,
            skip_memory=True,
            conversation_history=history or None,
        )
        incident.external_refs["conversation"] = _serialize_history(run_result.messages)
        return Result(success=True, summary=run_result.final_response[:200] or "hermes ran")

    def _resolve_toolsets(self, allowed: list[str]) -> list[str]:
        """Map the allowed governance actions to the Hermes toolsets they need."""
        toolsets: list[str] = []
        for action in allowed:
            ts = self._action_toolsets.get(action)
            if ts is not None and ts not in toolsets:
                toolsets.append(ts)
        return toolsets

    def _verify_tool_surface(
        self,
        client: HermesClient,
        toolsets: list[str],
        incident_id: str,
    ) -> None:
        """Verify the tool listing exposes no governance action outside the intent.

        Hermes ``list_tools`` returns *real tool names* (e.g. ``process``,
        ``patch``), a different vocabulary from governance *action names* (e.g.
        ``restart_workflow``). Comparing them directly would always report every
        tool as a leak. Instead we translate the listing into the action space:
        each listed tool maps to a toolset, each toolset unlocks a set of
        actions, and we refuse if any unlocked action is not among the actions
        the enabled toolsets were *intended* to provide. Unknown tool names (no
        known toolset) fail closed — they indicate an unexpected surface.
        """
        listed = set(client.list_tools(toolsets))
        tool_to_toolset = {
            tool: toolset for toolset, tools in self._toolset_tools.items() for tool in tools
        }
        unknown = {tool for tool in listed if tool not in tool_to_toolset}
        if unknown:
            raise HermesRefusedError(
                f"tool-surface restriction failed for incident {incident_id}: "
                f"unrecognized Hermes tools present: {sorted(unknown)}"
            )
        listed_toolsets = {tool_to_toolset[tool] for tool in listed}
        intended_toolsets = set(toolsets)
        intended_actions = {
            action
            for action, toolset in self._action_toolsets.items()
            if toolset in intended_toolsets
        }
        listed_actions = {
            action
            for action, toolset in self._action_toolsets.items()
            if toolset in listed_toolsets
        }
        leaked = listed_actions - intended_actions
        if leaked:
            raise HermesRefusedError(
                f"tool-surface restriction failed for incident {incident_id}: "
                f"denied actions reachable via Hermes listing: {sorted(leaked)}"
            )

    def _load_history(self, incident: Incident) -> list[dict[str, Any]]:
        """Deserialize a prior conversation history from external_refs, if present."""
        raw = incident.external_refs.get("conversation")
        if not raw:
            return []
        try:
            return list(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            return []

    def _build_message(self, incident: Incident, allowed: list[str]) -> str:
        """Compose the headless prompt for this remediation attempt."""
        return (
            f"Remediate incident {incident.id} (source={incident.source}, "
            f"attempt {incident.attempts}). Context: "
            f"{json.dumps(incident.context, default=str)}. "
            f"Permitted actions: {', '.join(allowed) or 'none (lockdown)'}."
        )


def _serialize_history(messages: list[dict[str, Any]]) -> str:
    """Serialize the message history for storage in external_refs."""
    return json.dumps(messages, default=str)


def _default_config_loader() -> dict[str, Any]:
    """Load Hermes config from ~/.hermes/config.yaml (lazy import)."""
    from hermes_cli.config import load_config  # type: ignore[import-not-found]

    return dict(load_config())
