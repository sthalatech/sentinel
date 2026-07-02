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
        docker_check: Callable[[], bool] = _docker_daemon_running,
        config_loader: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._enforcer = enforcer
        self._trust_store = trust_store
        self._action_toolsets = dict(action_toolsets or DEFAULT_ACTION_TOOLSETS)
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
        self._verify_tool_surface(client, toolsets, allowed, incident.id)
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
        allowed: list[str],
        incident_id: str,
    ) -> None:
        """Verify the listed action-tools exactly match the allowed surface.

        Registry-level check: an action not in ``allowed`` must not appear in
        Hermes's tool listing for the configured toolsets. If a denied action
        leaks through, refuse rather than run.
        """
        listed = set(client.list_tools(toolsets))
        leaked = listed - set(allowed)
        if leaked:
            raise HermesRefusedError(
                f"tool-surface restriction failed for incident {incident_id}: "
                f"denied actions present in Hermes listing: {sorted(leaked)}"
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
