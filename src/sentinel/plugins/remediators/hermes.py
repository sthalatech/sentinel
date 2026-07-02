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

Enforcement is per-action, not toolset-routed (contrast with shell toolsets):
  Hermes's built-in ``terminal``/``file``/``web`` toolsets are generic execution
  primitives — ``terminal`` takes an arbitrary ``command`` shell string. Mapping
  governance actions onto them cannot enforce an action-level distinction: a
  trust level allowing ``restart_workflow`` but denying ``roll_back_deployment``
  (both mapped to ``terminal``) still hands the model a shell, so it can run
  ``kubectl rollout undo`` regardless of the allow-list. Confirmed against Hermes
  v0.18.0: ``model_tools.get_tool_definitions(enabled_toolsets=["terminal"])``
  registers ``terminal`` with a free-form ``command`` parameter.
  Instead we register one narrow tool per governance action, each in its OWN
  toolset ``sentinel_<action>`` (see ``hermes_mcp_tools``), exposing only that
  action's specific parameters with no shell surface. Before each run we resolve
  ``allowed_actions`` and enable exactly the per-action toolsets for those
  actions — so denying ``roll_back_deployment`` means its toolset is never
  registered and the model has no surface that can perform a rollback. The tool
  listing is then verified (see ``_verify_tool_surface``) to be exactly the
  allowed action tool names, not merely registry-shaped. As defense in depth,
  the run is also executed under Hermes's per-thread tool-name whitelist
  (``set_thread_tool_whitelist``), which blocks any tool not in the allowed set
  at invoke time — independent of the registry — so a denied action's operation
  is unreachable even if a tool leaked into the listing.

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
from sentinel.plugins.remediators.hermes_mcp_tools import toolsets_for_actions

#: Governance actions the remediator can expose as narrow per-action Hermes
#: tools. Each action is registered (in ``hermes_mcp_tools``) under its own
#: ``sentinel_<action>`` toolset with a schema admitting only that action's
#: parameters — no shared shell/file toolset, so denying one action never
#: exposes another's underlying operation.
DEFAULT_ACTIONS: tuple[str, ...] = (
    "restart_workflow",
    "reconcile_table_write",
    "clear_cache",
    "retry_webhook",
    "scale_resource",
    "roll_back_deployment",
)


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
        tool_allowlist: set[str] | None,
        skip_memory: bool,
        conversation_history: list[dict[str, Any]] | None,
    ) -> HermesRunResult:
        """Run one headless turn under a per-tool-name invoke-time allowlist.

        ``tool_allowlist`` is the set of governance action tool names the model
        may invoke this run; a real client applies it via Hermes's
        ``set_thread_tool_whitelist`` so a denied action's tool is blocked at
        invoke time even if it somehow surfaced in the registry. ``None`` means
        no invoke-time gate (lockdown runs with an empty toolset need no gate).
        """
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
        actions: tuple[str, ...] | None = None,
        docker_check: Callable[[], bool] = _docker_daemon_running,
        config_loader: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._enforcer = enforcer
        self._trust_store = trust_store
        self._actions: tuple[str, ...] = actions if actions is not None else DEFAULT_ACTIONS
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
            tool_allowlist=set(allowed) if allowed else None,
            skip_memory=True,
            conversation_history=history or None,
        )
        incident.external_refs["conversation"] = _serialize_history(run_result.messages)
        return Result(success=True, summary=run_result.final_response[:200] or "hermes ran")

    def _resolve_toolsets(self, allowed: list[str]) -> list[str]:
        """Map allowed governance actions to their per-action Hermes toolsets.

        Each action lives in its own ``sentinel_<action>`` toolset, so there is a
        1:1 mapping — enabling a toolset surfaces exactly that action's narrow
        tool and no other action's operation.
        """
        known = set(self._actions)
        unknown = [a for a in allowed if a not in known]
        if unknown:
            raise HermesRefusedError(f"unknown remediation actions in allow-list: {unknown}")
        return toolsets_for_actions(allowed)

    def _verify_tool_surface(
        self,
        client: HermesClient,
        toolsets: list[str],
        allowed: list[str],
        incident_id: str,
    ) -> None:
        """Verify the tool listing is exactly the allowed action tool names.

        With per-action toolsets, the listed tool names ARE governance action
        names (each ``sentinel_<action>`` toolset registers one tool named
        ``<action>``), so the vocabularies match and we can check the listing is
        exactly ``set(allowed)``. Any extra tool (e.g. a leaked ``terminal``
        shell primitive) or any missing allowed tool fails closed — the model
        must neither gain a denied action's surface nor silently lose an allowed
        one.
        """
        listed = set(client.list_tools(toolsets))
        intended = set(allowed)
        leaked = listed - intended
        missing = intended - listed
        if leaked:
            raise HermesRefusedError(
                f"tool-surface restriction failed for incident {incident_id}: "
                f"tools present beyond the allow-list: {sorted(leaked)}"
            )
        if missing:
            raise HermesRefusedError(
                f"tool-surface restriction failed for incident {incident_id}: "
                f"allowed actions missing from Hermes listing: {sorted(missing)}"
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
