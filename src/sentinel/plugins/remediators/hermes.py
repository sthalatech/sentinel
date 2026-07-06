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
from sentinel.plugins.remediators.hermes_mcp_tools import (
    build_spec_set,
    register_action_tools,
    toolsets_for_actions,
)

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
        spec_set: dict[str, Any] | None = None,
        registrar: Any = None,
    ) -> None:
        self._client_factory = client_factory
        self._enforcer = enforcer
        self._trust_store = trust_store
        self._actions: tuple[str, ...] = actions if actions is not None else DEFAULT_ACTIONS
        self._docker_check = docker_check
        self._config_loader = config_loader or _default_config_loader
        self._spec_set = spec_set if spec_set is not None else build_spec_set()
        self._verify_startup()
        self._register_tools(registrar)

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

    def _register_tools(self, registrar: Any) -> None:
        """Register the wired spec_set's tools against Hermes's tool registry.

        This is the call site that was missing: a real run must register the
        per-action tools (with REAL handlers, not the fail-closed placeholders)
        before any ``run_conversation`` so ``get_tool_definitions`` surfaces them
        and dispatch lands in the wired operation. ``registrar`` defaults to
        Hermes's global ``tools.registry.registry`` in production; tests inject a
        recording registrar so handler-wiring gaps are observable. When no
        registrar is supplied and Hermes is not installed (CI), there is no
        global registry to register against and the remediator cannot run
        anyway, so registration is silently skipped rather than crashing.
        """
        reg = registrar
        if reg is None:
            try:
                reg = _default_registrar()
            except ImportError:
                return
        register_action_tools(reg, self._spec_set)

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
        allowlist = set(allowed) if allowed else set()
        violations = _tool_call_violations(run_result.messages, allowlist)
        if violations:
            names = ", ".join(sorted(violations))
            return Result(
                success=False,
                summary=(
                    f"policy-enforcement breach: denied tool(s) invoked despite "
                    f"allowlist: {names}"
                ),
                breach=True,
            )
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
        """Compose the headless prompt for this remediation attempt.

        The prompt names the permitted tools AND, for reconciliation incidents,
        spells out the exact per-row tool arguments (table/row_id/expected) so a
        real model calls the tool with the right payload on the first turn
        rather than guessing or emitting empty arguments. A live trial against a
        real Hermes instance showed models otherwise call reconcile_table_write
        with empty args on the first turn; making the args explicit avoids that
        wasted round-trip.
        """
        base = (
            f"Remediate incident {incident.id} (source={incident.source}, "
            f"attempt {incident.attempts}). Context: "
            f"{json.dumps(incident.context, default=str)}. "
            f"Permitted actions: {', '.join(allowed) or 'none (lockdown)'}."
        )
        mismatches = (
            incident.context.get("mismatches") if isinstance(incident.context, dict) else None
        )
        if isinstance(mismatches, list) and mismatches and "reconcile_table_write" in allowed:
            rows = ", ".join(_mismatch_row_str(m) for m in mismatches if isinstance(m, dict))
            base += (
                " For each mismatch, call the reconcile_table_write tool with "
                f"those exact arguments: {rows}. Do not ask questions; call the tool."
            )
        return base


def _serialize_history(messages: list[dict[str, Any]]) -> str:
    """Serialize the message history for storage in external_refs."""
    return json.dumps(messages, default=str)


def _mismatch_row_str(m: dict[str, Any]) -> str:
    """Format one mismatch as the exact tool-arg dict the model should call."""
    return (
        "{table: "
        + str(m.get("table"))
        + ", row_id: "
        + str(m.get("row_id"))
        + ", expected: "
        + str(m.get("expected"))
        + "}"
    )


#: Marker Hermes's per-thread tool whitelist writes into the tool result when
#: it blocks a denied tool at invoke time (hermes_cli/plugins.py
#: ``set_thread_tool_whitelist`` / ``get_pre_tool_call_block_message``). A
#: denied tool whose result carries this marker was BLOCKED, not fail-opened.
_WHITELIST_DENIAL_MARKER = "denied: not in this thread's tool whitelist"


def _index_tool_results(messages: list[dict[str, Any]]) -> dict[str, str]:
    """Index ``tool`` role messages by ``tool_call_id`` for pairing with calls.

    Hermes writes one ``{"role":"tool","tool_call_id":...,"content":...}`` per
    tool call immediately after the assistant message holding the tool_calls.
    """
    out: dict[str, str] = {}
    for msg in messages or []:
        if isinstance(msg, dict) and msg.get("role") == "tool":
            cid = msg.get("tool_call_id")
            if isinstance(cid, str):
                out[cid] = str(msg.get("content") or "")
    return out


def _was_blocked_at_invoke(result: str) -> bool:
    """True if the tool result is the per-thread whitelist's denial marker.

    Defense-in-depth (``set_thread_tool_whitelist``) blocks a denied tool BEFORE
    its handler runs and writes this marker into the result — that is the gate
    working, not a fail-open breach.
    """
    return _WHITELIST_DENIAL_MARKER in result


def _tool_call_violations(messages: list[dict[str, Any]], allowlist: set[str]) -> set[str]:
    """Return denied tool names that actually ran (fail-open), not blocked ones.

    Post-run audit: Hermes's pre-call gate is wrapped in ``try/except`` that
    defaults to allowing the call through, so a denied tool can execute if the
    gate throws. Catching that in the message history turns a silent fail-open
    into a recorded breach. Defense-in-depth (per-thread whitelist) blocks a
    denied tool before its handler runs and writes the denial marker into the
    tool result — that is the gate working, NOT a breach. Pair each tool_call
    with its tool result by ``tool_call_id`` to tell blocked from fail-open.

    Fail-closed: an unparseable name or a denied call with no matching tool
    result is a violation (we cannot prove it was blocked).
    """
    tool_results = _index_tool_results(messages)
    violations: set[str] = set()
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        tool_calls = msg.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue
        for tc in tool_calls:
            name = _tool_call_name(tc)
            if name is None:
                violations.add("<unknown-tool>")
                continue
            if name in allowlist:
                continue
            cid = tc.get("id") if isinstance(tc, dict) else None
            result = tool_results.get(cid, "") if isinstance(cid, str) else ""
            if _was_blocked_at_invoke(result):
                continue  # blocked before the handler ran — not a breach
            violations.add(name)
    return violations


def _tool_call_name(tool_call: Any) -> str | None:
    """Extract the function name from an OpenAI-style tool_call, or None."""
    if not isinstance(tool_call, dict):
        return None
    fn = tool_call.get("function")
    name = fn.get("name") if isinstance(fn, dict) else None
    return name if isinstance(name, str) and name else None


def _default_config_loader() -> dict[str, Any]:
    """Load Hermes config from ~/.hermes/config.yaml (lazy import)."""
    from hermes_cli.config import load_config  # type: ignore[import-not-found]

    return dict(load_config())


def _default_registrar() -> Any:
    """Resolve Hermes's global tool registry (lazy import; production only).

    Hermes's ``model_tools.get_tool_definitions`` reads from the global
    ``tools.registry.registry`` singleton, so production registration targets
    that object. Imported lazily so the module (and its tests) load without the
    ``hermes-agent`` package installed.
    """
    from tools.registry import registry  # type: ignore[import-not-found]

    return registry
