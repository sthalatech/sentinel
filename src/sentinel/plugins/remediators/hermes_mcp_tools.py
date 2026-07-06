"""One narrow Hermes tool per governance remediation action.

Why this exists (replacing the toolset-routing approach):
  Hermes's built-in ``terminal`` / ``file`` / ``web`` toolsets are *generic
  execution primitives* — ``terminal`` takes an arbitrary ``command`` shell
  string, ``file`` exposes ``patch``/``write_file``. Mapping governance actions
  onto those toolsets (``restart_workflow`` -> ``terminal``, ``roll_back_deployment``
  -> ``terminal``) cannot enforce an action-level distinction: a trust level that
  allows ``restart_workflow`` but denies ``roll_back_deployment`` still hands the
  model a shell, so it can run ``kubectl rollout undo`` (roll_back_deployment's
  underlying operation) regardless of the allow-list. This was confirmed against
  Hermes v0.18.0: ``model_tools.get_tool_definitions(enabled_toolsets=['terminal'])``
  registers ``terminal`` with a free-form ``command`` parameter.

Design:
  Each governance action lives in its OWN Hermes toolset named
  ``sentinel_<action>``, containing exactly one tool named ``<action>``. The
  tool's schema accepts only that action's narrow parameters (e.g.
  ``workflow_id``) and its handler performs exactly that one operation — no
  shell, no file primitives, no capability overlap. ``HermesRemediator`` enables
  one toolset per allowed action, so denying ``roll_back_deployment`` means its
  toolset is never registered for the run and the model has no surface that can
  perform a rollback — not merely a registry that "looks correct".

Hermes toolset filtering is toolset-level only (``get_tool_definitions`` has no
per-tool-name include), so one-toolset-per-action is the granularity primitive.
Handlers dispatch to injectable operation callables and fail closed (refuse) if
no backend is wired, so the module imports cleanly without real Temporal/k8s.

Scope boundary — ``reconcile_table_write`` only supports tables with a single
non-key column today: the ``expected`` value it writes is the comparable value
produced by ``SqliteTableSource.snapshot()``, which is verbatim only for a
single non-key column (a hash for multiple). Multi-column reconciliation is out
of scope until an explicit value mapping is added; the backend refuses it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

#: Type of a narrow operation backend: takes the action's args, returns a result string.
Operation = Callable[..., str]


class ToolRegistrar(Protocol):
    """Hermes ``tools.registry.registry``-shaped registration surface."""

    def register(
        self,
        name: str,
        toolset: str,
        schema: dict[str, Any],
        handler: Callable[..., Any],
        description: str = "",
        **kwargs: Any,
    ) -> None:
        """Register one tool under a toolset (called at module import)."""
        ...


def toolset_for(action: str) -> str:
    """Return the per-action Hermes toolset name for a governance action."""
    return f"sentinel_{action}"


@dataclass(frozen=True)
class ActionToolSpec:
    """Schema + handler for one narrow per-action tool."""

    action: str
    description: str
    schema: dict[str, Any]
    handler: Callable[..., str]


def _refuse(action: str, reason: str) -> Callable[..., str]:
    """Return a handler that fails closed until a real backend is wired.

    Hermes's tool registry dispatches handlers as ``handler(args, **kwargs)``
    where ``args`` is the parsed-arguments dict (see tools/registry.py
    ``ToolRegistry.run`` and tools/mcp_tool.py's dispatch-interface docstring).
    The handler therefore takes one positional dict, not bare keyword args.
    """

    def _h(_args: Any | None = None, **_kwargs: Any) -> str:
        return f"{action}: refused ({reason}); no backend wired"

    return _h


def reconcile_table_write_backend(
    targets_by_table: dict[str, Any],
    valid_row_ids_by_table: dict[str, dict[str, str]] | None = None,
) -> Operation:
    """Return a narrow handler that reconciles one row of a known target table.

    Backs the ``reconcile_table_write`` tool with the same SQLite abstraction
    the detector/verifier use (``SqliteTableSource.write_row``). The handler
    accepts EXACTLY ``{table, row_id, expected}`` and performs that one write;
    it refuses any table not registered in ``targets_by_table`` (fail closed —
    the model cannot write to an arbitrary table), and never accepts or executes
    a shell command or arbitrary SQL. ``targets_by_table`` maps table name to a
    ``DataSource``-with-``write_row`` (e.g. ``SqliteTableSource``) for the live
    DB being reconciled.

    ``valid_row_ids_by_table`` (optional) maps table name to ``{row_id:
    canonical_expected}`` for the current incident's mismatches — the only
    (row_id, expected) pairs a reconcile call should write. When supplied, the
    handler refuses BEFORE the write if either (a) ``row_id`` is not one of the
    mismatched rows (listing the valid ids), or (b) ``expected`` does not match
    the canonical expected value for that row_id (listing the valid value). The
    first trial showed a real model can hallucinate a row_id; the second showed
    it can also write a WRONG expected value to a VALID row_id ("shipped SDR"
    instead of "shipped"), which the handler would have accepted and recorded as
    success. Refusing up front with the valid pair collapses both to one
    correction instead of a corrupted write or a blind retry.
    """

    def _h(args: Any | None = None, **kwargs: Any) -> str:
        # Hermes dispatches handler(args_dict, **kwargs): the parsed tool
        # arguments arrive as the single positional ``args`` dict. Accept both
        # that and bare kwargs (defensive) so the contract holds either way.
        a: dict[str, Any] = {}
        if isinstance(args, dict):
            a.update(args)
        a.update(kwargs)
        return _reconcile_one(targets_by_table, valid_row_ids_by_table or {}, a)

    return _h


def _reconcile_one(
    targets_by_table: dict[str, Any],
    valid_by_table: dict[str, dict[str, str]],
    a: dict[str, Any],
) -> str:
    """Validate one reconcile call and apply it to the registered target."""
    # Validate the exact narrow contract at the handler boundary too, so a
    # malformed call is refused even if it bypassed the tool schema.
    table = a.get("table")
    row_id = a.get("row_id")
    expected = a.get("expected")
    if not (isinstance(table, str) and isinstance(row_id, str) and isinstance(expected, str)):
        return "reconcile_table_write: refused; expected {table,row_id,expected} as strings"
    source = targets_by_table.get(table)
    if source is None:
        return f"reconcile_table_write: refused; table {table!r} not registered"
    valid = valid_by_table.get(table)
    if valid is not None:
        refusal = _validate_against_mismatch_set(table, row_id, expected, valid)
        if refusal is not None:
            return refusal
    try:
        changed = source.write_row(row_id, expected)
    except Exception as exc:  # noqa: BLE001 - surface the failure, never raise
        return f"reconcile_table_write: failed for {table}:{row_id}: {exc}"
    if changed <= 0:
        # No row matched row_id in the target DB (e.g. an id that was valid at
        # incident time but the row was since deleted). Tell the model so it
        # retries with the right id rather than believing the fix landed.
        return f"reconcile_table_write: no row matched {table}:{row_id}; nothing changed"
    return f"reconcile_table_write: reconciled {table}:{row_id}"


def _validate_against_mismatch_set(
    table: str, row_id: str, expected: str, valid: dict[str, str]
) -> str | None:
    """Refuse a (row_id, expected) not in the incident's mismatch set, or None.

    Returns a refusal string if the call should be rejected before writing (with
    the valid ids/values listed as the correction path), else None to proceed.
    Catches both a hallucinated row_id (first-trial finding #3) and a wrong
    expected value on a valid row_id (second-trial finding #6: the model wrote
    "shipped SDR" instead of "shipped").
    """
    if row_id not in valid:
        ids = ", ".join(sorted(valid)) or "(none)"
        return (
            f"reconcile_table_write: refused; row_id {row_id!r} is not one of "
            f"the mismatched rows for table {table!r}. Valid row_ids: {ids}. "
            f"Call again with one of those."
        )
    want = valid[row_id]
    if expected != want:
        return (
            f"reconcile_table_write: refused; expected {expected!r} does not "
            f"match the canonical expected value {want!r} for {table}:{row_id}. "
            f"Call again with expected={want!r}."
        )
    return None


#: Default narrow specs for every governance remediation action. Each tool's
#: schema admits ONLY its action's parameters — no free-form command surface.
default_specs: dict[str, ActionToolSpec] = {
    "restart_workflow": ActionToolSpec(
        action="restart_workflow",
        description="Restart exactly one Temporal workflow by id. No shell access.",
        schema={
            "type": "object",
            "properties": {
                "workflow_id": {"type": "string", "description": "Temporal workflow ID"},
                "reason": {"type": "string", "description": "Why the restart was issued."},
            },
            "required": ["workflow_id"],
            "additionalProperties": False,
        },
        handler=_refuse("restart_workflow", "no temporal backend"),
    ),
    "reconcile_table_write": ActionToolSpec(
        action="reconcile_table_write",
        description="Idempotently reconcile one mismatched DB row. No shell access.",
        schema={
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "row_id": {"type": "string"},
                "expected": {"type": "string", "description": "Canonical expected value."},
            },
            "required": ["table", "row_id", "expected"],
            "additionalProperties": False,
        },
        handler=_refuse("reconcile_table_write", "no db backend"),
    ),
    "clear_cache": ActionToolSpec(
        action="clear_cache",
        description="Invalidate one named cache. No shell access.",
        schema={
            "type": "object",
            "properties": {"cache_name": {"type": "string"}},
            "required": ["cache_name"],
            "additionalProperties": False,
        },
        handler=_refuse("clear_cache", "no cache backend"),
    ),
    "retry_webhook": ActionToolSpec(
        action="retry_webhook",
        description="Re-deliver one failed webhook by id. No shell access.",
        schema={
            "type": "object",
            "properties": {"webhook_id": {"type": "string"}},
            "required": ["webhook_id"],
            "additionalProperties": False,
        },
        handler=_refuse("retry_webhook", "no webhook backend"),
    ),
    "scale_resource": ActionToolSpec(
        action="scale_resource",
        description="Scale one named resource to an exact replica count. No shell access.",
        schema={
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "replicas": {"type": "integer", "minimum": 0},
            },
            "required": ["resource", "replicas"],
            "additionalProperties": False,
        },
        handler=_refuse("scale_resource", "no scaling backend"),
    ),
    "roll_back_deployment": ActionToolSpec(
        action="roll_back_deployment",
        description="Roll one named deployment back to a prior revision. No shell access.",
        schema={
            "type": "object",
            "properties": {
                "deployment": {"type": "string"},
                "revision": {"type": "string"},
            },
            "required": ["deployment"],
            "additionalProperties": False,
        },
        handler=_refuse("roll_back_deployment", "no rollout backend"),
    ),
}


@dataclass
class ToolRegistration:
    """Record of what was registered, for inspection/tests."""

    registered: dict[str, str] = field(default_factory=dict)  # action -> toolset


def register_action_tools(
    registrar: ToolRegistrar,
    specs: dict[str, ActionToolSpec] | None = None,
) -> ToolRegistration:
    """Register one narrow tool per action spec under its own ``sentinel_<action>`` toolset.

    Each tool is registered in a toolset named ``sentinel_<action>`` so that
    enabling a per-action toolset surfaces exactly that one tool and nothing
    else — there is no shared toolset through which a denied action's operation
    could be reached.
    """
    spec_set = specs if specs is not None else default_specs
    record = ToolRegistration()
    for action, spec in spec_set.items():
        toolset = toolset_for(action)
        registrar.register(
            name=action,
            toolset=toolset,
            # Emit the OpenAI tool-schema shape Hermes's registry surfaces to
            # the model: a ``function`` schema carries its arguments under a
            # ``parameters`` key (see tools/terminal_tool.py TERMINAL_SCHEMA:
            # {"name": ..., "description": ..., "parameters": {"type":"object",
            # "properties":..., "required":...}}). The spec's internal
            # ``schema`` is the bare parameters dict ("properties"/"required"/
            # "additionalProperties") — registering it as-is leaves the tool
            # with NO ``parameters`` key, so Hermes's OpenAI-format builder
            # (registry.get_definitions wraps as {"type":"function",
            # "function": schema_with_name}) presents a tool with an empty
            # argument schema. A real model then either cannot call it or has
            # its arguments stripped before dispatch: the handler receives an
            # empty dict and refuses with "expected {table,row_id,expected} as
            # strings" — exactly what the GLM-5.2 live trial caught. Wrapping
            # here (not on the spec, so tests asserting spec.schema["properties"]
            # still hold) surfaces the real narrow parameters to the model and
            # routes the parsed args to the handler.
            schema=_to_openai_function_schema(action, spec),
            handler=spec.handler,
            description=spec.description,
        )
        record.registered[action] = toolset
    return record


def _to_openai_function_schema(action: str, spec: ActionToolSpec) -> dict[str, Any]:
    """Return the OpenAI tool-schema shape Hermes surfaces to the model.

    The spec's ``schema`` is the bare JSON-schema for the arguments (the
    ``parameters`` body); Hermes's registry expects the full function envelope
    (``name`` + ``description`` + ``parameters``), matching how its built-in
    tools register (e.g. terminal_tool.py TERMINAL_SCHEMA). We build that
    envelope here so the model sees the real narrow argument schema and the
    runtime routes parsed args into the handler.
    """
    params = dict(spec.schema)
    # Defensive: if a caller already passed a full envelope (has "parameters"),
    # don't double-wrap. The default specs are bare argument schemas, so this
    # branch is the normal path.
    if "properties" in params or "required" in params or "type" in params:
        return {"name": action, "description": spec.description, "parameters": params}
    return params


def toolsets_for_actions(actions: list[str]) -> list[str]:
    """Map allowed governance actions to their per-action Hermes toolsets."""
    return [toolset_for(a) for a in actions]


def build_spec_set(
    reconcile_targets_by_table: dict[str, Any] | None = None,
    reconcile_valid_row_ids_by_table: dict[str, dict[str, str]] | None = None,
) -> dict[str, ActionToolSpec]:
    """Return the full action spec set with real backends wired where supplied.

    This is the wiring point a real run uses (instead of ``default_specs``
    unmodified): it starts from the narrow per-action ``default_specs`` and, for
    ``reconcile_table_write``, replaces the fail-closed ``_refuse`` placeholder
    with ``reconcile_table_write_backend(targets_by_table, valid_by_table)``
    so the tool actually writes to the target DB via the SQLite abstraction AND
    refuses a row_id/expected pair that is not one of the current incident's
    mismatches (listing the valid ids/values). Other actions keep their
    ``_refuse`` placeholder until their own backends are supplied; the set still
    imports and registers cleanly.

    ``reconcile_targets_by_table`` maps table name -> ``DataSource``-with-
    ``write_row`` (e.g. ``SqliteTableSource``) for the live DB being reconciled.
    ``reconcile_valid_row_ids_by_table`` maps table name -> ``{row_id:
    canonical_expected}`` for the current incident's mismatches (the only
    (row_id, expected) pairs a reconcile call should write). ``None`` (default)
    leaves the placeholder in place — fail closed, never a silent no-op — so a
    caller that forgets to supply targets gets the same explicit refusal as
    before, not a handler that pretends to succeed.
    """
    spec_set = dict(default_specs)
    if reconcile_targets_by_table is not None:
        spec_set["reconcile_table_write"] = wire_backend(
            "reconcile_table_write",
            reconcile_table_write_backend(
                reconcile_targets_by_table, reconcile_valid_row_ids_by_table
            ),
        )
    return spec_set


def wire_backend(action: str, operation: Operation) -> ActionToolSpec:
    """Return a new spec for ``action`` whose handler delegates to ``operation``."""
    base = default_specs[action]
    return ActionToolSpec(
        action=base.action, description=base.description, schema=base.schema, handler=operation
    )


class HermesAIAgentClient:
    """Real Hermes client wrapping ``AIAgent`` with a per-run tool-name allowlist.

    Applies Hermes's ``set_thread_tool_whitelist`` around each run so a denied
    action's tool is blocked at invoke time (``agent_runtime_helpers`` checks
    ``get_pre_tool_call_block_message`` before every tool execution), in addition
    to the registry-level isolation from per-action toolsets. The whitelist is
    cleared in ``finally`` so it can never leak across runs/threads.
    """

    def __init__(self, agent_factory: Callable[[], Any]) -> None:
        self._agent_factory = agent_factory
        self._agent: Any | None = None

    def list_tools(self, enabled_toolsets: list[str]) -> list[str]:
        """Return the real tool names Hermes registers for these toolsets."""
        from model_tools import get_tool_definitions  # type: ignore[import-not-found]

        defs = get_tool_definitions(enabled_toolsets=enabled_toolsets, quiet_mode=True)
        return [d["function"]["name"] for d in defs]

    def run(
        self,
        message: str,
        *,
        enabled_toolsets: list[str],
        tool_allowlist: set[str] | None,
        skip_memory: bool,
        conversation_history: list[dict[str, Any]] | None,
        timeout_s: float | None = None,
    ) -> Any:
        """Run one headless turn under a per-tool-name invoke-time allowlist.

        Bounded by ``timeout_s`` via a worker-thread join (Hermes's
        ``run_conversation`` has no native cancel); see ``_resolve_run_result``
        for the timeout/abort/fail-open handling and the cross-thread caveat.
        """
        import threading

        from hermes_cli.plugins import (  # type: ignore[import-not-found]
            clear_thread_tool_whitelist,
            set_thread_tool_whitelist,
        )

        if self._agent is None:
            self._agent = self._agent_factory()
        if tool_allowlist is not None:
            set_thread_tool_whitelist(tool_allowlist)
        box: dict[str, Any] = {}
        worker = threading.Thread(
            target=_run_conversation_into,
            args=(self._agent, message, conversation_history, box),
            daemon=True,
        )
        worker.start()
        worker.join(timeout_s)
        if tool_allowlist is not None:
            clear_thread_tool_whitelist()
        return _resolve_run_result(box, worker.is_alive(), timeout_s)


def _run_conversation_into(
    agent: Any, message: str, history: list[dict[str, Any]] | None, box: dict[str, Any]
) -> None:
    """Run one Hermes turn, capturing result/exception into ``box`` for the caller."""
    try:
        box["result"] = agent.run_conversation(user_message=message, conversation_history=history)
    except BaseException as exc:  # noqa: BLE001 - surface every failure to the caller
        box["exc"] = exc


def _resolve_run_result(box: dict[str, Any], timed_out: bool, timeout_s: float | None) -> Any:
    """Turn the worker's captured box into a HermesRunResult or raise.

    Raises ``TimeoutError`` if the worker is still alive (turn did not return in
    ``timeout_s``), re-raises any exception the worker captured, raises
    ``RuntimeError`` for a non-retryable abort (Hermes marks those
    ``completed=False`` / ``failed=True`` with the error in ``final_response`` —
    treating that as a normal result would record a provider billing failure as
    success=True, a fail-open the second live trial caught on HTTP 402), else
    builds the HermesRunResult from the completed turn.
    """
    from sentinel.plugins.remediators.hermes import HermesRunResult

    if timed_out:
        raise TimeoutError(f"hermes run_conversation did not return within {timeout_s}s")
    if box.get("exc") is not None:
        raise box["exc"]
    result = box.get("result") or {}
    if result.get("completed") is False or result.get("failed") is True:
        err = str(
            result.get("error") or result.get("final_response") or "hermes run did not complete"
        )
        raise RuntimeError(f"hermes run aborted (not completed): {err}")
    final = str(result.get("response") or result.get("final_response") or "")
    messages = list(result.get("messages") or [])
    return HermesRunResult(final_response=final, messages=messages)
