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
    """Return a handler that fails closed until a real backend is wired."""

    def _h(**_kwargs: Any) -> str:
        return f"{action}: refused ({reason}); no backend wired"

    return _h


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
            schema=spec.schema,
            handler=spec.handler,
            description=spec.description,
        )
        record.registered[action] = toolset
    return record


def toolsets_for_actions(actions: list[str]) -> list[str]:
    """Map allowed governance actions to their per-action Hermes toolsets."""
    return [toolset_for(a) for a in actions]


def wire_backend(action: str, operation: Operation) -> ActionToolSpec:
    """Return a new spec for ``action`` whose handler delegates to ``operation``."""
    base = default_specs[action]
    return ActionToolSpec(
        action=base.action, description=base.description, schema=base.schema, handler=operation
    )
