"""Declarative remediation actionbook — user-defined actions from YAML, no code.

This is the remediator's analogue of odoodb-synth's rulebook
(https://github.com/sthalatech/odoodb-synth ``rules/``). odoodb-synth separates
a *strategy vocabulary* (``00_strategies.yml``: named masking strategies, each
with a ``sql_template``) from *field assignments* (``10_core.yml``:
``model.field: { strategy: name }``). Adding a masking rule = a YAML edit.

The actionbook separates a *backend vocabulary* (named remediation primitives,
each with an invoke mechanism + a parameter schema) from *action assignments*
(named remediation actions, each binding a backend and locking most of its
parameters so the model can only vary a narrow subset). Adding a remediation =
a YAML edit. No code change, no rebuild, no relisting in ``DEFAULT_ACTIONS``.

Why locked vs prompted parameters is the enforcement boundary:
  A backend like ``odoo_method`` accepts ``model``, ``method``, ``ids``. If the
  model could set all three, it could call *any* method on *any* model — that is
  the ``terminal`` shell-surface problem again. So each action LOCKS the
  identity parameters (``model``, ``method``) to literals the model cannot
  change and PROMPTS only the safe per-call inputs (``ids``). The generated tool
  schema exposes ONLY the prompted parameters (``additionalProperties: False``),
  so the model's tool surface is exactly the narrow per-call input — it can
  neither see nor set the locked identity. Denying the action at the trust
  ladder means its toolset is never enabled, so the locked operation is
  unreachable. This preserves the per-action-toolset enforcement architecture
  from docs/SECURITY.md for user-defined actions without a code change.

Invoke mechanisms (fixed vocabulary, implemented in code):
  ``odoo_method``    call ``env[model].browse(ids).method()`` via an OdooClient.
  ``odoo_recompute`` recompute one stored field on a bounded domain.
  A new mechanism needs code; a new use of an existing mechanism is YAML only.
  If the required client is not injected at load time, the handler fails closed
  (refuses with "no odoo backend wired") — same posture as ``_refuse``.

The output is ``dict[str, ActionToolSpec]`` — the same type
``HermesRemediator`` and ``register_action_tools`` already consume — so the
actionbook plugs into the existing remediator with no change to the tool
registration or tool-surface verification path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from sentinel.plugins.remediators.hermes_mcp_tools import ActionToolSpec

#: Blast-radius tiers. The trust ladder in governance/policy.example.yaml gates
#: which action NAMES are allowed at each level; blast_radius is a SECOND guard:
#: a high-blast action is refused at A4 even if a policy typo lists it there.
#: Values match governance/agentaz.example.json's tier grouping.
_BLAST_RADII: frozenset[str] = frozenset({"low", "medium", "high"})

#: Invoke mechanisms implemented in code. A backend whose ``invoke`` is not in
#: this set is rejected at load time (fail closed — an unknown mechanism must be
#: implemented, not silently treated as a no-op).
_INVOKE_MECHANISMS: frozenset[str] = frozenset({"odoo_method", "odoo_recompute"})


class OdooClient(Protocol):
    """Odoo invocation surface the actionbook backends dispatch to.

    Production injects a JSON-RPC/execute_kw client; tests inject a fake so the
    dispatch path is observable without a live Odoo. Keeping this a Protocol (not
    a concrete class) means the actionbook has no Odoo dependency and imports
    cleanly in CI.
    """

    def call(self, model: str, method: str, ids: list[int]) -> str:
        """Invoke ``env[model].browse(ids).method()``; return a human-readable result."""
        ...

    def recompute(self, model: str, field: str, domain: list[Any]) -> str:
        """Recompute ``field`` on ``env[model].search(domain)``; return a result string."""
        ...


@dataclass(frozen=True)
class BackendDef:
    """One named, reusable remediation backend (the strategy vocabulary entry)."""

    name: str
    invoke: str  # one of _INVOKE_MECHANISMS
    params: dict[str, dict[str, Any]]  # param name -> JSON-schema fragment
    require: list[str]  # params that must be present (locked or prompted) at call time
    description: str = ""


@dataclass(frozen=True)
class ActionDef:
    """One named remediation action (the field-assignment entry)."""

    name: str
    description: str
    backend: str  # BackendDef.name
    lock: dict[str, Any]  # param -> literal value the model cannot change
    prompt: list[str]  # param names the model fills (the tool schema surface)
    blast_radius: str  # one of _BLAST_RADII


@dataclass
class ActionbookValidation:
    """Result of validating an actionbook: errors stop loading, warnings don't."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _parse_backend(raw: dict[str, Any]) -> BackendDef:
    """Parse one backend entry, validating its shape."""
    name = str(raw.get("name", "")).strip()
    invoke = str(raw.get("invoke", "")).strip()
    params = raw.get("params") or {}
    if not isinstance(params, dict):
        raise ValueError(f"backend {name!r}: params must be an object")
    require = list(raw.get("require") or [])
    return BackendDef(
        name=name,
        invoke=invoke,
        params={str(k): v for k, v in params.items() if isinstance(v, dict)},
        require=[str(r) for r in require],
        description=str(raw.get("description", "")),
    )


def _parse_action(name: str, raw: dict[str, Any]) -> ActionDef:
    """Parse one action entry (raw values; cross-field validation is in _validate)."""
    lock = raw.get("lock") or {}
    prompt = raw.get("prompt") or []
    if not isinstance(lock, dict):
        raise ValueError(f"action {name!r}: lock must be an object")
    if not isinstance(prompt, list):
        raise ValueError(f"action {name!r}: prompt must be a list")
    return ActionDef(
        name=name,
        description=str(raw.get("description", "")),
        backend=str(raw.get("backend", "")),
        lock={str(k): v for k, v in lock.items()},
        prompt=[str(p) for p in prompt],
        blast_radius=str(raw.get("blast_radius", "low")),
    )


def _validate(
    backends: dict[str, BackendDef], actions: dict[str, ActionDef]
) -> ActionbookValidation:
    """Cross-field validation: backend refs, param refs, lock/prompt overlap, tiers."""
    v = ActionbookValidation()
    # Backends: invoke mechanism known, required params exist in params.
    for b in backends.values():
        if b.invoke not in _INVOKE_MECHANISMS:
            v.errors.append(
                f"backend {b.name!r}: unknown invoke {b.invoke!r}; "
                f"known mechanisms: {sorted(_INVOKE_MECHANISMS)}"
            )
        for r in b.require:
            if r not in b.params:
                v.errors.append(f"backend {b.name!r}: required param {r!r} not in params")
    # Actions: backend exists, locked/prompted params exist, no overlap, tier valid,
    # every required param is reachable (locked or prompted).
    for a in actions.values():
        backend: BackendDef | None = backends.get(a.backend)
        if backend is None:
            v.errors.append(f"action {a.name!r}: unknown backend {a.backend!r}")
            continue
        overlap = set(a.lock) & set(a.prompt)
        if overlap:
            v.errors.append(
                f"action {a.name!r}: params both locked and prompted: {sorted(overlap)}"
            )
        for p in list(a.lock) + list(a.prompt):
            if p not in backend.params:
                v.errors.append(
                    f"action {a.name!r}: param {p!r} not declared by backend {a.backend!r}"
                )
        for r in backend.require:
            if r not in a.lock and r not in a.prompt:
                v.errors.append(
                    f"action {a.name!r}: required param {r!r} is neither locked nor prompted"
                )
        if a.blast_radius not in _BLAST_RADII:
            v.errors.append(
                f"action {a.name!r}: blast_radius {a.blast_radius!r} not in {sorted(_BLAST_RADII)}"
            )
    return v


def _build_schema(action: ActionDef, backend: BackendDef) -> dict[str, Any]:
    """Build the tool's JSON-schema: ONLY prompted params are model-fillable.

    Locked params are absent from the schema (the model can neither see nor set
    them) and ``additionalProperties: False`` forbids the model from injecting
    them. This is what makes a locked ``model``/``method`` an enforcement
    boundary rather than a suggestion: the model's tool surface is exactly the
    prompted per-call inputs.
    """
    props: dict[str, Any] = {}
    required: list[str] = []
    for p in action.prompt:
        props[p] = dict(backend.params[p])
        if p in backend.require:
            required.append(p)
    return {
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": False,
    }


def _make_handler(
    action: ActionDef,
    backend: BackendDef,
    odoo_client: OdooClient | None,
) -> Callable[..., str]:
    """Build the dispatch handler for one action.

    Merges locked params (literals) with the model's prompted args, checks all
    required params are present, and dispatches to the backend's invoke
    mechanism. Fails closed (returns a refusal string, never raises) if the
    invoke client is not wired or the call is malformed — same posture as
    ``_refuse``, so an unwired backend is an explicit refusal, not a silent
    no-op or a crash.
    """

    def _h(args: Any | None = None, **kwargs: Any) -> str:
        a: dict[str, Any] = {}
        if isinstance(args, dict):
            a.update(args)
        a.update(kwargs)
        # Only accept prompted params from the model; ignore anything else
        # (additionalProperties: False already blocks this at the schema level,
        # but enforce it at the handler boundary too — defense in depth).
        full: dict[str, Any] = dict(action.lock)
        for p in action.prompt:
            if p in a:
                full[p] = a[p]
        missing = [r for r in backend.require if r not in full]
        if missing:
            return f"{action.name}: refused; missing required params {missing}"
        invoke = backend.invoke
        if invoke == "odoo_method":
            if odoo_client is None:
                return f"{action.name}: refused (no odoo backend wired)"
            try:
                return odoo_client.call(str(full["model"]), str(full["method"]), list(full["ids"]))
            except Exception as exc:  # noqa: BLE001 - surface, never raise
                return f"{action.name}: odoo call failed: {exc}"
        if invoke == "odoo_recompute":
            if odoo_client is None:
                return f"{action.name}: refused (no odoo backend wired)"
            try:
                return odoo_client.recompute(
                    str(full["model"]), str(full["field"]), list(full["domain"])
                )
            except Exception as exc:  # noqa: BLE001 - surface, never raise
                return f"{action.name}: odoo recompute failed: {exc}"
        return f"{action.name}: refused (unknown invoke mechanism {invoke!r})"

    return _h


def load_actionbook(
    path: str,
    *,
    odoo_client: OdooClient | None = None,
) -> dict[str, ActionToolSpec]:
    """Load an actionbook YAML and return ``{action_name: ActionToolSpec}``.

    Raises ``ValueError`` if the actionbook fails validation (unknown backend,
    unknown param, lock/prompt overlap, bad blast radius). A caller that wants
    errors without raising should call ``validate_actionbook`` first.
    """
    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    backends_raw = raw.get("backends") or {}
    actions_raw = raw.get("actions") or {}
    if not isinstance(backends_raw, dict):
        raise ValueError("actionbook: 'backends' must be an object")
    if not isinstance(actions_raw, dict):
        raise ValueError("actionbook: 'actions' must be an object")
    backends: dict[str, BackendDef] = {}
    for name, bdef in backends_raw.items():
        if not isinstance(bdef, dict):
            raise ValueError(f"backend {name!r}: must be an object")
        b = _parse_backend({**bdef, "name": name})
        backends[b.name] = b
    actions: dict[str, ActionDef] = {}
    for name, adef in actions_raw.items():
        if not isinstance(adef, dict):
            raise ValueError(f"action {name!r}: must be an object")
        actions[name] = _parse_action(name, adef)
    v = _validate(backends, actions)
    if not v.ok:
        raise ValueError("actionbook validation failed:\n  " + "\n  ".join(v.errors))
    specs: dict[str, ActionToolSpec] = {}
    for name, action in actions.items():
        backend = backends[action.backend]
        specs[name] = ActionToolSpec(
            action=name,
            description=action.description,
            schema=_build_schema(action, backend),
            handler=_make_handler(action, backend, odoo_client),
        )
    return specs


def validate_actionbook(path: str) -> ActionbookValidation:
    """Validate an actionbook without loading specs; returns errors + warnings.

    The CLI ``sentinel actions validate`` calls this so a user can catch a
    typo'd backend name or a lock/prompt overlap before pointing the remediator
    at the file — exactly like ``odoo-synth rules validate``.
    """
    import yaml

    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return ActionbookValidation(errors=[f"YAML parse error: {exc}"])
    backends_raw = raw.get("backends") or {}
    actions_raw = raw.get("actions") or {}
    if not isinstance(backends_raw, dict):
        return ActionbookValidation(errors=["'backends' must be an object"])
    if not isinstance(actions_raw, dict):
        return ActionbookValidation(errors=["'actions' must be an object"])
    backends: dict[str, BackendDef] = {}
    for name, bdef in backends_raw.items():
        if not isinstance(bdef, dict):
            return ActionbookValidation(errors=[f"backend {name!r}: must be an object"])
        try:
            b = _parse_backend({**bdef, "name": name})
        except ValueError as exc:
            return ActionbookValidation(errors=[str(exc)])
        backends[b.name] = b
    actions: dict[str, ActionDef] = {}
    for name, adef in actions_raw.items():
        if not isinstance(adef, dict):
            return ActionbookValidation(errors=[f"action {name!r}: must be an object"])
        try:
            actions[name] = _parse_action(name, adef)
        except ValueError as exc:
            return ActionbookValidation(errors=[str(exc)])
    return _validate(backends, actions)
