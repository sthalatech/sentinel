"""Tests for the declarative remediation actionbook (config/actions.example.yml).

The actionbook is the remediator's analogue of odoodb-synth's rulebook: a user
defines remediation actions in YAML (backends + action assignments) and the
remediator builds narrow per-action tools from it with no code change. These
tests pin the load/validate/build contract so a community user's YAML-driven
workflow is safe: unknown backends/params/blast tiers fail closed, locked
params never appear in the model's tool schema, and dispatch lands in the
injected OdooClient.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.plugins.remediators.actionbook import (
    load_actionbook,
    validate_actionbook,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "config" / "actions.example.yml"


class _FakeOdoo:
    """Recording OdooClient so dispatch is observable without a live Odoo."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, list[int]]] = []
        self.recomputes: list[tuple[str, str, list]] = []

    def call(self, model: str, method: str, ids: list[int]) -> str:
        self.calls.append((model, method, ids))
        return f"called {model}.{method}({ids})"

    def recompute(self, model: str, field: str, domain: list) -> str:
        self.recomputes.append((model, field, domain))
        return f"recomputed {model}.{field} on {len(domain)}-domain"


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "actions.yml"
    p.write_text(body)
    return p


_GOOD = """
backends:
  odoo_method:
    invoke: odoo_method
    params:
      model:  { type: string }
      method: { type: string }
      ids:    { type: array, items: { type: integer } }
    require: [model, method, ids]
actions:
  requeue_queue_job:
    description: Requeue one stuck queue.job by id.
    backend: odoo_method
    lock:    { model: queue.job, method: requeue_job }
    prompt:  [ids]
    blast_radius: low
"""


def test_example_actionbook_validates() -> None:
    """The shipped example actionbook must validate clean (community deliverable)."""
    result = validate_actionbook(str(EXAMPLE))
    assert result.ok, result.errors


def test_load_builds_spec_per_action(tmp_path: Path) -> None:
    """load_actionbook returns one ActionToolSpec per action, keyed by name."""
    p = _write(tmp_path, _GOOD)
    specs = load_actionbook(str(p))
    assert set(specs) == {"requeue_queue_job"}
    spec = specs["requeue_queue_job"]
    assert spec.action == "requeue_queue_job"
    props = spec.schema["properties"]
    assert set(props) == {"ids"}
    assert spec.schema["additionalProperties"] is False
    assert spec.schema["required"] == ["ids"]


def test_locked_params_are_absent_from_model_surface(tmp_path: Path) -> None:
    """A locked param must never appear in the tool schema the model sees."""
    p = _write(tmp_path, _GOOD)
    specs = load_actionbook(str(p))
    schema = specs["requeue_queue_job"].schema
    assert "model" not in schema["properties"]
    assert "method" not in schema["properties"]


def test_dispatch_merges_locked_and_prompted(tmp_path: Path) -> None:
    """The handler merges locked literals with the model's prompted args and dispatches."""
    p = _write(tmp_path, _GOOD)
    odoo = _FakeOdoo()
    specs = load_actionbook(str(p), odoo_client=odoo)
    out = specs["requeue_queue_job"].handler({"ids": [42, 43]})
    assert "called queue.job.requeue_job([42, 43])" in out
    assert odoo.calls == [("queue.job", "requeue_job", [42, 43])]


def test_dispatch_ignores_model_attempting_locked_param(tmp_path: Path) -> None:
    """If the model injects a locked param, it is ignored (defense in depth)."""
    p = _write(tmp_path, _GOOD)
    odoo = _FakeOdoo()
    specs = load_actionbook(str(p), odoo_client=odoo)
    out = specs["requeue_queue_job"].handler(
        {"ids": [1], "model": "account.move", "method": "button_draft"}
    )
    assert odoo.calls == [("queue.job", "requeue_job", [1])]
    assert "account.move" not in out


def test_unwired_odoo_fails_closed(tmp_path: Path) -> None:
    """No odoo_client injected = explicit refusal, not a silent no-op or crash."""
    p = _write(tmp_path, _GOOD)
    specs = load_actionbook(str(p))
    out = specs["requeue_queue_job"].handler({"ids": [1]})
    assert "refused" in out and "no odoo backend" in out


def test_missing_required_prompted_param_refused(tmp_path: Path) -> None:
    """A required prompted param the model omitted is refused, not defaulted."""
    p = _write(tmp_path, _GOOD)
    odoo = _FakeOdoo()
    specs = load_actionbook(str(p), odoo_client=odoo)
    out = specs["requeue_queue_job"].handler({})
    assert "refused" in out and "missing" in out
    assert odoo.calls == []


def test_unknown_backend_rejected(tmp_path: Path) -> None:
    """An action referencing an undeclared backend fails validation."""
    p = _write(
        tmp_path,
        _GOOD.replace("backend: odoo_method\n    lock:", "backend: nope\n    lock:"),
    )
    result = validate_actionbook(str(p))
    assert not result.ok
    assert any("unknown backend" in e for e in result.errors)


def test_lock_prompt_overlap_rejected(tmp_path: Path) -> None:
    """A param both locked and prompted is ambiguous and rejected."""
    body = _GOOD.replace("    prompt:  [ids]\n", "    prompt:  [ids, model]\n")
    p = _write(tmp_path, body)
    result = validate_actionbook(str(p))
    assert not result.ok
    assert any("both locked and prompted" in e for e in result.errors)


def test_required_param_neither_locked_nor_prompted_rejected(tmp_path: Path) -> None:
    """A backend-required param that is neither locked nor prompted is a gap."""
    body = _GOOD.replace("    lock:    { model: queue.job, method: requeue_job }\n", "")
    p = _write(tmp_path, body)
    with pytest.raises(ValueError, match="neither locked nor prompted"):
        load_actionbook(str(p))


def test_bad_blast_radius_rejected(tmp_path: Path) -> None:
    """blast_radius must be one of low/medium/high."""
    body = _GOOD.replace("    blast_radius: low\n", "    blast_radius: nuclear\n")
    p = _write(tmp_path, body)
    result = validate_actionbook(str(p))
    assert not result.ok
    assert any("blast_radius" in e for e in result.errors)


def test_unknown_invoke_mechanism_rejected(tmp_path: Path) -> None:
    """A backend whose invoke is not implemented in code fails closed at load."""
    body = _GOOD.replace("    invoke: odoo_method\n", "    invoke: arbitrary_shell\n")
    p = _write(tmp_path, body)
    result = validate_actionbook(str(p))
    assert not result.ok
    assert any("unknown invoke" in e for e in result.errors)


def test_odoo_recompute_dispatch(tmp_path: Path) -> None:
    """The odoo_recompute mechanism routes to OdooClient.recompute."""
    body = """
backends:
  odoo_recompute:
    invoke: odoo_recompute
    params:
      model:  { type: string }
      field:  { type: string }
      domain: { type: array }
    require: [model, field, domain]
actions:
  recompute_stored_field:
    description: Recompute one stored field on a bounded domain.
    backend: odoo_recompute
    prompt:  [model, field, domain]
    blast_radius: low
"""
    p = _write(tmp_path, body)
    odoo = _FakeOdoo()
    specs = load_actionbook(str(p), odoo_client=odoo)
    out = specs["recompute_stored_field"].handler(
        {"model": "account.move", "field": "amount_total", "domain": ["id", "in", [1, 2]]}
    )
    assert "recomputed account.move.amount_total" in out
    assert odoo.recomputes == [("account.move", "amount_total", ["id", "in", [1, 2]])]


def test_cli_actions_validate_succeeds_on_example() -> None:
    """sentinel actions validate exits 0 on the shipped example."""
    from sentinel.cli.incidents import main

    try:
        main(["actions", "validate", str(EXAMPLE)])
    except SystemExit as exc:
        assert exc.code == 0


def test_cli_actions_validate_fails_on_bad_actionbook(tmp_path: Path) -> None:
    """sentinel actions validate exits non-zero on a broken actionbook."""
    p = _write(
        tmp_path, _GOOD.replace("backend: odoo_method\n    lock:", "backend: nope\n    lock:")
    )
    from sentinel.cli.incidents import main

    with pytest.raises(SystemExit) as exc:
        main(["actions", "validate", str(p)])
    assert exc.value.code == 1


def test_cli_actions_list_lists_example_actions() -> None:
    """sentinel actions list prints every action with its backend + blast tier."""
    from sentinel.cli.incidents import main

    main(["actions", "list", str(EXAMPLE)])
