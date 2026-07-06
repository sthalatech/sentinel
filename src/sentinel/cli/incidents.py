"""Incident management CLI for sentinel."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Sequence

from sentinel.config import build_default_config, load_settings
from sentinel.core.engine import SentinelConfig, apply_status_change
from sentinel.core.incident import Incident, IncidentStatus


def _load_config(path: str | None) -> SentinelConfig:
    """Return a SentinelConfig from a config path or the default wiring."""
    if path is None:
        path = "sentinel.json"
    if pathlib.Path(path).exists():
        return load_settings(path)
    return build_default_config()


def _fmt_incident(incident: Incident) -> str:
    """Return a human-readable summary of an incident."""
    resolved = incident.resolved_at.isoformat() if incident.resolved_at else "-"
    lines = [
        f"id:                  {incident.id}",
        f"source:              {incident.source}",
        f"source_ref:          {incident.source_ref}",
        f"status:              {incident.status.value}",
        f"trust_level_at_open: {incident.trust_level_at_open}",
        f"attempts:            {incident.attempts}",
        f"detected_at:         {incident.detected_at.isoformat()}",
        f"resolved_at:         {resolved}",
        "context:",
        json.dumps(incident.context, indent=2, default=str),
        "external_refs:",
        json.dumps(incident.external_refs, indent=2),
    ]
    return "\n".join(lines)


def _set_status(args: argparse.Namespace, status: IncidentStatus, verb: str) -> None:
    """Apply a status change and print a confirmation message."""
    cfg = _load_config(args.config)
    apply_status_change(
        cfg.state_store,
        cfg.audit,
        cfg.issue_tracker,
        args.id,
        status,
        args.reason,
        "human-cli",
    )
    print(f"{verb} {args.id}")


def _handle_pause(args: argparse.Namespace) -> None:
    """Pause an incident with a human-provided reason."""
    _set_status(args, IncidentStatus.PAUSED, "paused")


def _handle_reopen(args: argparse.Namespace) -> None:
    """Reopen a paused or resolved incident for remediation."""
    _set_status(args, IncidentStatus.REMEDIATING, "reopened")


def _handle_open(args: argparse.Namespace) -> None:
    """Print the conversation link for an incident, if available."""
    cfg = _load_config(args.config)
    incident = cfg.state_store.get(args.id)
    if incident is None:
        print(f"incident not found: {args.id}", file=sys.stderr)
        sys.exit(1)
    link = incident.external_refs.get("conversation", "(no conversation)")
    print(link)


def _handle_deprioritize(args: argparse.Namespace) -> None:
    """Soft-pause an incident with a human-provided reason."""
    _set_status(args, IncidentStatus.PAUSED, "deprioritized (paused)")


def _handle_list(args: argparse.Namespace) -> None:
    """List all known incidents."""
    cfg = _load_config(args.config)
    incidents = cfg.state_store.list()
    if not incidents:
        print("no incidents")
        return
    for incident in incidents:
        print(
            f"{incident.id}\t{incident.source}\t{incident.status.value}\t"
            f"attempts={incident.attempts}"
        )


def _handle_show(args: argparse.Namespace) -> None:
    """Show full detail for a single incident."""
    cfg = _load_config(args.config)
    incident = cfg.state_store.get(args.id)
    if incident is None:
        print(f"incident not found: {args.id}", file=sys.stderr)
        sys.exit(1)
    print(_fmt_incident(incident))


def _add_id_reason(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
) -> argparse.ArgumentParser:
    """Add an incidents subcommand that requires id and --reason."""
    parser = sub.add_parser(name, help=help_text)
    parser.add_argument("id")
    parser.add_argument("--reason", required=True)
    return parser


def _add_id_only(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
) -> argparse.ArgumentParser:
    """Add an incidents subcommand that requires only an id."""
    parser = sub.add_parser(name, help=help_text)
    parser.add_argument("id")
    return parser


def _handle_trust_reset(args: argparse.Namespace) -> None:
    """Reset the global trust level to a chosen level with a reason."""
    cfg = _load_config(args.config)
    cfg.trust.reset(args.level, args.reason, actor="human-cli")
    print(f"trust reset to {args.level}")


def _handle_actions_validate(args: argparse.Namespace) -> None:
    """Validate a remediation actionbook without loading it into a remediator.

    Catches typo'd backend names, lock/prompt overlaps, undeclared params, and
    bad blast-radius tiers before the actionbook is pointed at a live remediator
    -- exactly like odoo-synth rules validate does for the masking rulebook.
    Exits non-zero on any validation error so it is CI-usable.
    """
    from sentinel.plugins.remediators.actionbook import validate_actionbook

    result = validate_actionbook(args.path)
    if result.warnings:
        for w in result.warnings:
            print(f"warn: {w}")
    if result.errors:
        for e in result.errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"actionbook OK: {args.path}")


def _handle_actions_list(args: argparse.Namespace) -> None:
    """List the action names an actionbook declares (for policy-authoring help).

    Prints each action with its backend and blast-radius tier, so a user writing
    governance/policy.example.yaml can see which names to put in which trust
    level's allowed_actions without opening the YAML.
    """
    import yaml

    from sentinel.plugins.remediators.actionbook import validate_actionbook

    result = validate_actionbook(args.path)
    if not result.ok:
        for e in result.errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    raw = yaml.safe_load(pathlib.Path(args.path).read_text(encoding="utf-8")) or {}
    backends = raw.get("backends") or {}
    actions = raw.get("actions") or {}
    for name, adef in actions.items():
        backend = adef.get("backend", "?") if isinstance(adef, dict) else "?"
        blast = adef.get("blast_radius", "?") if isinstance(adef, dict) else "?"
        bdesc = ""
        if isinstance(backends.get(backend), dict):
            bdesc = backends[backend].get("description", "")
        print(f"{name}\tbackend={backend}\tblast={blast}\t{bdesc}")


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with the incidents subcommand tree."""
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel Loop CLI")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to sentinel.json; uses default wiring if omitted and sentinel.json is absent.",
    )

    top = parser.add_subparsers(dest="command", required=True)
    incidents = top.add_parser("incidents", help="Manage incidents.")
    sub = incidents.add_subparsers(dest="incident_command", required=True)

    _add_id_reason(sub, "pause", "Pause an incident.").set_defaults(handler=_handle_pause)
    _add_id_reason(sub, "reopen", "Reopen an incident for remediation.").set_defaults(
        handler=_handle_reopen
    )
    _add_id_only(sub, "open", "Print the incident conversation link.").set_defaults(
        handler=_handle_open
    )
    _add_id_reason(sub, "deprioritize", "Soft-pause an incident (alias for pause).").set_defaults(
        handler=_handle_deprioritize
    )
    sub.add_parser("list", help="List all incidents.").set_defaults(handler=_handle_list)
    _add_id_only(sub, "show", "Show full detail for an incident.").set_defaults(
        handler=_handle_show
    )

    trust = top.add_parser("trust", help="Manage global trust level.")
    trust_sub = trust.add_subparsers(dest="trust_command", required=True)
    reset = trust_sub.add_parser("reset", help="Reset the global trust level.")
    reset.add_argument("level", help="Target trust level, e.g. A4.")
    reset.add_argument("--reason", required=True)
    reset.set_defaults(handler=_handle_trust_reset)

    actions = top.add_parser("actions", help="Validate/list the remediation actionbook.")
    actions_sub = actions.add_subparsers(dest="actions_command", required=True)
    validate = actions_sub.add_parser("validate", help="Validate an actionbook YAML file.")
    validate.add_argument("path", help="Path to the actionbook YAML.")
    validate.set_defaults(handler=_handle_actions_validate)
    listing = actions_sub.add_parser("list", help="List action names an actionbook declares.")
    listing.add_argument("path", help="Path to the actionbook YAML.")
    listing.set_defaults(handler=_handle_actions_list)

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Entrypoint for the sentinel incident CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.handler(args)


if __name__ == "__main__":
    main()
