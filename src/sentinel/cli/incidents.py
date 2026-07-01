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

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Entrypoint for the sentinel incident CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.handler(args)


if __name__ == "__main__":
    main()
