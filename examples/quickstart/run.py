"""One-command quickstart for sentinel.

Run with no arguments:

    python examples/quickstart/run.py

This uses the zero-setup default wiring (mock detector, remediator, verifier,
enforcer, notifier, issue tracker, sqlite state store, audit, and trust). It
runs a single pass of the engine and prints a short report.

To swap in real plugins, write a `sentinel.json` config that points to your own
classes by dotted import path (see `config/settings.schema.json` for the schema
and `docs/PLUGIN_GUIDE.md` for how to implement a plugin).
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

from sentinel.config import build_default_config
from sentinel.core.engine import SentinelConfig, run_once
from sentinel.core.incident import IncidentStatus


def _summarize_report(cfg: SentinelConfig) -> str:
    """Return a short human-readable summary after one engine pass."""
    incidents = cfg.state_store.list()
    detected = len(incidents)
    resolved = sum(1 for i in incidents if i.status == IncidentStatus.RESOLVED)
    remediated = sum(1 for i in incidents if i.status != IncidentStatus.DETECTED)
    return (
        f"Sentinel Loop quickstart complete: "
        f"{detected} detected, {remediated} remediated, {resolved} resolved."
    )


def main() -> None:
    """Run one engine pass with the default wiring and print a summary."""
    cfg = build_default_config(db_path=":memory:", interval=60.0)
    run_once(cfg)
    print(_summarize_report(cfg))


if __name__ == "__main__":
    main()
