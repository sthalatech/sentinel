# sentinel-loop

A pluggable, self-healing agent framework for Python. Sentinel Loop runs on a
timer: detect incidents, attempt remediation, verify the fix, and escalate when
needed. Every moving part is a one-method plugin behind a Protocol, so you can
swap in real detectors, remediators, notifiers, and issue trackers without
changing the engine.

## Design principles

1. **Everything is a plugin behind a one-method interface.**
2. **Zero required external infrastructure.** The default wiring uses SQLite and
   stdout; real backends are opt-in plugins.
3. **No secrets in the repo.** Values are resolved at runtime through
   `SecretProvider` instances.
4. **Small functions, no magic.** Public functions stay under 40 lines.
5. **Governance is core.** Trust levels, policy gates, and audit logs are
   first-class concepts.
6. **Human intervention is conversational.** Each incident may carry an
   `external_refs["conversation"]` link for hand-off.

## Repo layout

```
sentinel-loop/
├── core/                  # Engine, incident model, trust, audit
│   ├── engine.py
│   ├── incident.py
│   ├── trust.py
│   └── audit.py
├── interfaces/            # Nine one-method Protocols
│   ├── detector.py
│   ├── remediator.py
│   ├── verifier.py
│   ├── enforcer.py
│   ├── notifier.py
│   ├── issue_tracker.py
│   ├── state_store.py
│   ├── secret_provider.py
│   └── orchestrator.py
├── plugins/               # Core plugins (sqlite, stdout, mock, env secrets)
├── vendors/               # Vendor-specific integrations (GitHub, Slack, ...)
├── cli/                   # `sentinel` command-line interface
│   └── incidents.py
├── examples/quickstart/   # One-command demo
├── config/                # Settings loader, schema, and .env.example
├── docs/                  # PLUGIN_GUIDE.md and SECURITY.md
├── governance/            # Trust ladder and policy examples
└── tests/                 # Contract tests
```

## Quickstart

```bash
python examples/quickstart/run.py
```

This runs the engine once with mock plugins and an in-memory SQLite store, then
prints how many incidents were detected, remediated, and resolved.

## The nine interfaces

| Interface | File | One-line job |
|-----------|------|--------------|
| Detector | `interfaces/detector.py` | Find problems. |
| Remediator | `interfaces/remediator.py` | Fix one incident. |
| Verifier | `interfaces/verifier.py` | Confirm the fix. |
| Enforcer | `interfaces/enforcer.py` | Authorize tool actions. |
| Notifier | `interfaces/notifier.py` | Escalate to humans. |
| IssueTracker | `interfaces/issue_tracker.py` | Mirror lifecycle externally. |
| StateStore | `interfaces/state_store.py` | Persist incidents. |
| SecretProvider | `interfaces/secret_provider.py` | Resolve secrets. |
| Orchestrator | `interfaces/orchestrator.py` | Run on a schedule. |

## Status flow

```
DETECTED → REMEDIATING → VERIFYING → RESOLVED
                              |
                              → ESCALATED

PAUSED      ← human or policy holds the incident
HUMAN_OWNED ← explicitly assigned to a human
```

`PAUSED` and `HUMAN_OWNED` incidents are skipped by the engine until a human
reopens them through the single write path.

## CLI usage

```bash
# List incidents
python -m cli incidents list

# Show detail
python -m cli incidents show mock-0

# Pause and reopen
python -m cli incidents pause mock-0 --reason "waiting on upstream"
python -m cli incidents reopen mock-0 --reason "upstream is back"

# Print conversation link
python -m cli incidents open mock-0

# Soft-pause alias
python -m cli incidents deprioritize mock-0 --reason "not urgent"
```

The CLI uses only `config.settings`, `core.engine`, and `core.incident` — it
never imports the agent or vendor plugins directly.

## Add a plugin

Implement the relevant Protocol, add a dotted-path entry to `sentinel.json`, and
run the contract tests. See `docs/PLUGIN_GUIDE.md` for the full guide and
`config/settings.schema.json` for the schema.

## License

MIT — see `LICENSE`.

![CI](https://github.com/sentinel-loop/sentinel-loop/actions/workflows/ci.yml/badge.svg)
