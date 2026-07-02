# sentinel

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
sentinel/
├── src/sentinel/           # Installable package: `import sentinel`
│   ├── core/              # Engine, incident model, trust, audit
│   │   ├── engine.py
│   │   ├── incident.py
│   │   ├── trust.py
│   │   └── audit.py
│   ├── interfaces/        # Nine one-method Protocols
│   │   ├── detector.py
│   │   ├── remediator.py
│   │   ├── verifier.py
│   │   ├── enforcer.py
│   │   ├── notifier.py
│   │   ├── issue_tracker.py
│   │   ├── state_store.py
│   │   ├── secret_provider.py
│   │   └── orchestrator.py
│   ├── plugins/          # Plugin implementations (one file per plugin)
│   │   ├── detectors/        # mock, temporal, data_reconciliation
│   │   ├── remediators/      # hermes (primary — see docs/SECURITY.md), mock,
│   │   │                     # shelley, claude_agent_sdk, human_manual
│   │   ├── enforcers/        # noop, agt (policy.yaml + trust
│   │   │                     # ladder — see docs/SECURITY.md)
│   │   ├── notifiers/        # stdout, webhook, slack
│   │   ├── issue_trackers/   # github_issues, linear, jira
│   │   ├── state_stores/     # sqlite_store, postgres_store
│   │   ├── orchestrators/    # simple_loop, temporal
│   │   └── secret_providers/ # env_provider
│   ├── cli/              # `sentinel` command-line interface
│   └── config.py         # Settings loader + default wiring
├── config/                # Data: settings.schema.json and .env.example
├── examples/quickstart/   # One-command demo (no deps, no secrets)
├── docs/                  # PLUGIN_GUIDE.md and SECURITY.md
├── governance/            # Trust ladder and policy examples
├── tests/                 # Contract + plugin tests
└── pyproject.toml         # `pip install -e .` exposes the `sentinel` command
```

## Quickstart

```bash
python examples/quickstart/run.py
```

This runs the engine once with mock plugins and an in-memory SQLite store, then
prints how many incidents were detected, remediated, and resolved.

To install the package and use the CLI:

```bash
pip install -e .
sentinel incidents list
```

## The nine interfaces

| Interface | File | One-line job |
|-----------|------|--------------|
| Detector | `src/sentinel/interfaces/detector.py` | Find problems. |
| Remediator | `src/sentinel/interfaces/remediator.py` | Fix one incident. Hermes plugs in here. |
| Verifier | `src/sentinel/interfaces/verifier.py` | Confirm the fix. |
| Enforcer | `src/sentinel/interfaces/enforcer.py` | Restrict tool surface pre-run. See `docs/SECURITY.md`. |
| Notifier | `src/sentinel/interfaces/notifier.py` | Escalate to humans. |
| IssueTracker | `src/sentinel/interfaces/issue_tracker.py` | Mirror lifecycle externally. |
| StateStore | `src/sentinel/interfaces/state_store.py` | Persist incidents. |
| SecretProvider | `src/sentinel/interfaces/secret_provider.py` | Resolve secrets. |
| Orchestrator | `src/sentinel/interfaces/orchestrator.py` | Run on a schedule. |

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

## Remediation actions

The Hermes remediator exposes one narrow tool per governance action (see
`docs/SECURITY.md`). `reconcile_table_write` reconciles one mismatched DB row
to its canonical value — it only supports tables with a single non-key column
today; multi-column reconciliation is refused until an explicit value mapping is
added.

## CLI usage

```bash
# List incidents
sentinel incidents list

# Show detail
sentinel incidents show mock-0

# Pause and reopen
sentinel incidents pause mock-0 --reason "waiting on upstream"
sentinel incidents reopen mock-0 --reason "upstream is back"

# Print conversation link
sentinel incidents open mock-0

# Soft-pause alias
sentinel incidents deprioritize mock-0 --reason "not urgent"

# Reset global trust after human review
sentinel trust reset A4 --reason "post-incident review complete"
```

The CLI uses only `sentinel.config`, `sentinel.core.engine`, and
`sentinel.core.incident` — it never imports the agent or vendor plugins
directly.

## Add a plugin

Implement the relevant Protocol, add a dotted-path entry to `sentinel.json`, and
run the contract tests. See `docs/PLUGIN_GUIDE.md` for the full guide and
`config/settings.schema.json` for the schema.

## License

MIT — see `LICENSE`.

![CI](https://github.com/sthalatech/sentinel/actions/workflows/ci.yml/badge.svg)
