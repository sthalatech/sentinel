# Plugin Guide

Sentinel Loop is built from nine one-method interfaces. A plugin is any class
that satisfies one of these Protocols. No inheritance is required.

## The interfaces

| Interface | One-line job |
|-----------|--------------|
| `interfaces.detector.Detector` | Find problems, cheaply and deterministically. |
| `interfaces.remediator.Remediator` | Fix one incident, gated by an enforcer. |
| `interfaces.verifier.Verifier` | Re-run the original check to confirm resolution. |
| `interfaces.enforcer.Enforcer` | Authorize every tool action before it runs. |
| `interfaces.notifier.Notifier` | Escalate an event to a human, fire-and-forget. |
| `interfaces.issue_tracker.IssueTracker` | Mirror incident lifecycle into an external tracker. |
| `interfaces.state_store.StateStore` | Persist incidents, trust level, and audit trail. |
| `interfaces.secret_provider.SecretProvider` | Resolve secret values by name at runtime. |
| `interfaces.orchestrator.Orchestrator` | Run the loop on a schedule with retry/backoff. |

Every interface exposes exactly one public method. That is the framework's
central design rule: *everything is a one-method interface*.

## Implementing a plugin

Implement a Protocol by writing a class whose public methods match the
Protocol signatures. You do not need to inherit from the Protocol.

Example: a custom detector in `my_project/detectors/stale_workflow.py`:

```python
from __future__ import annotations
from datetime import datetime, timezone
from core.incident import Incident, IncidentStatus
from interfaces.detector import Detector

class StaleWorkflowDetector(Detector):
    def detect(self) -> list[Incident]:
        stale = self._find_stale()  # your own logic
        return [
            Incident(
                id=f"stale-{run.id}",
                source="stale_workflow",
                source_ref=str(run.id),
                status=IncidentStatus.DETECTED,
                trust_level_at_open="A4",
                attempts=0,
                detected_at=datetime.now(timezone.utc),
                resolved_at=None,
                context={"run_id": run.id, "age_hours": run.age_hours},
                external_refs={"conversation": run.slack_thread_url},
            )
            for run in stale
        ]
```

## Registering a plugin in config

Plugins are loaded from `sentinel.json` by dotted import path and constructor
keyword arguments. The shape is defined in `config/settings.schema.json`.

```json
{
  "detector": {
    "path": "my_project.detectors.stale_workflow.StaleWorkflowDetector",
    "kwargs": {"max_age_hours": 24}
  },
  "notifier": {
    "path": "sentinel.plugins.notifiers.slack.SlackNotifier",
    "kwargs": {
      "secret_provider": {"path": "sentinel.plugins.secret_providers.env_provider.EnvSecretProvider"},
      "webhook_env": "SLACK_WEBHOOK_URL"
    }
  }
}
```

Secrets are referenced with `{"from_env": "VAR_NAME"}` instead of literal
values. The loader resolves them from the environment at startup. No secret
values belong in `sentinel.json`.

## Running contract tests

The repository includes contract tests that exercise the core assumptions for
any detector, remediator, state store, and enforcer. Run the suite against your
new plugin with pytest:

```bash
pip install -e ".[dev]"
pytest tests/ plugins/my_plugin/tests/
```

Before submitting a plugin, run:

```bash
ruff check .
black --check .
mypy .
pytest
```

Keep public functions under 40 lines, add one-line docstrings, and never check
in commented-out code or TODO markers.
