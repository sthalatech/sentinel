"""Configuration loader and default wiring for sentinel."""

from __future__ import annotations

import importlib
import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

from core.audit import AuditLog
from core.engine import SentinelConfig
from core.incident import Incident
from core.trust import TrustManager
from plugins.detectors.mock_example import MockDetector, default_mock_incident
from plugins.enforcers.noop import NoopEnforcer
from plugins.notifiers.stdout import StdoutNotifier
from plugins.remediators.mock import MockRemediator
from plugins.state_stores.sqlite_store import SqliteAuditSink, SqliteStateStore


@dataclass
class SentinelSettings:
    """Raw configuration values before plugin wiring."""

    detector: dict[str, Any] = field(default_factory=dict)
    remediator: dict[str, Any] = field(default_factory=dict)
    verifier: dict[str, Any] = field(default_factory=dict)
    enforcer: dict[str, Any] = field(default_factory=dict)
    notifier: dict[str, Any] = field(default_factory=dict)
    issue_tracker: dict[str, Any] = field(default_factory=dict)
    state_store: dict[str, Any] = field(default_factory=dict)
    trust: dict[str, Any] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)
    orchestrator: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)


def load_settings(path: str) -> SentinelConfig:
    """Read a JSON config file and wire it into a SentinelConfig."""
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    settings = _raw_to_settings(data)
    return _wire(settings)


def build_default_config(db_path: str = "sentinel.db", interval: float = 60.0) -> SentinelConfig:
    """Return a fully wired SentinelConfig using zero-setup defaults."""
    store = SqliteStateStore(db_path)
    return _build_config(store, interval)


def _raw_to_settings(data: dict[str, Any]) -> SentinelSettings:
    """Map a parsed JSON object into SentinelSettings."""
    settings = SentinelSettings()
    for key in settings.__dataclass_fields__:
        value = data.get(key, {})
        if not isinstance(value, dict):
            raise ValueError(f"config section '{key}' must be an object")
        setattr(settings, key, value)
    return settings


def _wire(settings: SentinelSettings) -> SentinelConfig:
    """Instantiate plugins from settings and return a wired config."""
    store = _load_plugin(settings.state_store)
    audit = AuditLog(_load_plugin(settings.audit, default=_audit_sink(store)))
    trust = TrustManager(store, audit, level=settings.trust.get("level", "A4"))
    return SentinelConfig(
        detector=_load_plugin(settings.detector),
        remediator=_load_plugin(settings.remediator),
        verifier=_load_plugin(settings.verifier),
        enforcer=_load_plugin(settings.enforcer),
        notifier=_load_plugin(settings.notifier),
        issue_tracker=_load_plugin(settings.issue_tracker),
        state_store=store,
        trust=trust,
        audit=audit,
    )


def _build_config(store: SqliteStateStore, interval: float) -> SentinelConfig:
    """Wire all defaults around a given sqlite store."""
    audit = AuditLog(SqliteAuditSink(store))
    trust = TrustManager(store, audit)
    return SentinelConfig(
        detector=MockDetector(count=1, factory=default_mock_incident),
        remediator=MockRemediator(),
        verifier=_MockVerifier(),
        enforcer=NoopEnforcer(),
        notifier=StdoutNotifier(),
        issue_tracker=_MockIssueTracker(),
        state_store=store,
        trust=trust,
        audit=audit,
    )


def _audit_sink(store: SqliteStateStore) -> SqliteAuditSink:
    """Build the default sqlite audit sink from a state store."""
    return SqliteAuditSink(store)


def _load_plugin(spec: dict[str, Any], default: Any = None) -> Any:
    """Import a plugin by dotted path and instantiate it with kwargs."""
    if not spec:
        if default is None:
            raise ValueError("missing plugin config and no default provided")
        return default
    path = spec.get("path")
    if not path:
        raise ValueError("plugin config missing 'path'")
    kwargs = _resolve_secrets(spec.get("kwargs", {}))
    module_name, _, class_name = path.rpartition(".")
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    return cls(**kwargs)


def _resolve_secrets(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Replace secret references with values from environment variables."""
    resolved = {}
    for key, value in kwargs.items():
        if isinstance(value, dict) and value.get("from_env"):
            env_name = value["from_env"]
            resolved[key] = os.environ.get(env_name, "")
        else:
            resolved[key] = value
    return resolved


class _MockVerifier:
    """Default verifier that claims every incident is resolved."""

    def verify(self, incident: Incident) -> bool:
        """Always report the incident as resolved."""
        return True


class _MockIssueTracker:
    """Default no-op issue tracker mirroring incident state."""

    def create(self, incident: Incident) -> str:
        """Pretend to create a tracked issue."""
        return f"mock-tracker:{incident.id}"

    def comment(self, incident: Incident, body: str) -> None:
        """Ignore comments."""
        pass

    def sync_status(self, incident: Incident) -> None:
        """Ignore status syncs."""
        pass
