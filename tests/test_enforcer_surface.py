"""Tests for the additive allowed_actions() surface + audit mirroring."""

from __future__ import annotations

from pathlib import Path

from sentinel.core.audit import AuditEntry, AuditLog
from sentinel.core.incident import Decision
from sentinel.plugins.enforcers.agt import AGTEnforcer
from sentinel.plugins.enforcers.noop import NoopEnforcer

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = str(REPO_ROOT / "governance" / "policy.example.yaml")


class _FakeTrustStore:
    """Minimal trust store for AGTEnforcer tests."""

    def __init__(self, level: str = "A4") -> None:
        self._level = level

    def set_trust(self, level: str) -> None:
        """Persist the global trust level."""
        self._level = level

    def get_trust(self) -> str:
        """Return the stored global trust level."""
        return self._level


class _ListSink:
    """In-memory AuditSink that records every appended entry in order."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def append(self, entry: AuditEntry) -> None:
        """Record one audit entry."""
        self.entries.append(entry)

    def last_entry(self) -> AuditEntry | None:
        """Return the most recent entry, or None when empty."""
        return self.entries[-1] if self.entries else None


def test_allowed_actions_a4_surface() -> None:
    """allowed_actions returns the A4 permitted-without-approval set."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A4"))
    assert set(enf.allowed_actions("A4")) == {
        "requeue_queue_job",
        "retry_mail_queue",
        "reset_cron_lock",
        "recompute_stored_field",
    }


def test_allowed_actions_a1_lockdown_is_empty() -> None:
    """At A1 lockdown the allowed surface is empty."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A1"))
    assert enf.allowed_actions("A1") == []


def test_allowed_actions_a3_includes_scale_and_rollback() -> None:
    """A3 broadens the surface to reconcile_move_line."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A3"))
    actions = set(enf.allowed_actions("A3"))
    assert "reconcile_move_line" in actions


def test_noop_enforcer_allowed_actions_is_empty() -> None:
    """NoopEnforcer exposes an empty allowed surface (it does not gate)."""
    assert NoopEnforcer().allowed_actions("A4") == []


def test_authorize_mirrors_into_audit_chain() -> None:
    """Each authorize() decision appends a hash-linked enforcement entry."""
    sink = _ListSink()
    audit = AuditLog(sink)
    enf = AGTEnforcer(
        policy_path=POLICY,
        trust_store=_FakeTrustStore("A4"),
        audit=audit,
    )
    enf.authorize("requeue_queue_job")
    enf.authorize("launch_missiles")
    assert len(sink.entries) == 2
    assert sink.entries[0].kind == "enforcement"
    assert sink.entries[0].payload["decision"] == "allow"
    assert sink.entries[1].payload["decision"] == "deny"
    # hash chain links each entry to the previous
    assert sink.entries[1].prev_hash == sink.entries[0].hash


def test_authorize_without_audit_does_not_raise() -> None:
    """No audit wired => authorize still works, nothing mirrored."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A4"))
    assert enf.authorize("requeue_queue_job") == Decision.ALLOW
