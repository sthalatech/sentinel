"""Tests for AGTEnforcer against the real governance policy + ladder."""

from __future__ import annotations

from pathlib import Path

from sentinel.core.incident import Decision
from sentinel.plugins.enforcers.agt import AGTEnforcer

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


def test_allow_for_allowlisted_action_at_a4() -> None:
    """An action in A4's allowed_actions returns ALLOW."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A4"))
    assert enf.authorize("requeue_queue_job") == Decision.ALLOW


def test_require_approval_for_roll_back_at_a3_per_level_gate() -> None:
    """reconcile_move_line is in A3's require_approval_for, so gate it."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A3"))
    assert enf.authorize("reconcile_move_line") == Decision.REQUIRE_APPROVAL


def test_deny_for_unlisted_action_at_current_level() -> None:
    """An action absent from both allowed and require_approval_for is DENY."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A4"))
    assert enf.authorize("launch_missiles") == Decision.DENY


def test_require_approval_for_delete_resource_at_any_level_global_gate() -> None:
    """reset_posted_invoice is in policy require_approval, gated at every level."""
    for level in ("A4", "A3", "A2"):
        enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore(level))
        assert enf.authorize("reset_posted_invoice") == Decision.REQUIRE_APPROVAL


def test_deny_for_every_action_at_a1_lockdown() -> None:
    """At A1 lockdown, every action is DENY (empty allowed_actions)."""
    enf = AGTEnforcer(policy_path=POLICY, trust_store=_FakeTrustStore("A1"))
    assert enf.authorize("requeue_queue_job") == Decision.DENY
    assert enf.authorize("retry_mail_queue") == Decision.DENY


def test_construction_fails_loud_on_missing_policy() -> None:
    """A missing policy file raises at construction, not at authorize time."""
    import pytest

    with pytest.raises(FileNotFoundError):
        AGTEnforcer(policy_path="/nonexistent/policy.yaml", trust_store=_FakeTrustStore("A4"))
