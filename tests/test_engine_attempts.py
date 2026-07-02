"""Tests for run_once attempts accounting and escalation at the cap."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from sentinel.core.engine import SentinelConfig, run_once
from sentinel.core.incident import Incident, IncidentStatus, Result


def _make_incident(attempts: int = 0) -> Incident:
    """Return a fresh detected incident for engine tests."""
    return Incident(
        id="inc-1",
        source="test",
        source_ref="ref-1",
        status=IncidentStatus.DETECTED,
        trust_level_at_open="A4",
        attempts=attempts,
        detected_at=datetime.now(UTC),
        resolved_at=None,
        context={},
    )


def _cfg(
    incident: Incident,
    *,
    verify: bool,
    max_attempts: int = 3,
) -> SentinelConfig:
    """Return a SentinelConfig wired with mocks for engine tests."""
    cfg = SentinelConfig(
        detector=MagicMock(),
        remediator=MagicMock(),
        verifier=MagicMock(),
        enforcer=MagicMock(),
        notifier=MagicMock(),
        issue_tracker=MagicMock(),
        state_store=MagicMock(),
        trust=MagicMock(),
        audit=MagicMock(),
        max_attempts=max_attempts,
    )
    cfg.detector.detect.return_value = [incident]
    cfg.trust.is_locked_down.return_value = False
    cfg.remediator.remediate.return_value = Result(success=True, summary="ok")
    cfg.verifier.verify.return_value = verify
    return cfg


def test_attempts_increments_per_run() -> None:
    """Each run_once increments the incident attempts counter by one."""
    incident = _make_incident(attempts=0)
    cfg = _cfg(incident, verify=True)
    run_once(cfg)
    assert incident.attempts == 1
    assert incident.status == IncidentStatus.RESOLVED


def test_incident_escalates_at_cap() -> None:
    """A still-failing incident reaches ESCALATED once attempts hit the cap."""
    incident = _make_incident(attempts=2)
    cfg = _cfg(incident, verify=False, max_attempts=3)
    run_once(cfg)
    assert incident.attempts == 3
    assert incident.status == IncidentStatus.ESCALATED


def test_escalated_incident_is_skipped_next_run() -> None:
    """An escalated incident is not remediated again on a later run_once."""
    incident = _make_incident(attempts=3)
    incident.status = IncidentStatus.ESCALATED
    cfg = _cfg(incident, verify=False, max_attempts=3)
    run_once(cfg)
    cfg.remediator.remediate.assert_not_called()
    assert incident.status == IncidentStatus.ESCALATED
    assert incident.attempts == 3


def test_breach_escalates_and_records_breach_audit_not_routine_retry() -> None:
    """A policy-enforcement breach (Result.breach=True) is escalated immediately
    with a dedicated `breach` audit entry and a breach-tagged demotion — not
    treated as a routine unresolved retry.
    """
    incident = _make_incident(attempts=0)
    cfg = _cfg(incident, verify=False, max_attempts=3)
    cfg.remediator.remediate.return_value = Result(
        success=False, summary="policy-enforcement breach: denied tool invoked", breach=True
    )
    run_once(cfg)
    # Escalated immediately, not waiting for the attempts cap.
    assert incident.status == IncidentStatus.ESCALATED
    assert incident.attempts == 1  # only one attempt, not retried up to the cap
    cfg.audit.record_breach.assert_called_once()
    cfg.trust.demote.assert_called_once()
    demote_reason = cfg.trust.demote.call_args.kwargs["reason"]
    assert demote_reason.startswith("breach:")
    # Notifier carries the breach reason, distinct from "unresolved".
    notify_call = cfg.notifier.notify.call_args
    assert notify_call.args[0].reason == "policy-enforcement-breach"
