"""The run_once loop and the single status-change write path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.audit import AuditLog
from core.incident import EscalationEvent, Incident, IncidentStatus, Result

if TYPE_CHECKING:
    from interfaces.detector import Detector
    from interfaces.enforcer import Enforcer
    from interfaces.issue_tracker import IssueTracker
    from interfaces.notifier import Notifier
    from interfaces.remediator import Remediator
    from interfaces.state_store import StateStore
    from interfaces.verifier import Verifier
    from core.trust import TrustManager


@dataclass
class SentinelConfig:
    """Wiring of all plugins for one run of the loop."""

    detector: "Detector"
    remediator: "Remediator"
    verifier: "Verifier"
    enforcer: "Enforcer"
    notifier: "Notifier"
    issue_tracker: "IssueTracker"
    state_store: "StateStore"
    trust: "TrustManager"
    audit: AuditLog


def run_once(cfg: SentinelConfig) -> None:
    """One pass: detect, remediate, verify, escalate. Called on a timer."""
    for incident in cfg.detector.detect():
        cfg.state_store.put(incident)
        cfg.issue_tracker.sync_status(incident)
        if incident.status in (IncidentStatus.PAUSED, IncidentStatus.HUMAN_OWNED):
            continue
        if cfg.trust.is_locked_down():
            cfg.notifier.notify(EscalationEvent(incident, reason="trust-locked"))
            continue
        incident.status = IncidentStatus.REMEDIATING
        cfg.state_store.put(incident)
        cfg.issue_tracker.sync_status(incident)
        result = cfg.remediator.remediate(incident, cfg.enforcer)
        cfg.audit.record(incident, result)
        cfg.issue_tracker.comment(incident, f"Attempt {incident.attempts}: {result.summary}")
        if cfg.verifier.verify(incident):
            incident.status = IncidentStatus.RESOLVED
        else:
            cfg.trust.demote(reason=incident.id)
            cfg.notifier.notify(EscalationEvent(incident, reason="unresolved"))
        cfg.state_store.put(incident)
        cfg.issue_tracker.sync_status(incident)


def apply_status_change(state_store: "StateStore", audit: AuditLog,
                        issue_tracker: "IssueTracker", incident_id: str,
                        status: IncidentStatus, reason: str, actor: str) -> None:
    """The single write path for any engine-visible status change."""
    incident = state_store.get(incident_id)
    if incident is None:
        raise KeyError(f"incident not found: {incident_id}")
    incident.status = status
    state_store.put(incident)
    audit.record_status_change(incident_id, status, reason, actor)
    issue_tracker.sync_status(incident)
