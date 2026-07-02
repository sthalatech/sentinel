"""The run_once loop and the single status-change write path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sentinel.core.audit import AuditLog
from sentinel.core.incident import EscalationEvent, IncidentStatus

if TYPE_CHECKING:
    from sentinel.core.trust import TrustManager
    from sentinel.interfaces.detector import Detector
    from sentinel.interfaces.enforcer import Enforcer
    from sentinel.interfaces.issue_tracker import IssueTracker
    from sentinel.interfaces.notifier import Notifier
    from sentinel.interfaces.remediator import Remediator
    from sentinel.interfaces.state_store import StateStore
    from sentinel.interfaces.verifier import Verifier

MAX_ATTEMPTS_DEFAULT = 3

_TERMINAL_STATUSES = (IncidentStatus.PAUSED, IncidentStatus.HUMAN_OWNED, IncidentStatus.ESCALATED)


@dataclass
class SentinelConfig:
    """Wiring of all plugins for one run of the loop."""

    detector: Detector
    remediator: Remediator
    verifier: Verifier
    enforcer: Enforcer
    notifier: Notifier
    issue_tracker: IssueTracker
    state_store: StateStore
    trust: TrustManager
    audit: AuditLog
    max_attempts: int = MAX_ATTEMPTS_DEFAULT


def run_once(cfg: SentinelConfig) -> None:
    """One pass: detect, remediate, verify, escalate. Called on a timer."""
    for incident in cfg.detector.detect():
        cfg.state_store.put(incident)
        cfg.issue_tracker.sync_status(incident)
        if incident.status in _TERMINAL_STATUSES:
            continue
        if cfg.trust.is_locked_down():
            cfg.notifier.notify(EscalationEvent(incident, reason="trust-locked"))
            continue
        incident.status = IncidentStatus.REMEDIATING
        incident.attempts += 1
        cfg.state_store.put(incident)
        cfg.issue_tracker.sync_status(incident)
        result = cfg.remediator.remediate(incident, cfg.enforcer)
        cfg.audit.record(incident, result)
        cfg.issue_tracker.comment(incident, f"Attempt {incident.attempts}: {result.summary}")
        if getattr(result, "breach", False):
            # Policy-enforcement breach: a denied action's tool was invoked
            # despite the allowlist (Hermes's pre-call gate failed open). This
            # is not a routine remediation failure — record it as a breach,
            # demote trust hard, and escalate immediately rather than retrying.
            cfg.audit.record_breach(incident.id, result.summary)
            cfg.trust.demote(reason=f"breach:{incident.id}")
            incident.status = IncidentStatus.ESCALATED
            cfg.notifier.notify(EscalationEvent(incident, reason="policy-enforcement-breach"))
        elif cfg.verifier.verify(incident):
            incident.status = IncidentStatus.RESOLVED
        elif incident.attempts >= cfg.max_attempts:
            incident.status = IncidentStatus.ESCALATED
            cfg.notifier.notify(EscalationEvent(incident, reason="max-attempts-exceeded"))
        else:
            cfg.trust.demote(reason=incident.id)
            cfg.notifier.notify(EscalationEvent(incident, reason="unresolved"))
        cfg.state_store.put(incident)
        cfg.issue_tracker.sync_status(incident)


def apply_status_change(
    state_store: StateStore,
    audit: AuditLog,
    issue_tracker: IssueTracker,
    incident_id: str,
    status: IncidentStatus,
    reason: str,
    actor: str,
) -> None:
    """The single write path for any engine-visible status change."""
    incident = state_store.get(incident_id)
    if incident is None:
        raise KeyError(f"incident not found: {incident_id}")
    incident.status = status
    state_store.put(incident)
    audit.record_status_change(incident_id, status, reason, actor)
    issue_tracker.sync_status(incident)
