"""Incident model and shared types used across Sentinel Loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class IncidentStatus(Enum):
    """Lifecycle state of an incident, driven solely by the engine."""

    DETECTED = "detected"
    REMEDIATING = "remediating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    PAUSED = "paused"
    HUMAN_OWNED = "human_owned"


class Decision(Enum):
    """Authorization outcome returned by an Enforcer for a proposed action."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Result:
    """Outcome of a single remediation attempt.

    ``breach=True`` marks a policy-enforcement breach — a denied governance
    action's tool was invoked despite the per-run allowlist (i.e. Hermes's
    pre-call gate failed open). This is categorically distinct from an ordinary
    failed fix: the engine must treat it with enforcement severity (lockdown /
    escalate) rather than as a routine retry, and the audit log must record it
    as a breach, not a normal remediation outcome.
    """

    success: bool
    summary: str
    breach: bool = False


@dataclass
class EscalationEvent:
    """Payload passed to a Notifier when an incident escalates."""

    incident: Incident
    reason: str


@dataclass
class Incident:
    """One record per incident; its id is the correlation key everywhere."""

    id: str
    source: str
    source_ref: str
    status: IncidentStatus
    trust_level_at_open: str
    attempts: int
    detected_at: datetime
    resolved_at: datetime | None
    context: dict[str, object]
    external_refs: dict[str, str] = field(default_factory=dict)
