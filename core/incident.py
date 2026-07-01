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
    """Outcome of a single remediation attempt."""

    success: bool
    summary: str


@dataclass
class EscalationEvent:
    """Payload passed to a Notifier when an incident escalates."""

    incident: "Incident"
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
    context: dict
    external_refs: dict[str, str] = field(default_factory=dict)
