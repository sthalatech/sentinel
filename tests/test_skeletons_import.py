"""Contract-style import and signature checks for skeleton plugins."""

from __future__ import annotations

import pytest

from plugins.detectors.data_reconciliation import DataReconciliationDetector
from plugins.detectors.temporal_workflow import TemporalWorkflowDetector
from plugins.enforcers.agt import AGTEnforcer
from plugins.issue_trackers.jira import JiraIssueTracker
from plugins.issue_trackers.linear import LinearIssueTracker
from plugins.orchestrators.temporal import TemporalOrchestrator
from plugins.remediators.claude_agent_sdk import ClaudeAgentRemediator
from plugins.remediators.human_manual import HumanManualRemediator
from plugins.remediators.shelley import ShelleyRemediator
from plugins.state_stores.postgres_store import PostgresStateStore


def test_detector_protocol_methods() -> None:
    """Detectors expose the detect method."""
    assert hasattr(TemporalWorkflowDetector, "detect")
    assert hasattr(DataReconciliationDetector, "detect")
    with pytest.raises(NotImplementedError):
        TemporalWorkflowDetector(address="temporal:7233").detect()
    with pytest.raises(NotImplementedError):
        DataReconciliationDetector(left_dsn="left", right_dsn="right", query="SELECT 1").detect()


def test_orchestrator_protocol_methods() -> None:
    """Orchestrators expose schedule, retry, and wait_signal."""
    assert hasattr(TemporalOrchestrator, "schedule")
    assert hasattr(TemporalOrchestrator, "retry")
    assert hasattr(TemporalOrchestrator, "wait_signal")
    with pytest.raises(NotImplementedError):
        TemporalOrchestrator(address="temporal:7233").wait_signal("wake", 1.0)


def test_enforcer_protocol_methods() -> None:
    """Enforcers expose authorize."""
    assert hasattr(AGTEnforcer, "authorize")
    with pytest.raises(NotImplementedError):
        AGTEnforcer().authorize("tool.action")


def test_remediator_protocol_methods() -> None:
    """Remediators expose remediate."""
    assert hasattr(ShelleyRemediator, "remediate")
    assert hasattr(ClaudeAgentRemediator, "remediate")
    assert hasattr(HumanManualRemediator, "remediate")


def test_state_store_protocol_methods() -> None:
    """State stores expose get, put, list, set_trust, and get_trust."""
    assert hasattr(PostgresStateStore, "get")
    assert hasattr(PostgresStateStore, "put")
    assert hasattr(PostgresStateStore, "list")
    assert hasattr(PostgresStateStore, "set_trust")
    assert hasattr(PostgresStateStore, "get_trust")


def test_issue_tracker_protocol_methods() -> None:
    """Issue trackers expose create, comment, and sync_status."""
    assert hasattr(LinearIssueTracker, "create")
    assert hasattr(LinearIssueTracker, "comment")
    assert hasattr(LinearIssueTracker, "sync_status")
    assert hasattr(JiraIssueTracker, "create")
    assert hasattr(JiraIssueTracker, "comment")
    assert hasattr(JiraIssueTracker, "sync_status")
