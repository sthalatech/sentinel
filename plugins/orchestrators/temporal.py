"""Skeleton orchestrator that drives the loop as a Temporal workflow."""

from __future__ import annotations

from core.engine import SentinelConfig
from interfaces.orchestrator import Orchestrator


class TemporalOrchestrator(Orchestrator):
    """Run sentinel-loop as a Temporal workflow with signal-based wakeups."""

    def __init__(
        self,
        address: str,
        namespace: str = "default",
        workflow_id: str = "sentinel-loop",
        task_queue: str = "sentinel",
    ) -> None:
        self.address = address
        self.namespace = namespace
        self.workflow_id = workflow_id
        self.task_queue = task_queue

    def schedule(self, cfg: SentinelConfig) -> None:
        """Begin invoking run_once on the configured cadence."""
        raise NotImplementedError(
            "install 'temporalio' (extras: temporal) and schedule "
            "run_once via WorkflowClient.start_workflow"
        )

    def retry(self, cfg: SentinelConfig) -> None:
        """Re-run the loop after a failure, applying backoff."""
        raise NotImplementedError(
            "install 'temporalio' (extras: temporal) and retry "
            "via Temporal workflow handle execute_update or signal"
        )

    def wait_signal(self, key: str, timeout: float) -> bool:
        """Block until a named signal arrives or timeout elapses."""
        raise NotImplementedError(
            "install 'temporalio' (extras: temporal) and wait for a "
            "named workflow signal external signal with a timeout"
        )
