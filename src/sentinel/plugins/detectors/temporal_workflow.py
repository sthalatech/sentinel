"""Skeleton detector that polls Temporal workflow execution histories."""

from __future__ import annotations

from sentinel.core.incident import Incident
from sentinel.interfaces.detector import Detector


class TemporalWorkflowDetector(Detector):
    """Poll Temporal for failed or timed-out workflow executions."""

    def __init__(
        self,
        address: str,
        namespace: str = "default",
        task_queue: str = "fsil-sync",
        workflow_ids: list[str] | None = None,
    ) -> None:
        self.address = address
        self.namespace = namespace
        self.task_queue = task_queue
        self.workflow_ids = workflow_ids or []

    def detect(self) -> list[Incident]:
        """Return incidents for failed/timed-out Temporal workflows."""
        raise NotImplementedError(
            "install 'temporalio' (extras: temporal) and implement "
            "workflow history polling via WorkflowClient"
        )
