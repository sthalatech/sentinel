"""Skeleton issue tracker that mirrors incidents into Jira."""

from __future__ import annotations

from sentinel.core.incident import Incident
from sentinel.interfaces.issue_tracker import IssueTracker
from sentinel.interfaces.secret_provider import SecretProvider


class JiraIssueTracker(IssueTracker):
    """Mirror incident lifecycle into a Jira project via REST."""

    def __init__(self, base_url: str, project_key: str, secret_provider: SecretProvider) -> None:
        self.base_url = base_url
        self.project_key = project_key
        self._secret_provider = secret_provider

    def create(self, incident: Incident) -> str:
        """Create the mirrored issue; return its external ref id."""
        raise NotImplementedError(
            "use Jira REST API; mirror create/comment/sync_status like github_issues.py"
        )

    def comment(self, incident: Incident, body: str) -> None:
        """Append a comment to the mirrored issue."""
        raise NotImplementedError(
            "use Jira REST API; mirror create/comment/sync_status like github_issues.py"
        )

    def sync_status(self, incident: Incident) -> None:
        """Assert the tracker state matches the incident status."""
        raise NotImplementedError(
            "use Jira REST API; mirror create/comment/sync_status like github_issues.py"
        )
