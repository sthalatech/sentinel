"""Skeleton issue tracker that mirrors incidents into Linear."""

from __future__ import annotations

from core.incident import Incident
from interfaces.issue_tracker import IssueTracker
from interfaces.secret_provider import SecretProvider


class LinearIssueTracker(IssueTracker):
    """Mirror incident lifecycle into a Linear team via GraphQL."""

    def __init__(self, team_id: str, secret_provider: SecretProvider) -> None:
        self.team_id = team_id
        self._secret_provider = secret_provider

    def create(self, incident: Incident) -> str:
        """Create the mirrored issue; return its external ref id."""
        raise NotImplementedError(
            "use Linear GraphQL API; mirror create/comment/sync_status like github_issues.py"
        )

    def comment(self, incident: Incident, body: str) -> None:
        """Append a comment to the mirrored issue."""
        raise NotImplementedError(
            "use Linear GraphQL API; mirror create/comment/sync_status like github_issues.py"
        )

    def sync_status(self, incident: Incident) -> None:
        """Assert the tracker state matches the incident status."""
        raise NotImplementedError(
            "use Linear GraphQL API; mirror create/comment/sync_status like github_issues.py"
        )
