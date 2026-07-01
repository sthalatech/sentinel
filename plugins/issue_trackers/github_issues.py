"""GitHub Issues tracker implementation using only stdlib HTTP."""

from __future__ import annotations

import json
import logging
import pprint
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from core.incident import Incident, IncidentStatus
from interfaces.issue_tracker import IssueTracker
from interfaces.secret_provider import SecretProvider

logger = logging.getLogger(__name__)


class GitHubIssues(IssueTracker):
    """Mirror incident lifecycle into a GitHub repository issue."""

    def __init__(
        self, repo: str, secret_provider: SecretProvider, base_url: str = "https://api.github.com"
    ) -> None:
        self.repo = repo
        self._secret_provider = secret_provider
        self._base_url = base_url.rstrip("/")

    def create(self, incident: Incident) -> str:
        """Create an issue for the incident and record its external ref."""
        body = self._issue_body(incident)
        payload = {"title": f"sentinel/{incident.id}", "body": body}
        data = self._request("POST", f"/repos/{self.repo}/issues", payload)
        number = data["number"]
        incident.external_refs["issue"] = f"{self.repo}#{number}"
        return incident.external_refs["issue"]

    def comment(self, incident: Incident, body: str) -> None:
        """Post a comment on the mirrored issue."""
        number = self._number(incident)
        payload = {"body": body}
        self._request("POST", f"/repos/{self.repo}/issues/{number}/comments", payload)

    def sync_status(self, incident: Incident) -> None:
        """Idempotently ensure the issue state matches the incident status."""
        try:
            if "issue" not in incident.external_refs:
                self.create(incident)
            desired = self._desired_state(incident)
            number = self._number(incident)
            self._request("PATCH", f"/repos/{self.repo}/issues/{number}", {"state": desired})
        except (RuntimeError, OSError) as exc:
            logger.warning("GitHub sync_status failed for %s: %s", incident.id, exc)

    def _issue_body(self, incident: Incident) -> str:
        """Return a formatted issue body summarizing the incident."""
        lines = [
            f"**Source:** {incident.source}",
            f"**Source ref:** {incident.source_ref}",
            "",
            "**Context:**",
            "```json",
            pprint.pformat(incident.context, indent=2, width=80),
            "```",
        ]
        return "\n".join(lines)

    def _desired_state(self, incident: Incident) -> str:
        """Map incident status to a GitHub issue state."""
        return "closed" if incident.status == IncidentStatus.RESOLVED else "open"

    def _number(self, incident: Incident) -> int:
        """Parse the issue number from incident.external_refs['issue']."""
        ref = incident.external_refs["issue"]
        number_part = ref.split("#", 1)[1]
        return int(number_part)

    def _token(self) -> str:
        """Fetch the GitHub token from the secret provider."""
        return self._secret_provider.get("GITHUB_TOKEN")

    def _headers(self) -> dict[str, str]:
        """Return GitHub REST API request headers."""
        return {
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Send an authenticated JSON request and return parsed JSON."""
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        request = Request(url, data=data, method=method, headers=self._headers())
        try:
            with urlopen(request, timeout=30) as response:
                content = response.read().decode("utf-8")
                if not content:
                    return {}
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    raise RuntimeError(f"GitHub {method} {path} -> unexpected JSON type")
                return parsed
        except HTTPError as exc:
            content = exc.read().decode("utf-8") or exc.reason
            raise RuntimeError(f"GitHub {method} {path} -> {exc.code}: {content}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"GitHub {method} {path} -> invalid JSON: {exc}") from exc
