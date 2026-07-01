"""Skeleton remediator that delegates incident handling to Shelley."""

from __future__ import annotations

from sentinel.core.incident import Incident, Result
from sentinel.interfaces.enforcer import Enforcer
from sentinel.interfaces.remediator import Remediator
from sentinel.interfaces.secret_provider import SecretProvider


class ShelleyRemediator(Remediator):
    """One Shelley conversation per incident; only write-back is status."""

    def __init__(self, api_url: str, secret_provider: SecretProvider) -> None:
        self.api_url = api_url
        self._secret_provider = secret_provider

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Open or resume a conversation titled sentinel/{incident.id}."""
        raise NotImplementedError(
            "create/resume one conversation per incident titled "
            "sentinel/{incident.id}; store ref in incident.external_refs["
            "'conversation']; the agent gets only set_incident_status as a bridge tool"
        )
