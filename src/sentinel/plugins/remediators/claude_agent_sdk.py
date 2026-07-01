"""Skeleton remediator that delegates remediation to the Claude Agent SDK."""

from __future__ import annotations

from sentinel.core.incident import Incident, Result
from sentinel.interfaces.enforcer import Enforcer
from sentinel.interfaces.remediator import Remediator
from sentinel.interfaces.secret_provider import SecretProvider


class ClaudeAgentRemediator(Remediator):
    """Drive remediation via the Claude Agent SDK, gated by the enforcer."""

    def __init__(
        self, api_key_env: str = "ANTHROPIC_API_KEY", secret_provider: SecretProvider | None = None
    ) -> None:
        self.api_key_env = api_key_env
        self._secret_provider = secret_provider

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Attempt remediation using Claude Agent SDK."""
        raise NotImplementedError(
            "use the Claude Agent SDK to drive remediation; "
            "gate tool calls through the provided enforcer"
        )
