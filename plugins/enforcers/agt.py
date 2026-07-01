"""Skeleton enforcer based on AGT policy and a trust ladder."""

from __future__ import annotations

import os

from core.incident import Decision
from core.trust import TrustStore
from interfaces.enforcer import Enforcer


class AGTEnforcer(Enforcer):
    """Gate tool calls using policy.yaml plus a governance trust ladder."""

    def __init__(
        self,
        policy_path: str = "",
        trust_store: TrustStore | None = None,
    ) -> None:
        self.policy_path = policy_path or os.environ.get(
            "AGT_POLICY_PATH", "governance/policy.example.yaml"
        )
        self._trust_store = trust_store

    def authorize(self, action: str) -> Decision:
        """Return ALLOW, DENY, or REQUIRE_APPROVAL for a named action."""
        raise NotImplementedError(
            "parse policy.yaml + governance/agentaz.example.json trust ladder; "
            "return Decision based on current trust level and action allowlist"
        )
