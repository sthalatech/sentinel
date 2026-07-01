"""Enforcer gating tool calls against policy.yaml and a trust ladder."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sentinel.core.incident import Decision
from sentinel.core.trust import TrustStore
from sentinel.interfaces.enforcer import Enforcer


def _load_yaml(path: Path) -> dict[str, Any]:
    """Return parsed YAML or raise a clear error if missing or malformed."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - install-time failure
        raise RuntimeError(
            "AGTEnforcer needs PyYAML; install with `pip install sentinel[agt]`"
        ) from exc
    if not path.is_file():
        raise FileNotFoundError(f"AGT policy file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"AGT policy is not valid YAML ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"AGT policy must be a YAML mapping ({path})")
    return data


def _load_ladder(path: Path) -> dict[str, Any]:
    """Return parsed trust-ladder JSON or raise if missing or malformed."""
    if not path.is_file():
        raise FileNotFoundError(f"AGT trust ladder not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"AGT trust ladder is not valid JSON ({path}): {exc}") from exc
    if not isinstance(data, dict) or "trust_levels" not in data:
        raise ValueError(f"AGT trust ladder missing 'trust_levels' ({path})")
    return data


class AGTEnforcer(Enforcer):
    """Gate tool calls using policy.yaml plus a governance trust ladder."""

    def __init__(
        self,
        policy_path: str = "",
        trust_store: TrustStore | None = None,
    ) -> None:
        self._policy_path = Path(
            policy_path or os.environ.get("AGT_POLICY_PATH", "governance/policy.example.yaml")
        )
        self._trust_store = trust_store
        policy = _load_yaml(self._policy_path)
        top = policy.get("policy")
        if not isinstance(top, dict):
            raise ValueError(f"AGT policy missing 'policy' section ({self._policy_path})")
        ladder_rel = top.get("trust_ladder")
        if not isinstance(ladder_rel, str):
            raise ValueError(f"AGT policy missing 'trust_ladder' ({self._policy_path})")
        self._require_approval = self._require_list(top.get("require_approval"))
        self._ladder_path = self._resolve_ladder(ladder_rel)
        self._ladder = _load_ladder(self._ladder_path)
        self._validate_levels()

    def _resolve_ladder(self, ladder_rel: str) -> Path:
        """Resolve the ladder path relative to the policy, then the repo root."""
        rel = Path(ladder_rel)
        candidates = [
            (self._policy_path.parent / rel).resolve(),
            (self._policy_path.parents[1] / rel).resolve(),
        ]
        for cand in candidates:
            if cand.is_file():
                return cand
        return candidates[0]

    def _validate_levels(self) -> None:
        """Ensure every ladder level has the expected action fields."""
        levels = self._ladder.get("trust_levels", {})
        for level, entry in levels.items():
            if not isinstance(entry, dict):
                raise ValueError(f"AGT level {level} is not a mapping")
            for key in ("allowed_actions", "require_approval_for"):
                if key not in entry:
                    raise ValueError(f"AGT level {level} missing '{key}'")

    @staticmethod
    def _require_list(raw: Any) -> list[str]:
        """Coerce a YAML list-of-strings into a list[str], else raise."""
        if not isinstance(raw, list):
            raise ValueError("AGT policy 'require_approval' must be a list")
        return [str(item) for item in raw]

    def _level_entry(self, level: str) -> dict[str, Any]:
        """Return the trust-ladder entry for one level (parsed once in init)."""
        levels: dict[str, Any] = self._ladder["trust_levels"]
        entry: dict[str, Any] | None = levels.get(level)
        if entry is None:
            raise KeyError(f"trust level {level} not present in AGT ladder")
        return entry

    def authorize(self, action: str) -> Decision:
        """Return ALLOW, DENY, or REQUIRE_APPROVAL for a named action."""
        if action in self._require_approval:
            return Decision.REQUIRE_APPROVAL
        if self._trust_store is None:
            raise RuntimeError("AGTEnforcer has no trust store; cannot read level")
        level = self._trust_store.get_trust()
        entry = self._level_entry(level)
        if action in entry.get("require_approval_for", []):
            return Decision.REQUIRE_APPROVAL
        if action in entry.get("allowed_actions", []):
            return Decision.ALLOW
        return Decision.DENY
