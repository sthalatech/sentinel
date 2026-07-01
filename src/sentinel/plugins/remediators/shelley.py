"""Remediator that delegates one incident to one Shelley conversation.

Programmatic mechanism found (verified live on this VM, shelley v0.752):
  The local Shelley server exposes a CLI client and a Unix-socket HTTP API.
    - Create a conversation: `shelley client chat -p "PROMPT"` prints
      `{"conversation_id": "..."}`. There is NO -title flag; the slug is
      auto-derived from the first prompt, so "sentinel/{incident.id}" is
      placed in the first prompt (not set as a literal conversation title).
    - Resume: `shelley client chat -c <conversation_id> -p "..."`.
    - Stream the agent turn to completion: `shelley client read -wait <id>`
      emits one JSON line per message with `end_of_turn: true` on the last
      agent message; the stream self-terminates when the turn ends.

Tool-call gating (the safety-critical part) — read this carefully:
  Shelley's own tools (bash, patch, browser, subagent, ...) execute with
  FULL VM access during a turn. Neither the CLI nor the HTTP API exposes
  a per-conversation tool allowlist, a tool-call interception hook, or a
  way to inject a Python function as a callable tool. We verified:
    - `shelley client chat` has no -tools/-allowlist flag.
    - POST /api/conversations/new silently ignores unknown JSON fields
      (allowed_tools, tools_filter, etc. are accepted but not enforced).
    - The /api/tools endpoint lists built-in tools but offers no gating.
  Therefore gating CANNOT be enforced at the tool-execution layer from
  outside the server; it is enforced structurally at this plugin:
    1. The prompt handed to Shelley names the incident and states that any
       real-world-effect action (a shell command, a file write, a network
       call) must first be declared as a named action and may only proceed
       if enforcer.authorize(action) == ALLOW; REQUIRE_APPROVAL/DENY means
       the agent must NOT perform it and must instead report back.
    2. The only write the agent is permitted to make into engine state is
       the set_incident_status directive (see _parse_status_directive),
       applied via apply_status_change(actor="agent").
  This is prompt-bound enforcement, not a sandbox. A model that ignores
  instructions can still run tools. The AGTEnforcer exists to make the
  policy explicit and auditable; defense-in-depth (an actual Shelley-side
  tool filter / approval gate) is a Shelley feature request, not something
  this plugin can provide.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Protocol

from sentinel.core.engine import apply_status_change
from sentinel.core.incident import Incident, IncidentStatus, Result
from sentinel.interfaces.enforcer import Enforcer
from sentinel.interfaces.remediator import Remediator
from sentinel.interfaces.secret_provider import SecretProvider

_BRIDGE_TOOL = "set_incident_status"


class ShelleyClient(Protocol):
    """Minimal client surface for talking to a Shelley server."""

    def chat(self, prompt: str, conversation_id: str | None = None) -> str:
        """Send a message; return the conversation_id (new or resumed)."""

    def read_until_done(self, conversation_id: str, timeout: float) -> list[dict[str, Any]]:
        """Return all messages once the agent turn ends, bounded by timeout."""


class CliShelleyClient:
    """Real client driving `shelley client chat` and `shelley client read -wait`."""

    def __init__(self, url: str | None = None, model: str | None = None) -> None:
        self._url = url
        self._model = model

    def _base_args(self) -> list[str]:
        """Return the base `shelley client` argv, plus -url when configured."""
        args = ["shelley", "client"]
        if self._url:
            args += ["-url", self._url]
        return args

    def chat(self, prompt: str, conversation_id: str | None = None) -> str:
        """Create or resume a conversation via `shelley client chat`."""
        cmd = self._base_args() + ["chat", "-p", prompt]
        if conversation_id is not None:
            cmd += ["-c", conversation_id]
        if self._model is not None:
            cmd += ["-model", self._model]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout.strip())
        return str(data["conversation_id"])

    def read_until_done(self, conversation_id: str, timeout: float) -> list[dict[str, Any]]:
        """Stream `read -wait` until the turn ends or the timeout elapses."""
        cmd = self._base_args() + ["read", "-wait", conversation_id]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


class ShelleyRemediator(Remediator):
    """One Shelley conversation per incident; only write-back is status."""

    def __init__(
        self,
        api_url: str,
        secret_provider: SecretProvider,
        client: ShelleyClient | None = None,
        turn_timeout: float = 120.0,
        state_store: Any = None,
        audit: Any = None,
        issue_tracker: Any = None,
    ) -> None:
        self.api_url = api_url
        self._secret_provider = secret_provider
        self._client = client if client is not None else CliShelleyClient(url=api_url)
        self._turn_timeout = turn_timeout
        self._state_store = state_store
        self._audit = audit
        self._issue_tracker = issue_tracker

    def remediate(self, incident: Incident, enforcer: Enforcer) -> Result:
        """Open or resume a conversation titled sentinel/{incident.id}."""
        conv_ref = incident.external_refs.get("conversation")
        prompt = self._build_prompt(incident, enforcer)
        if conv_ref is None:
            conv_ref = self._client.chat(prompt)
            incident.external_refs["conversation"] = conv_ref
        else:
            self._client.chat(prompt, conversation_id=conv_ref)
        messages = self._client.read_until_done(conv_ref, self._turn_timeout)
        self._apply_status_directives(incident, messages)
        return Result(success=True, summary=f"conversation {conv_ref} turn complete")

    def _build_prompt(self, incident: Incident, enforcer: Enforcer) -> str:
        """Compose the incident prompt with the gating contract for the agent."""
        del enforcer  # gating contract is stated in prose; see module docstring.
        return (
            f"sentinel/{incident.id}\n"
            f"Incident source: {incident.source} ref {incident.source_ref}\n"
            f"Context: {json.dumps(incident.context, default=str)}\n\n"
            "You are the remediation agent for this incident. Rules:\n"
            "1. Before any action with real-world effect (shell, file write, "
            "network), name it and only proceed if the enforcer allows it.\n"
            "2. The ONLY way to change engine state is to emit, in your final "
            f"message, a fenced JSON block: `{_BRIDGE_TOOL} "
            '{{"status": "<status>", "reason": "<reason>"}}` where status is one '
            "of detected, remediating, verifying, resolved, escalated, paused, "
            "human_owned. Do not call any other write path.\n"
            "3. End your turn with a one-line summary of what you attempted."
        )

    def _apply_status_directives(self, incident: Incident, messages: list[dict[str, Any]]) -> None:
        """Apply each set_incident_status directive via the single write path."""
        if self._state_store is None or self._audit is None or self._issue_tracker is None:
            return
        for msg in messages:
            if msg.get("type") != "agent":
                continue
            for status, reason in _parse_status_directive(str(msg.get("text", ""))):
                apply_status_change(
                    state_store=self._state_store,
                    audit=self._audit,
                    issue_tracker=self._issue_tracker,
                    incident_id=incident.id,
                    status=status,
                    reason=reason,
                    actor="agent",
                )


_STATUS_VALUES = {s.value for s in IncidentStatus}
_DIRECTIVE_RE = re.compile(
    r"set_incident_status\s*\{\s*\"status\"\s*:\s*\"([^\"]+)\""
    r"\s*,\s*\"reason\"\s*:\s*\"([^\"]*)\"\s*\}",
    re.MULTILINE,
)


def _parse_status_directive(text: str) -> list[tuple[IncidentStatus, str]]:
    """Return (status, reason) pairs for each valid directive in the text."""
    out: list[tuple[IncidentStatus, str]] = []
    for status_raw, reason in _DIRECTIVE_RE.findall(text):
        if status_raw in _STATUS_VALUES:
            out.append((IncidentStatus(status_raw), reason))
    return out
