# Security Policy

## Secrets

* Only environment variable **names** are allowed in the repository.
* Secret **values** are resolved at runtime through a `SecretProvider`, such as
  `plugins.secret_providers.env_provider.EnvSecretProvider`.
* `.env` files are gitignored.
* An example of allowed variable names lives in `config/.env.example`.
* The CI pipeline runs `gitleaks` on every push and pull request (see
  `.github/workflows/ci.yml` and `.gitleaks.toml`).

## Single write path

All engine-visible status changes go through
`core.engine.apply_status_change(state_store, audit, issue_tracker, incident_id, status, reason, actor)`.
This is the only function that mutates an incident's status while also writing a
hash-chained audit entry and syncing the issue tracker. Keeping all writes in
one place makes the lifecycle observable, testable, and tamper-evident.

## One bridge tool

The active remediator is the only component that may invoke external tools. The
enforcer gates each action before it runs, the verifier independently confirms
resolution, and the notifier only escalates. This separation means the agent
has exactly one bridge to the outside world during remediation, and that bridge
is explicitly authorized.

## Enforcement architecture (validated)

This section exists because the obvious design — the enforcer intercepts each
tool call live, mid-conversation — was tested against five real candidates and
only one of them actually survives unattended, headless invocation (a
Claude Agent SDK `PreToolUse` hook). That option requires an Anthropic
subscription, which isn't available here, so the architecture below is built
entirely from mechanisms that were independently verified to hold up without
it. Anyone revisiting this decision should re-run that validation rather than
trust this write-up alone — tool docs in this space have repeatedly claimed
guarantees that didn't hold under headless testing.

**The core adjustment from the original design: gating moves before the run,
not during it.** Hermes's live approval system is bypassed entirely on its
headless entry points — confirmed by reproduction, not assumption. So instead
of asking "should this specific action be allowed right now," the enforcer
answers "which tools should even exist for this run" before the remediator
starts, using two mechanisms that *were* verified to hold regardless of
invocation mode:

1. **Tool-surface restriction, computed pre-run.** Before each remediation
   attempt, `AGTEnforcer` resolves the current global trust level's
   `allowed_actions` from the governance ladder and `HermesRemediator` renders
   that set as Hermes's `enabled_toolsets` for the run. Hermes performs
   registry-level tool removal — an action whose toolset is not enabled is
   never registered as a tool the model can see (verified independently via
   `model_tools.get_tool_definitions(enabled_toolsets=[...])`, not something
   the model can argue its way past). `REQUIRE_APPROVAL` and `DENY` both
   collapse to "not exposed" for the unattended loop; an action needing
   real-time approval is only reachable through a human opening the incident's
   live conversation or using the `sentinel incidents` CLI directly — the
   channels built for exactly that in "Human intervention," above.
2. **Mandatory container isolation.** `HermesRemediator` requires Hermes's
   Docker terminal backend; local (unsandboxed) execution is refused at
   startup. This mirrors a failure pattern that showed up independently in
   two other tools during evaluation: a sandbox that silently degrades to no
   isolation when a dependency is missing. Startup here checks that Docker is
   actually running and the configured backend is `docker`, and refuses to
   start otherwise — the same dependency, treated as a hard requirement
   instead of a soft one.

**Decision logic and audit run behind `AGTEnforcer`, not inside Hermes.**
`AGTEnforcer` evaluates each action against `governance/policy.example.yaml`
(global `require_approval`) and the trust ladder in
`governance/agentaz.example.json` (per-level `allowed_actions` /
`require_approval_for`). Unlisted actions fall through to `DENY` by default
(fail-closed). Every `authorize()` decision is mirrored into the existing
hash-chained audit log via `AuditLog.record_enforcement(...)`, so the
enforcement trail is tamper-evident alongside the rest of the lifecycle.

> **Naming, worth flagging so it doesn't confuse anyone later:**
> `plugins/enforcers/agt.py` implements our own `AGTEnforcer`, named for this
> project's AgentAz/ATF governance concept from the original design. It is a
> self-contained policy evaluator — it does **not** wrap any third-party
> "AGT" library. If a future change does adopt Microsoft's *Agent Governance
> Toolkit* (or anything else sharing the three-letter name), update this note
> so "the AGT toolkit" stays unambiguous.

**Fail-closed is a standing project rule, not a per-component judgment call.**
Every one of the following was a real bug found in some tool during
validation, not a hypothetical: Docker unavailable at startup → refuse to
run, not degrade. Action absent from the current trust level → never
registered as a tool, not merely denied if attempted. Policy engine given an
unrecognized action → deny. A hook or callback that raises → deny, not pass
through. New plugins should default to this posture rather than rediscovering
each of these independently.

**What this does not solve.** No tool evaluated — including two built
specifically to catch it — reliably detects a disguised or euphemistically
worded dangerous request; the underlying classifiers are pattern matching
regardless of vendor claims. The compensating control is keeping
`allowed_actions` per trust level genuinely narrow rather than trusting a
classifier to catch intent, so a successful disguise still has a small blast
radius.

## Trust demotion

If an incident cannot be resolved, the engine demotes the global trust level.
When trust reaches the minimum level (`A1`), the loop enters lockdown and stops
running remediation, escalating every new incident instead. This protects
against runaway automation on unverified failures.

## Reporting

Please report security concerns by opening a private discussion or emailing the
maintainers listed in `GOVERNANCE.md`.
