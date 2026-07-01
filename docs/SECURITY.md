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

## Trust demotion

If an incident cannot be resolved, the engine demotes the global trust level.
When trust reaches the minimum level (`A1`), the loop enters lockdown and stops
running remediation, escalating every new incident instead. This protects
against runaway automation on unverified failures.

## Reporting

Please report security concerns by opening a private discussion or emailing the
maintainers listed in `GOVERNANCE.md`.
