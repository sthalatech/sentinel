# Quickstart

Run the zero-setup example in one command:

```bash
python examples/quickstart/run.py
```

This runs a single pass of the Sentinel Loop engine with mock plugins and an
in-memory SQLite store, then prints how many incidents were detected,
remediated, and resolved. It requires no external services, credentials, or
environment variables.

To move from mocks to real plugins, create a `sentinel.json` config file and
point it at your own detector/remediator/verifier classes. See
`docs/PLUGIN_GUIDE.md` and `config/settings.schema.json` for the schema and
contract details.
