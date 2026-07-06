"""First live trial of HermesRemediator against a real Hermes instance.

Throwaway observational run on disposable synthetic data: a real model decides
what to do (not a scripted fake), observed through the real HermesRemediator
code path with the real per-action toolset restriction and real tool dispatch.

Provider/model are read from Hermes's own config (~/.hermes/config.yaml); the
API key is resolved from the env var named for that provider via Hermes's own
get_env_value_prefer_dotenv (no secrets in this script, nothing hardcoded).
Swapping providers is a config.yaml change, not a code change here or in
HermesRemediator.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

# --- make both stacks importable from this dedicated venv -------------------
HERMES_ROOT = "/tmp/of/hermes-test/hermes-agent"
SENTINEL_SRC = "/tmp/of/sentinel-real/src"
for p in (HERMES_ROOT, SENTINEL_SRC):
    if p not in sys.path:
        sys.path.insert(0, p)


def _log(label: str, msg: str) -> None:
    """Print a timestamped observation line."""
    print(f"[{label}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# 1. Provider/model from Hermes config; api_key from env (no secrets here).
# ---------------------------------------------------------------------------


def build_agent_factory() -> Any:
    """Return a factory building a real Hermes AIAgent from config + env.

    Reads model/provider/base_url from ``hermes_cli.config.load_config`` and the
    API key from the provider's env var via Hermes's own
    ``get_env_value_prefer_dotenv``. Nothing is hardcoded: swapping providers is
    a config.yaml edit. ``enabled_toolsets`` is left unset here because the
    remediator restricts the surface per-run via ``client.run``; we pass the
    allowed action's toolset at run time.
    """
    from hermes_cli.config import (  # type: ignore[import-not-found]
        get_env_value_prefer_dotenv,
        load_config,
    )
    from run_agent import AIAgent  # type: ignore[import-not-found]

    cfg = load_config()
    model_cfg = cfg.get("model", {}) or {}
    provider = model_cfg.get("provider", "openrouter")
    model = model_cfg.get("default", "")
    base_url = model_cfg.get("base_url", "")
    # Map provider -> env var name. openrouter resolves via OPENROUTER_API_KEY;
    # extend this map only if a new provider is added to config.yaml.
    env_var = {"openrouter": "OPENROUTER_API_KEY"}.get(provider, f"{provider.upper()}_API_KEY")
    api_key = get_env_value_prefer_dotenv(env_var) or os.environ.get(env_var, "")
    if not api_key:
        raise RuntimeError(f"no API key resolved for provider {provider!r} via {env_var}")
    _log(
        "CONFIG",
        f"provider={provider} model={model} base_url={base_url} "
        f"key=<resolved,{len(api_key)} chars>",
    )

    def _factory() -> Any:
        # quiet_mode=True: no rich UI noise; skip_memory avoids session state.
        return AIAgent(
            base_url=base_url,
            api_key=api_key,
            provider=provider,
            model=model,
            max_iterations=8,  # one tool call + a short follow-up is plenty
            quiet_mode=True,
            skip_memory=True,
            load_soul_identity=False,
        )

    return _factory


# ---------------------------------------------------------------------------
# 2. Disposable staging data: two fresh SQLite DBs, one seeded mismatch.
# ---------------------------------------------------------------------------


def seed_staging(tmp: Path) -> tuple[sqlite3.Connection, sqlite3.Connection]:
    """Create source + target DBs with one realistic mismatch (order o2)."""
    src = sqlite3.connect(str(tmp / "source.db"))
    tgt = sqlite3.connect(str(tmp / "target.db"))
    for conn in (src, tgt):
        conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT)")
    # o1 matches; o2 is the seeded mismatch (shipped vs stale 'paid'); o3 matches.
    src.executemany(
        "INSERT INTO orders VALUES (?,?)", [("o1", "shipped"), ("o2", "shipped"), ("o3", "closed")]
    )
    tgt.executemany(
        "INSERT INTO orders VALUES (?,?)", [("o1", "shipped"), ("o2", "paid"), ("o3", "closed")]
    )
    src.commit()
    tgt.commit()
    _log("SEED", "source o2=shipped, target o2=paid (stale) — one mismatch seeded")
    return src, tgt


# ---------------------------------------------------------------------------
# 3. The real run: detect -> remediate -> verify, through HermesRemediator.
# ---------------------------------------------------------------------------


def run_trial(tmp: Path) -> dict[str, Any]:
    """Run the full sequence against the live Hermes instance and collect obs."""
    from sentinel.core.audit import AuditLog  # noqa: F401
    from sentinel.core.trust import (
        TrustManager,  # noqa: F401
        TrustStore,
    )
    from sentinel.interfaces.enforcer import Enforcer
    from sentinel.plugins.datasource import SqliteTableSource
    from sentinel.plugins.detectors.data_reconciliation import (
        DataReconciliationDetector,
        ReconciliationTarget,
    )
    from sentinel.plugins.remediators.hermes import HermesRemediator
    from sentinel.plugins.remediators.hermes_mcp_tools import (
        HermesAIAgentClient,
        build_spec_set,
    )
    from sentinel.plugins.verifiers.data_reconciliation import (
        DataReconciliationVerifier,
    )

    src, tgt = seed_staging(tmp)
    target = ReconciliationTarget(
        name="orders",
        source=SqliteTableSource(src, "orders", "id"),
        target=SqliteTableSource(tgt, "orders", "id"),
        table="orders",
        key_column="id",
    )
    detector = DataReconciliationDetector([target])
    verifier = DataReconciliationVerifier([target])

    class _AllowReconcile(Enforcer):
        """Throwaway enforcer: allow reconcile_table_write for this trial only."""

        def authorize(self, action: str) -> Any:
            del action
            return None

        def allowed_actions(self, trust_level: str) -> list[str]:
            del trust_level
            return ["reconcile_table_write"]

    class _FixedTrust(TrustStore):
        """Throwaway trust store pinned at A4."""

        def set_trust(self, level: str) -> None:
            self._level = level

        def get_trust(self) -> str:
            return "A4"

    # 1. Detect
    incidents = detector.detect()
    _log("DETECT", f"incidents={len(incidents)}")
    assert len(incidents) == 1, incidents
    inc = incidents[0]
    _log(
        "DETECT",
        f"incident={inc.id} mismatches={inc.context.get('mismatches')} "
        f"total={inc.context.get('total_mismatch_count')}",
    )
    assert verifier.verify(inc) is False, "should be mismatched before remediation"

    # 2. Construct the real remediator. registrar=None -> production path:
    #    registers the wired spec set into Hermes's real global tools.registry.
    agent_factory = build_agent_factory()
    client = HermesAIAgentClient(agent_factory)
    spec_set = build_spec_set({"orders": target.target})
    remediator = HermesRemediator(
        lambda: client,
        _AllowReconcile(),
        _FixedTrust(),
        spec_set=spec_set,
        registrar=None,  # real global registry
    )

    # 3. Confirm the real tool listing (per-action toolset restriction) BEFORE run
    toolsets = ["sentinel_reconcile_table_write"]
    listed = client.list_tools(toolsets)
    _log("TOOL_SURFACE", f"enabled_toolsets={toolsets} listed_tools={listed}")

    # 4. Remediate against the live model
    t0 = time.time()
    result = remediator.remediate(inc, _AllowReconcile())
    dt = time.time() - t0
    _log("REMEDIATE", f"success={result.success} breach={result.breach} elapsed={dt:.1f}s")
    _log("REMEDIATE", f"summary={result.summary!r}")

    # 5. The full transcript Hermes actually produced
    convo = json.loads(inc.external_refs.get("conversation") or "[]")
    _log("TRANSCRIPT", f"{len(convo)} messages")
    for i, m in enumerate(convo):
        _log("TRANSCRIPT", f"--- msg {i} role={m.get('role')} ---")
        if m.get("content") is not None:
            _log("TRANSCRIPT", f"  content: {json.dumps(m.get('content'))[:300]}")
        if m.get("tool_calls"):
            for tc in m["tool_calls"]:
                fn = tc.get("function", {})
                _log("TRANSCRIPT", f"  tool_call: name={fn.get('name')} args={fn.get('arguments')}")
        if m.get("tool_call_id"):
            _log(
                "TRANSCRIPT",
                f"  tool_call_id={m.get('tool_call_id')} "
                f"content={json.dumps(m.get('content'))[:200]}",
            )

    # 6. Verify against the REAL database state afterward
    tgt_after = tgt.execute("SELECT id,status FROM orders ORDER BY id").fetchall()
    src_after = src.execute("SELECT id,status FROM orders ORDER BY id").fetchall()
    _log("DB_AFTER", f"target={tgt_after}")
    _log("DB_AFTER", f"source={src_after}")
    verified = verifier.verify(inc)
    _log("VERIFY", f"verify()={verified}")
    fresh = detector.detect()
    _log("VERIFY", f"fresh detect()={len(fresh)} incidents (expect 0 if reconciled)")

    src.close()
    tgt.close()
    return {
        "success": result.success,
        "breach": result.breach,
        "summary": result.summary,
        "listed_tools": listed,
        "transcript_len": len(convo),
        "verified": verified,
        "fresh_incidents": len(fresh),
        "elapsed_s": round(dt, 1),
    }


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory(prefix="hermes_trial_") as tmp:
        _log("START", f"tmp={tmp}")
        out = run_trial(Path(tmp))
        _log("RESULT", json.dumps(out, indent=2))
