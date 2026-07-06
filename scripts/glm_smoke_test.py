"""Smoke test: confirm GLM 5.2 (ollama.com) responds through the full Hermes stack.

Mirrors the live-trial's build_agent_factory (reads provider/model/base_url from
~/.hermes/config.yaml; resolves the API key from the provider's env var via
Hermes's own get_env_value_prefer_dotenv) but runs one NO-TOOL turn: it asks the
model a trivial question with every toolset disabled, so success depends ONLY on
the provider responding with usable content. No Docker, no reconcile handler,
no governance path -- just "is the configured LLM reachable and coherent?".

Run with the trial venv:
  source /tmp/of/hermes-test/hermes-agent/.venv-trial/bin/activate
  python scripts/glm_smoke_test.py
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

HERMES_ROOT = "/tmp/of/hermes-test/hermes-agent"
if HERMES_ROOT not in sys.path:
    sys.path.insert(0, HERMES_ROOT)


def build_agent() -> Any:
    """Build a real Hermes AIAgent from ~/.hermes/config.yaml + env, no tools."""
    from hermes_cli.config import get_env_value_prefer_dotenv, load_config
    from run_agent import AIAgent

    cfg = load_config()
    model_cfg = cfg.get("model", {}) or {}
    provider = model_cfg.get("provider", "")
    model = model_cfg.get("default", "")
    base_url = model_cfg.get("base_url", "")
    env_var = f"{provider.upper()}_API_KEY"
    api_key = get_env_value_prefer_dotenv(env_var) or os.environ.get(env_var, "")
    if not api_key:
        raise RuntimeError(f"no API key resolved for provider {provider!r} via {env_var}")
    print(
        f"[CONFIG] provider={provider} model={model} base_url={base_url} "
        f"key=<resolved,{len(api_key)} chars>",
        flush=True,
    )
    return AIAgent(
        base_url=base_url,
        api_key=api_key,
        provider=provider,
        model=model,
        max_iterations=2,
        max_tokens=2000,
        quiet_mode=True,
        skip_memory=True,
        load_soul_identity=False,
        disabled_toolsets=["terminal", "file", "web"],
    )


def main() -> int:
    agent = build_agent()
    t0 = time.time()
    result = agent.run_conversation(
        user_message=(
            "Reply with exactly one short sentence confirming you are online, "
            "then state the result of 2+2. No tool use."
        ),
        conversation_history=None,
    )
    dt = time.time() - t0
    final = getattr(result, "final_response", None) or str(result)
    print(f"[RUN] elapsed={dt:.1f}s", flush=True)
    print(f"[FINAL] {final!r}", flush=True)
    final_str = str(final).strip()
    if final_str and "No reply" not in final_str and final_str != "(empty)":
        print("[VERDICT] LLM responding: yes", flush=True)
        return 0
    print("[VERDICT] LLM responding: no (empty/no-reply)", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
