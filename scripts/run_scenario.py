"""
Run Phase 6 scenarios through the actual AgentSentry stdio proxy.

Usage:
  python scripts/run_scenario.py A3-exfil-chain-allowed-network
  python scripts/run_scenario.py --all

All server-side effects are simulation-only. The MCP server never opens sockets,
executes shell commands, or deletes real files.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from mcp import ClientSession, StdioServerParameters, stdio_client
from core.detector import BehaviorAnomalyDetector
from core.features import extract_session_features
from core.policy import get_policy, evaluate_policy
from core.risk_engine import assess_session
from core.telemetry import get_session_timeline
from lab.scenario_loader import load_scenarios
from lab.synthetic import benign_sessions

def _params(agent_id: str, db_path: Path, scenario: dict) -> StdioServerParameters:
    env = dict(os.environ)
    env["AGENTSENTRY_DB_PATH"] = str(db_path)
    mutation_after_calls = scenario.get("lab_config", {}).get(
        "read_document_rug_pull_after_calls"
    )
    if mutation_after_calls is None:
        env.pop("AGENTSENTRY_LAB_RUG_PULL_AFTER_CALLS", None)
    else:
        env["AGENTSENTRY_LAB_RUG_PULL_AFTER_CALLS"] = str(mutation_after_calls)
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "core.proxy", "--agent-id", agent_id, "--",
              sys.executable, str(PROJECT_ROOT / "mcp_lab" / "vulnerable_server.py")],
        cwd=str(PROJECT_ROOT),
        env=env,
    )

async def _execute(scenario: dict, db_path: Path) -> tuple[str, list]:
    params = _params(scenario["agent_id"], db_path, scenario)
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            available = {tool.name for tool in (await session.list_tools()).tools}
            for step in scenario["steps"]:
                tool = step["tool"]
                if tool not in available:
                    raise RuntimeError(f"{scenario['id']}: server does not expose required tool {tool!r}")
                if step.get("delay_sec"):
                    await asyncio.sleep(min(float(step["delay_sec"]), 5.0))
                await session.call_tool(tool, step["arguments"])
            # The proxy persists session rows before forwarding each response.
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    sid_row = conn.execute("SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1").fetchone()
    conn.close()
    if sid_row is None:
        raise RuntimeError("proxy did not create a telemetry session")
    sid = sid_row["session_id"]
    return sid, get_session_timeline(sid, db_path=db_path)

def _score(scenario: dict, rows: list) -> tuple[str, object]:
    call_rows = [row for row in rows if row.get("event_type") != "tool_definition_changed"]
    features = extract_session_features(scenario["id"], call_rows)
    agent_id = scenario["agent_id"]
    baseline = benign_sessions(agent_id, 40, seed_start=1000)
    detector = BehaviorAnomalyDetector(agent_id, model_dir=PROJECT_ROOT / "models" / "phase6-temp")
    detector.fit([extract_session_features(f"baseline-{i}", r).to_vector() for i, r in enumerate(baseline)])
    assessment = assess_session(scenario["id"], features, detector, get_policy(agent_id), rows=rows)
    return assessment.risk_level, assessment

def run_one(scenario: dict) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="agentsentry-phase6-") as td:
        db = Path(td) / "scenario.db"
        sid, rows = asyncio.run(_execute(scenario, db))
        level, assessment = _score(scenario, rows)
        expected = scenario["expected"]
        levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        ok = levels[level] >= levels[expected["min_risk_level"]]
        policy_hit = bool(assessment.policy_violations)
        if "expect_policy_violation" in expected:
            ok = ok and policy_hit == expected["expect_policy_violation"]
        wanted_chain = expected.get("expect_chain")
        actual_chains = {c.chain_id for c in assessment.attack_chains}
        if wanted_chain:
            ok = ok and wanted_chain in actual_chains
        elif scenario["type"] == "benign":
            ok = ok and not actual_chains and not policy_hit
        reasons = "; ".join(assessment.why_flagged()) or "No deterministic finding"
        return ok, f"{scenario['id']}: {level} | policy={policy_hit} | chains={','.join(sorted(actual_chains)) or '-'} | {reasons}"

def main() -> int:
    parser = argparse.ArgumentParser(description="Run AgentSentry's isolated simulated MCP attack scenarios")
    parser.add_argument("scenario", nargs="?", help="Scenario ID or filename stem")
    parser.add_argument("--all", action="store_true", help="Run every scenario")
    args = parser.parse_args()
    scenarios = load_scenarios()
    if args.all:
        selected = scenarios
    elif args.scenario:
        key = args.scenario.removesuffix(".json")
        selected = [s for s in scenarios if s["id"] == key or s["id"].startswith(key)]
        if not selected:
            parser.error(f"unknown scenario: {args.scenario}")
    else:
        parser.error("provide a scenario ID or --all")
    results = []
    for scenario in selected:
        try:
            ok, detail = run_one(scenario)
        except Exception as exc:
            ok, detail = False, f"{scenario['id']}: ERROR: {type(exc).__name__}: {exc}"
        results.append((ok, detail))
    print("\nAgentSentry Phase 6 — simulation results")
    print("-" * 110)
    for ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {detail}")
    print("-" * 110)
    print(f"{sum(ok for ok, _ in results)}/{len(results)} scenarios passed")
    return 0 if all(ok for ok, _ in results) else 1

if __name__ == "__main__":
    raise SystemExit(main())
