"""
Shared synthetic-session helpers (OWNER: Member 2, used by everyone).

Builds telemetry-shaped rows (same keys as core.telemetry.get_session_calls)
WITHOUT needing a live MCP session. Used by:
  - lab/scenario_loader.py  (turn a scenario's steps into rows)
  - benchmark/run_benchmark.py (Member 3)
  - scripts/demo_risk_assessment.py (Member 1)
  - Phase 8 tests (Member 2)

These rows are SYNTHETIC. Anything measured on them must be reported as
"synthetic benchmark", never as real-world detection accuracy.
"""

from __future__ import annotations

import json
import random

PATHS = ["notes.txt", "README.md", "src/app.py", "src/utils.py", "docs/guide.md"]
QUERIES = ["TODO", "FIXME", "auth", "login", "rate limit"]
URLS = [
    "https://docs.python.org/3/",
    "https://flask.palletsprojects.com/",
    "https://pypi.org/project/mcp/",
]


def build_rows(calls, rng, delays=None):
    """calls: list of (tool_name, arguments_dict). Returns list of row dicts."""
    rows, t = [], 0.0
    for i, (tool, args) in enumerate(calls):
        gap = delays[i] if delays and delays[i] is not None else rng.uniform(0.01, 0.1)
        t += gap
        rows.append(
            {
                "tool_name": tool,
                "arguments_json": json.dumps(args),
                "called_at": t,
                "duration_ms": rng.uniform(1.0, 20.0),
                "is_error": 0,
                "sequence_num": i + 1,
            }
        )
    return rows


def _args_for(tool, rng):
    if tool == "read_file":
        return {"path": rng.choice(PATHS)}
    if tool == "search_code":
        return {"query": rng.choice(QUERIES)}
    if tool == "http_request":
        return {"url": rng.choice(URLS)}
    if tool == "report":
        return {"summary": "Reviewed, no blocking issues."}
    return {}


# Normal behaviour per agent. research-assistant legitimately uses the network.
PROFILES = {
    "demo-code-reviewer": ["read_file", "search_code"],
    "research-assistant": ["read_file", "search_code", "http_request"],
}


def benign_rows(agent_id, seed):
    """One benign session: read_file first, 1-5 random profile tools, report last."""
    rng = random.Random(seed)
    tools = PROFILES.get(agent_id, PROFILES["demo-code-reviewer"])
    middle = [rng.choice(tools) for _ in range(rng.randint(1, 5))]
    sequence = ["read_file"] + middle + ["report"]
    calls = [(t, _args_for(t, rng)) for t in sequence]
    return build_rows(calls, rng)


def benign_sessions(agent_id, n, seed_start=0):
    return [benign_rows(agent_id, seed_start + i) for i in range(n)]
