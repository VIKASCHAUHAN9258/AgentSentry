"""
Scenario contract (OWNER: Member 2; CONSUMERS: Member 2 lab runner, Member 3 benchmark).

A scenario is one JSON file in lab/scenarios/. See lab/scenario_schema.md.
Changing the schema = tell the whole team (it is the shared contract).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from lab.synthetic import build_rows

SCENARIO_DIR = Path(__file__).parent / "scenarios"
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
REQUIRED = ("id", "name", "type", "agent_id", "description", "expected", "steps")


def validate_scenario(s: dict) -> None:
    for key in REQUIRED:
        if key not in s:
            raise ValueError(f"scenario missing key '{key}'")
    if s["type"] not in ("benign", "attack"):
        raise ValueError(f"{s['id']}: type must be 'benign' or 'attack'")
    if s["expected"].get("min_risk_level") not in LEVELS:
        raise ValueError(f"{s['id']}: expected.min_risk_level must be one of {LEVELS}")
    if not s["steps"]:
        raise ValueError(f"{s['id']}: steps must not be empty")
    for i, step in enumerate(s["steps"]):
        if not isinstance(step.get("tool"), str) or not isinstance(step.get("arguments"), dict):
            raise ValueError(f"{s['id']}: step {i} needs 'tool' (str) and 'arguments' (dict)")
    if "lab_config" in s:
        lab_config = s["lab_config"]
        if not isinstance(lab_config, dict):
            raise ValueError(f"{s['id']}: lab_config must be an object")
        mutation_after_calls = lab_config.get("read_document_rug_pull_after_calls")
        if (
            not isinstance(mutation_after_calls, int)
            or isinstance(mutation_after_calls, bool)
            or mutation_after_calls < 1
        ):
            raise ValueError(
                f"{s['id']}: lab_config.read_document_rug_pull_after_calls must be a positive integer"
            )


def load_scenarios(directory: Path = SCENARIO_DIR) -> list[dict]:
    scenarios = []
    for path in sorted(Path(directory).glob("*.json")):
        s = json.loads(path.read_text(encoding="utf-8"))
        validate_scenario(s)
        scenarios.append(s)
    return scenarios


def steps_to_rows(scenario: dict, seed: int = 0, benign_prefix: bool = False) -> list[dict]:
    """Scenario -> telemetry-shaped rows. benign_prefix adds 0-2 normal calls first
    (makes attack variants less trivially separable)."""
    rng = random.Random(seed)
    calls, delays = [], []
    if benign_prefix:
        for _ in range(rng.randint(0, 2)):
            calls.append(rng.choice([("read_file", {"path": "notes.txt"}), ("search_code", {"query": "TODO"})]))
            delays.append(None)
    for step in scenario["steps"]:
        calls.append((step["tool"], step["arguments"]))
        delays.append(step.get("delay_sec"))
    return build_rows(calls, rng, delays)
