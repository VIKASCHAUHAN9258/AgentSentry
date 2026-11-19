"""Phase 6 attack-lab contract and safety tests (no Docker/network required)."""
from __future__ import annotations

import ast
import json
import random
from pathlib import Path

from core.detector import BehaviorAnomalyDetector
from core.features import extract_session_features
from core.policy import get_policy
from core.risk_engine import assess_session
from lab.scenario_loader import load_scenarios, validate_scenario
from lab.synthetic import benign_sessions, build_rows

ROOT = Path(__file__).resolve().parents[1]


def test_all_five_phase6_scenarios_have_unique_ids_and_valid_steps():
    scenarios = load_scenarios()
    ids = [scenario["id"] for scenario in scenarios]
    assert len(scenarios) == 5
    assert len(ids) == len(set(ids))
    assert {s["id"] for s in scenarios} == {
        "A1-indirect-prompt-injection",
        "A2-privilege-escalation",
        "A3-exfil-chain-allowed-network",
        "A4-mcp-rug-pull",
        "B1-benign-code-review",
    }
    for scenario in scenarios:
        validate_scenario(scenario)


def test_lab_uses_fake_credentials_and_injected_text_only():
    fake_env = (ROOT / "lab_files" / ".env").read_text(encoding="utf-8")
    notes = (ROOT / "lab_files" / "notes.txt").read_text(encoding="utf-8")
    assert "FAKE-LAB" in fake_env
    assert "UNTRUSTED DOCUMENT CONTENT" in notes
    assert "Ignore previous instructions" in notes


def test_vulnerable_server_has_no_real_network_or_shell_execution():
    source = (ROOT / "mcp_lab" / "vulnerable_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_imports = {
        "subprocess",
        "urllib",
        "urllib3",
        "requests",
        "httpx",
        "http",
        "socket",
        "aiohttp",
    }
    imported_modules = []
    import_aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
                import_aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported_modules.append(module)
            for alias in node.names:
                import_aliases[alias.asname or alias.name] = f"{module}.{alias.name}"

    def qualified_name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = qualified_name(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

    assert not any(
        module == forbidden or module.startswith(f"{forbidden}.")
        for module in imported_modules
        for forbidden in forbidden_imports
    )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = qualified_name(node.func)
        if name is None:
            continue
        root, *suffix = name.split(".")
        name = ".".join([import_aliases.get(root, root), *suffix])
        assert name != "os.system"
        assert not name.startswith("subprocess.")
        assert not any(
            name == forbidden or name.startswith(f"{forbidden}.")
            for forbidden in forbidden_imports
        )
    assert "SIMULATED outbound request recorded locally" in source
    assert "SIMULATION ONLY: command was not executed" in source


def test_fast_benign_activity_is_low_risk_and_attack_chain_remains_high(tmp_path):
    scenarios = {scenario["id"]: scenario for scenario in load_scenarios()}
    benign = scenarios["B1-benign-code-review"]
    attack = scenarios["A3-exfil-chain-allowed-network"]

    for scenario in (benign, attack):
        baseline = benign_sessions(scenario["agent_id"], 40, seed_start=1000)
        detector = BehaviorAnomalyDetector(
            scenario["agent_id"], model_dir=tmp_path / scenario["agent_id"]
        )
        detector.fit(
            [
                extract_session_features(f"baseline-{index}", rows).to_vector()
                for index, rows in enumerate(baseline)
            ]
        )
        assert all(
            0.01 <= extract_session_features(f"timing-{index}", rows).avg_inter_call_gap_sec <= 0.1
            for index, rows in enumerate(baseline)
        )

        calls = [
            (step["tool"], step["arguments"])
            for step in scenario["steps"]
        ]
        delays = [0.0, 0.07, 0.015, 0.015][:len(calls)]
        rows = build_rows(calls, random.Random(17), delays=delays)
        features = extract_session_features(scenario["id"], rows)
        assessment = assess_session(
            scenario["id"],
            features,
            detector,
            get_policy(scenario["agent_id"]),
            rows=rows,
        )

        if scenario["type"] == "benign":
            assert assessment.risk_level == "LOW"
            assert assessment.policy_violations == []
            assert assessment.attack_chains == []
        else:
            assert assessment.risk_level in ("HIGH", "CRITICAL")
            assert any(
                chain.chain_id == scenario["expected"]["expect_chain"]
                for chain in assessment.attack_chains
            )


def test_docker_lab_is_network_isolated_and_hardened():
    compose = (ROOT / "lab" / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "lab" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "network_mode: none" in compose
    assert "cap_drop:" in compose and "ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "USER labuser" in dockerfile
