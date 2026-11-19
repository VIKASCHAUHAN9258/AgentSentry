"""
Phase 4 tests: risk engine (the hybrid combination of detector.py + policy.py).

The single most important behavior to verify here: a policy violation must
FORCE critical risk regardless of what the ML model scored — that's the
whole point of not being pure-ML (see risk_engine.py's module docstring).
"""

from __future__ import annotations

import random

import pytest

from core.detector import BehaviorAnomalyDetector
from core.features import extract_session_features
from core.policy import AgentPolicy, get_policy
from core.privilege import PrivilegeLevel
from core.risk_engine import assess_session


def _benign_rows(seed: int) -> list[dict]:
    rng = random.Random(seed)
    calls = [
        ("read_file", '{"path": "notes.txt"}'),
        ("search_code", '{"query": "TODO"}'),
        ("report", '{"summary": "Reviewed, no issues."}'),
    ]
    t = 0.0
    rows = []
    for i, (name, args) in enumerate(calls):
        t += rng.uniform(0.5, 3.0)
        rows.append(
            {
                "tool_name": name,
                "arguments_json": args,
                "called_at": t,
                "duration_ms": rng.uniform(1.0, 15.0),
                "is_error": 0,
                "sequence_num": i + 1,
            }
        )
    return rows


@pytest.fixture(scope="module")
def trained_detector(tmp_path_factory):
    training_vectors = []
    for seed in range(30):
        rows = _benign_rows(seed)
        features = extract_session_features(f"train-{seed}", rows)
        training_vectors.append(features.to_vector())
    model_dir = tmp_path_factory.mktemp("risk_engine_models")
    detector = BehaviorAnomalyDetector(agent_id="demo-code-reviewer", model_dir=model_dir)
    detector.fit(training_vectors)
    return detector


def test_benign_session_is_low_risk_with_no_violations(trained_detector):
    rows = _benign_rows(seed=999)
    features = extract_session_features("benign-session", rows)
    policy = get_policy("demo-code-reviewer")  # READ-only ceiling

    assessment = assess_session("benign-session", features, trained_detector, policy)

    assert assessment.policy_violations == []
    assert assessment.risk_level in ("LOW", "MEDIUM")
    assert assessment.final_risk_score == assessment.ml_risk_score


def test_policy_violation_forces_critical_regardless_of_ml_score(trained_detector):
    """Core hybrid guarantee: even a session an ML model might score as only mildly
    unusual gets forced to CRITICAL the moment it violates a hard policy rule."""
    rows = [
        {"tool_name": "read_file", "arguments_json": '{"path": "notes.txt"}',
         "called_at": 0.0, "duration_ms": 5.0, "is_error": 0, "sequence_num": 1},
        # demo-code-reviewer's policy explicitly denies shell_execute AND caps at READ
        {"tool_name": "shell_execute", "arguments_json": '{"command": "whoami"}',
         "called_at": 1.0, "duration_ms": 5.0, "is_error": 0, "sequence_num": 2},
    ]
    features = extract_session_features("privesc-attack", rows)
    policy = get_policy("demo-code-reviewer")

    assessment = assess_session("privesc-attack", features, trained_detector, policy)

    assert len(assessment.policy_violations) >= 1
    assert assessment.risk_level == "CRITICAL"
    assert assessment.final_risk_score >= 95.0


def test_why_flagged_includes_policy_violation_text(trained_detector):
    rows = [
        {"tool_name": "read_file", "arguments_json": "{}",
         "called_at": 0.0, "duration_ms": 5.0, "is_error": 0, "sequence_num": 1},
        {"tool_name": "sudo_command", "arguments_json": '{"cmd": "rm -rf /"}',
         "called_at": 1.0, "duration_ms": 5.0, "is_error": 0, "sequence_num": 2},
    ]
    features = extract_session_features("sudo-attack", rows)
    policy = get_policy("demo-code-reviewer")

    assessment = assess_session("sudo-attack", features, trained_detector, policy)
    reasons = assessment.why_flagged()

    assert any("POLICY VIOLATION" in line for line in reasons)
    assert any("sudo_command" in line for line in reasons)


def test_why_flagged_on_benign_session_has_no_policy_lines(trained_detector):
    rows = _benign_rows(seed=42)
    features = extract_session_features("benign-why", rows)
    policy = get_policy("demo-code-reviewer")

    assessment = assess_session("benign-why", features, trained_detector, policy)
    reasons = assessment.why_flagged()

    assert not any("POLICY VIOLATION" in line for line in reasons)


def test_unregistered_agent_gets_conservative_default_policy(trained_detector):
    """An agent nobody explicitly configured should not get a free pass to EXECUTE."""
    rows = [
        {"tool_name": "read_file", "arguments_json": "{}",
         "called_at": 0.0, "duration_ms": 5.0, "is_error": 0, "sequence_num": 1},
        {"tool_name": "shell_execute", "arguments_json": '{"command": "id"}',
         "called_at": 1.0, "duration_ms": 5.0, "is_error": 0, "sequence_num": 2},
    ]
    features = extract_session_features("unregistered-agent-session", rows)
    policy = get_policy("some-brand-new-agent")  # not in AGENT_POLICIES

    assessment = assess_session("unregistered-agent-session", features, trained_detector, policy)
    assert assessment.risk_level == "CRITICAL"  # EXECUTE > default NETWORK ceiling


def test_attack_chain_raises_allowed_network_session_to_high(trained_detector):
    """A3 has no policy violation; the sequence itself must raise risk to HIGH."""
    from lab.scenario_loader import load_scenarios, steps_to_rows

    scenario = next(s for s in load_scenarios() if s["id"] == "A3-exfil-chain-allowed-network")
    rows = steps_to_rows(scenario, seed=17)
    features = extract_session_features("a3-chain", rows)
    assessment = assess_session(
        "a3-chain", features, trained_detector, get_policy("research-assistant"), rows=rows
    )

    assert assessment.policy_violations == []
    assert assessment.final_risk_score >= 70.0
    assert assessment.risk_level in ("HIGH", "CRITICAL")
    assert any(c.chain_id == "sensitive_read_to_network" for c in assessment.attack_chains)
    assert any("ATTACK CHAIN" in line for line in assessment.why_flagged())


def test_critical_attack_chain_forces_critical_without_policy(trained_detector):
    """The chain severity floor is independent of the ML score and policy layer."""
    from lab.scenario_loader import load_scenarios, steps_to_rows

    scenario = next(s for s in load_scenarios() if s["id"] == "A2-privilege-escalation")
    rows = steps_to_rows(scenario, seed=23)
    features = extract_session_features("a2-chain", rows)
    assessment = assess_session(
        "a2-chain", features, trained_detector, get_policy("demo-code-reviewer"), rows=rows
    )

    assert assessment.risk_level == "CRITICAL"
    assert assessment.final_risk_score >= 95.0  # policy also independently forces this
    assert any(c.chain_id == "read_to_execute" for c in assessment.attack_chains)
