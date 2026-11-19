"""Contract test for lab/scenarios — keeps Member 2's scenarios and Member 3's benchmark in sync."""

from core.features import extract_session_features
from core.policy import evaluate_policy, get_policy
from lab.scenario_loader import load_scenarios, steps_to_rows


def test_all_scenarios_load_and_are_unique():
    scenarios = load_scenarios()
    ids = [s["id"] for s in scenarios]
    assert len(ids) == len(set(ids))
    assert any(s["type"] == "benign" for s in scenarios)
    assert sum(s["type"] == "attack" for s in scenarios) >= 4


def test_expected_policy_outcome_matches_real_policy_engine():
    """expect_policy_violation in each JSON must agree with core/policy.py — not just be claimed."""
    for s in load_scenarios():
        rows = steps_to_rows(s, seed=1)
        feats = extract_session_features(s["id"], rows)
        violations = evaluate_policy(feats, get_policy(s["agent_id"]))
        assert bool(violations) == s["expected"]["expect_policy_violation"], s["id"]
