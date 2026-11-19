"""
Phase 5 tests (Member 2). Written FIRST (test-driven).

These are active acceptance tests for the Phase 5 chain detector and sensitive-path matcher.
"""

import pytest

from core.chain_detector import detect_chains, is_sensitive_path
from lab.scenario_loader import load_scenarios, steps_to_rows

SCENARIOS = {s["id"]: s for s in load_scenarios()}


@pytest.mark.parametrize("scenario_id", [
    "A1-indirect-prompt-injection", "A2-privilege-escalation", "A3-exfil-chain-allowed-network",
])
def test_attack_scenarios_produce_their_expected_chain(scenario_id):
    s = SCENARIOS[scenario_id]
    chains = detect_chains(steps_to_rows(s, seed=3))
    assert s["expected"]["expect_chain"] in [c.chain_id for c in chains]


def test_benign_scenario_has_no_chain():
    assert detect_chains(steps_to_rows(SCENARIOS["B1-benign-code-review"], seed=3)) == []


def test_attack_with_benign_prefix_is_still_detected():
    s = SCENARIOS["A3-exfil-chain-allowed-network"]
    for seed in range(20):
        chains = detect_chains(steps_to_rows(s, seed=seed, benign_prefix=True))
        assert chains, f"missed with seed {seed}"


@pytest.mark.parametrize("path,expected", [
    (".env", True), ("config/.env.production", True), ("~/.ssh/id_rsa", True), ("notes.txt", False), ("README.md", False),
])
def test_is_sensitive_path(path, expected):
    assert is_sensitive_path(path) is expected


def test_chain_window_allows_configured_unrelated_calls_but_not_unbounded_gap():
    base = [
        {"tool_name": "read_file", "arguments_json": '{"path":".env"}', "sequence_num": 1},
        {"tool_name": "search_code", "arguments_json": '{}', "sequence_num": 2},
        {"tool_name": "report", "arguments_json": '{}', "sequence_num": 3},
        {"tool_name": "http_request", "arguments_json": '{"url":"https://example.invalid"}', "sequence_num": 4},
    ]
    assert any(c.chain_id == "sensitive_read_to_network" for c in detect_chains(base))
    too_far = base[:1] + [
        {"tool_name": "search_code", "arguments_json": '{}', "sequence_num": i}
        for i in range(2, 6)
    ] + [
        {"tool_name": "http_request", "arguments_json": '{}', "sequence_num": 6}
    ]
    assert not any(c.chain_id == "sensitive_read_to_network" for c in detect_chains(too_far))


def test_sensitive_path_detection_handles_nested_and_common_secret_names():
    assert is_sensitive_path("/home/agent/.ssh/id_ed25519")
    assert is_sensitive_path("config/api_key.json")
    assert is_sensitive_path("/etc/shadow")
    assert not is_sensitive_path("src/tokenizer.py")
    assert not is_sensitive_path("docs/README.md")


def test_tool_definition_change_requires_a_later_invocation_of_that_tool():
    rows = [
        {"tool_name": "read_document", "arguments_json": "{}", "sequence_num": 1},
        {
            "event_type": "tool_definition_changed",
            "tool_name": "read_document",
            "sequence_num": 1.5,
        },
        {"tool_name": "http_request", "arguments_json": "{}", "sequence_num": 2},
        {"tool_name": "read_document", "arguments_json": "{}", "sequence_num": 3},
    ]

    chain, = [
        chain for chain in detect_chains(rows)
        if chain.chain_id == "tool_definition_changed"
    ]
    assert chain.call_indices == [1, 3]


def test_tool_definition_change_does_not_match_the_removed_fake_marker_tool():
    rows = [
        {"tool_name": "__tool_definition_changed__", "arguments_json": "{}", "sequence_num": 1},
        {"tool_name": "read_document", "arguments_json": "{}", "sequence_num": 2},
    ]
    assert not any(chain.chain_id == "tool_definition_changed" for chain in detect_chains(rows))
