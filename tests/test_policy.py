"""
Phase 4 tests: policy engine (deterministic, no ML involved).
"""

from __future__ import annotations

from core.features import extract_session_features
from core.policy import AgentPolicy, evaluate_policy, get_policy
from core.privilege import PrivilegeLevel


def _rows(calls: list[tuple[str, str]]) -> list[dict]:
    return [
        {
            "tool_name": name,
            "arguments_json": args,
            "called_at": float(i),
            "duration_ms": 1.0,
            "is_error": 0,
            "sequence_num": i + 1,
        }
        for i, (name, args) in enumerate(calls)
    ]


def test_default_policy_for_unregistered_agent_is_conservative():
    policy = get_policy("some-new-agent-nobody-configured")
    assert policy.max_allowed_privilege == PrivilegeLevel.NETWORK


def test_registered_demo_agent_policy_is_read_only():
    policy = get_policy("demo-code-reviewer")
    assert policy.max_allowed_privilege == PrivilegeLevel.READ
    assert "shell_execute" in policy.denied_tools


def test_read_only_session_has_no_violations():
    rows = _rows([("read_file", '{"path": "notes.txt"}'), ("report", "{}")])
    features = extract_session_features("s1", rows)
    policy = get_policy("demo-code-reviewer")
    violations = evaluate_policy(features, policy)
    assert violations == []


def test_privilege_ceiling_violation_detected():
    rows = _rows([("read_file", "{}"), ("shell_execute", '{"command": "whoami"}')])
    features = extract_session_features("s2", rows)
    policy = get_policy("demo-code-reviewer")  # capped at READ
    violations = evaluate_policy(features, policy)
    assert any(v.rule == "max_allowed_privilege" for v in violations)


def test_denied_tool_violation_detected_even_if_privilege_allowed():
    """A custom policy could in principle allow EXECUTE broadly but still deny one
    specific tool by name — both checks are independent."""
    policy = AgentPolicy(
        agent_id="custom-agent",
        max_allowed_privilege=PrivilegeLevel.EXECUTE,
        denied_tools={"sudo_command"},
    )
    rows = _rows([("read_file", "{}"), ("sudo_command", '{"cmd": "rm -rf /"}')])
    features = extract_session_features("s3", rows)
    violations = evaluate_policy(features, policy)
    assert any(v.rule == "denied_tool" and "sudo_command" in v.detail for v in violations)
