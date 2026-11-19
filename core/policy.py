"""
AgentSentry — Phase 4 policy engine.

Deterministic, rule-based checks that do NOT depend on the ML model at all.
This is the layer that answers "what if the ML model is wrong": a policy
violation always forces a CRITICAL risk level, regardless of what the
Isolation Forest says. Real detection systems are never pure ML for exactly
this reason — a rule like "a READ_ONLY agent must never execute shell
commands" should not be something a statistical model can be talked out of.

Each agent gets an AgentPolicy: a privilege ceiling and an explicit deny-list
of tool names. Two independent checks are run:
    1. max_allowed_privilege — the highest privilege level this agent may
       EVER reach in a session (checked against features.max_privilege_level,
       which itself already accounts for every call in the session).
    2. denied_tools — specific tools that are never allowed for this agent,
       even if their privilege level would otherwise be acceptable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.features import SessionFeatures
from core.privilege import PrivilegeLevel


@dataclass
class AgentPolicy:
    agent_id: str
    max_allowed_privilege: int
    denied_tools: set[str] = field(default_factory=set)


@dataclass
class PolicyViolation:
    rule: str
    detail: str
    severity: str = "CRITICAL"


# Default policy for tools/agents with no explicit policy registered.
# Conservative by design: NETWORK-level ceiling, nothing EXECUTE-level allowed
# without an explicit policy saying so.
DEFAULT_POLICY_CEILING = PrivilegeLevel.NETWORK

# Phase 1-3's demo agent is a read-only "CodeReviewer" — its policy reflects
# exactly that. Later phases (Docker attack lab) will register policies for
# agents that legitimately need higher privilege, rather than loosening this
# default.
AGENT_POLICIES: dict[str, AgentPolicy] = {
    "research-assistant": AgentPolicy(
        agent_id="research-assistant",
        max_allowed_privilege=PrivilegeLevel.NETWORK,
        denied_tools=set(),
    ),
    "demo-code-reviewer": AgentPolicy(
        agent_id="demo-code-reviewer",
        max_allowed_privilege=PrivilegeLevel.READ,
        denied_tools={"shell_execute", "sudo_command", "delete_file", "http_request", "send_email"},
    ),
}


def get_policy(agent_id: str) -> AgentPolicy:
    """Look up an agent's policy, falling back to a conservative default
    rather than allowing unregistered agents unlimited privilege."""
    return AGENT_POLICIES.get(
        agent_id,
        AgentPolicy(agent_id=agent_id, max_allowed_privilege=DEFAULT_POLICY_CEILING),
    )


def evaluate_policy(features: SessionFeatures, policy: AgentPolicy) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []

    if features.max_privilege_level > policy.max_allowed_privilege:
        violations.append(
            PolicyViolation(
                rule="max_allowed_privilege",
                detail=(
                    f"Session reached privilege level {features.max_privilege_level} "
                    f"but agent '{policy.agent_id}' is capped at {policy.max_allowed_privilege}"
                ),
            )
        )

    used_denied_tools = set(features.tool_sequence) & policy.denied_tools
    for tool_name in sorted(used_denied_tools):
        violations.append(
            PolicyViolation(
                rule="denied_tool",
                detail=f"Agent '{policy.agent_id}' called denied tool '{tool_name}'",
            )
        )

    return violations
