"""
AgentSentry — Phase 4 risk engine.

Combines core/detector.py (ML anomaly score) and core/policy.py (deterministic
rules) into one final RiskAssessment. This is the hybrid design agreed on
earlier: a policy violation ALWAYS forces the risk level to CRITICAL,
regardless of what the ML model scored — the ML model can be wrong or
under-trained, a policy rule like "read-only agent must not execute shell
commands" should not be overridable by a statistical anomaly score.

Risk level thresholds (documented, tunable — not hidden magic numbers):
    0-24   LOW
    25-49  MEDIUM
    50-74  HIGH
    75-100 CRITICAL
A policy violation short-circuits straight to CRITICAL at score >= 95,
regardless of where the ML score alone would have landed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.detector import BehaviorAnomalyDetector, FeatureContribution
from core.features import SessionFeatures
from core.policy import AgentPolicy, PolicyViolation, evaluate_policy
from core.chain_detector import AttackChain, detect_chains


@dataclass
class RiskAssessment:
    session_id: str
    agent_id: str
    ml_risk_score: float
    final_risk_score: float
    risk_level: str
    policy_violations: list[PolicyViolation]
    feature_contributions: list[FeatureContribution]
    attack_chains: list[AttackChain] = field(default_factory=list)

    def why_flagged(self, top_n: int = 5) -> list[str]:
        """Human-readable 'why flagged' lines — the dashboard-facing explainability
        feature discussed earlier ('WHY FLAGGED?' breakdown, not just a bare score)."""
        lines = [f"POLICY VIOLATION: {v.detail}" for v in self.policy_violations]
        for chain in self.attack_chains:
            indices = ", ".join(str(i) for i in chain.call_indices)
            mitre = f" MITRE: {chain.mitre_hint}" if chain.mitre_hint else ""
            lines.append(
                f"ATTACK CHAIN: {chain.chain_id} ({chain.severity}) at call indices "
                f"[{indices}] — {chain.description}{mitre}"
            )
        for c in self.feature_contributions[:top_n]:
            if abs(c.z_score) < 1.0:
                continue  # not meaningfully different from baseline — don't clutter the reason list
            direction = "above" if c.z_score > 0 else "below"
            lines.append(
                f"{c.feature}: {c.value:.2f} is {abs(c.z_score):.1f} std devs {direction} "
                f"this agent's baseline ({c.baseline_mean:.2f})"
            )
        return lines


def _risk_level_from_score(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def assess_session(
    session_id: str,
    features: SessionFeatures,
    detector: BehaviorAnomalyDetector,
    policy: AgentPolicy,
    rows=None,
) -> RiskAssessment:
    ml_score, contributions = detector.score(features.to_vector())
    violations = evaluate_policy(features, policy)
    attack_chains = detect_chains(rows) if rows is not None else []

    if violations:
        # Policy layer wins regardless of ML score — see module docstring.
        final_score = max(ml_score, 95.0)
        risk_level = "CRITICAL"
    else:
        final_score = ml_score
        risk_level = _risk_level_from_score(final_score)

    # Deterministic chain findings raise (never lower) the hybrid assessment.
    for chain in attack_chains:
        if chain.severity.upper() == "CRITICAL":
            final_score = max(final_score, 90.0)
            risk_level = "CRITICAL"
        elif chain.severity.upper() == "HIGH":
            final_score = max(final_score, 70.0)
            if risk_level not in ("HIGH", "CRITICAL"):
                risk_level = "HIGH"

    return RiskAssessment(
        session_id=session_id,
        agent_id=policy.agent_id,
        ml_risk_score=ml_score,
        final_risk_score=final_score,
        risk_level=risk_level,
        policy_violations=violations,
        feature_contributions=contributions,
        attack_chains=attack_chains,
    )
