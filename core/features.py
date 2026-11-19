"""
AgentSentry — Phase 3 feature engineering.

Turns the raw tool_calls rows for one session (as logged by core/proxy.py in
Phase 2) into a numeric feature vector describing that session's behavior.
This is the layer Phase 4's Isolation Forest + policy engine will consume —
Phase 3 itself does NOT decide what's anomalous, it only measures.

Feature groups implemented here (matching the research doc's proposal):
    - sequence:     tool-call order, bigram counts, unique-tool count
    - privilege:    max privilege reached, escalation distance, start/end level
    - argument:     Shannon entropy of argument values (flags encoded/obfuscated payloads)
    - timing:       session duration, inter-call gaps
    - reliability:  error rate

Design note: this module works purely off `tool_calls` rows (session_id,
sequence_num, tool_name, arguments_json, called_at, duration_ms, is_error).
It does not care whether those rows came from a live MCP session or were
inserted directly for a test — which is what makes it independently testable
without a running MCP server (see tests/test_features.py).
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field

from core.privilege import privilege_of


@dataclass
class SessionFeatures:
    session_id: str
    call_count: int
    unique_tools_used: int
    tool_sequence: list[str]
    bigrams: Counter
    error_count: int
    error_rate: float
    session_duration_sec: float
    avg_inter_call_gap_sec: float
    max_inter_call_gap_sec: float
    max_privilege_level: int
    start_privilege_level: int
    end_privilege_level: int
    privilege_escalation_distance: int
    avg_argument_entropy: float
    max_argument_entropy: float

    def to_vector(self) -> dict[str, float]:
        """Flat numeric dict — what Phase 4's Isolation Forest will actually train on.
        Deliberately excludes non-numeric fields (tool_sequence, bigrams, session_id)."""
        return {
            "call_count": float(self.call_count),
            "unique_tools_used": float(self.unique_tools_used),
            "error_rate": self.error_rate,
            "session_duration_sec": self.session_duration_sec,
            "avg_inter_call_gap_sec": self.avg_inter_call_gap_sec,
            "max_inter_call_gap_sec": self.max_inter_call_gap_sec,
            "max_privilege_level": float(self.max_privilege_level),
            "start_privilege_level": float(self.start_privilege_level),
            "end_privilege_level": float(self.end_privilege_level),
            "privilege_escalation_distance": float(self.privilege_escalation_distance),
            "avg_argument_entropy": self.avg_argument_entropy,
            "max_argument_entropy": self.max_argument_entropy,
        }


def _shannon_entropy(text: str) -> float:
    """Character-level Shannon entropy in bits. Empty string -> 0.0.

    Used on argument VALUES (not keys) because obfuscated/encoded payloads
    (e.g. base64-encoded exfiltrated data) have visibly higher entropy than
    typical plain-text arguments like file paths or search queries — this is
    the concrete signal for the "transform" step in the documented
    sensitive-read -> transform -> network exfiltration chain pattern.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_argument_values_text(arguments_json: str) -> str:
    """Concatenate only the VALUES of an arguments dict into one string for entropy scoring."""
    try:
        args = json.loads(arguments_json)
    except (json.JSONDecodeError, TypeError):
        return arguments_json or ""
    if not isinstance(args, dict):
        return str(args)
    return " ".join(str(v) for v in args.values())


def extract_session_features(session_id: str, rows: list) -> SessionFeatures:
    """Build a SessionFeatures object from ordered tool_calls rows for one session.

    `rows` must be sqlite3.Row or dict-like objects with keys:
    tool_name, arguments_json, called_at, duration_ms, is_error, sequence_num
    — i.e. exactly what core.telemetry.get_session_calls() returns.
    """
    if not rows:
        raise ValueError(f"No tool_calls rows given for session {session_id}")

    tool_sequence = [r["tool_name"] for r in rows]
    call_count = len(tool_sequence)
    unique_tools_used = len(set(tool_sequence))

    bigrams: Counter = Counter(zip(tool_sequence, tool_sequence[1:]))

    error_count = sum(1 for r in rows if r["is_error"])
    error_rate = error_count / call_count

    timestamps = [r["called_at"] for r in rows]
    session_duration_sec = max(timestamps) - min(timestamps) if call_count > 1 else 0.0
    gaps = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    avg_gap = sum(gaps) / len(gaps) if gaps else 0.0
    max_gap = max(gaps) if gaps else 0.0

    privilege_levels = [privilege_of(name) for name in tool_sequence]
    max_privilege = max(privilege_levels)
    start_privilege = privilege_levels[0]
    end_privilege = privilege_levels[-1]

    # Escalation distance = the largest positive jump between ANY two calls in
    # the session (not just consecutive ones) — a session that reads a file
    # early, does other work, then executes a shell command late should still
    # register the full jump, not just the last step's delta.
    escalation_distance = max(
        (privilege_levels[j] - privilege_levels[i])
        for i in range(call_count)
        for j in range(i + 1, call_count)
    ) if call_count > 1 else 0
    escalation_distance = max(escalation_distance, 0)

    entropies = [
        _shannon_entropy(_extract_argument_values_text(r["arguments_json"])) for r in rows
    ]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    max_entropy = max(entropies) if entropies else 0.0

    return SessionFeatures(
        session_id=session_id,
        call_count=call_count,
        unique_tools_used=unique_tools_used,
        tool_sequence=tool_sequence,
        bigrams=bigrams,
        error_count=error_count,
        error_rate=error_rate,
        session_duration_sec=session_duration_sec,
        avg_inter_call_gap_sec=avg_gap,
        max_inter_call_gap_sec=max_gap,
        max_privilege_level=max_privilege,
        start_privilege_level=start_privilege,
        end_privilege_level=end_privilege,
        privilege_escalation_distance=escalation_distance,
        avg_argument_entropy=avg_entropy,
        max_argument_entropy=max_entropy,
    )
