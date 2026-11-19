"""
Phase 9 audit (Member 3) — can a hostile tool call blow up storage or crash feature extraction?
"""

import json

from core.features import extract_session_features
from core.telemetry import TelemetryStore, get_session_calls


def _store(tmp_path):
    db = tmp_path / "audit.db"
    return TelemetryStore(agent_id="audit-agent", db_path=db), db


def test_huge_arguments_and_result_are_truncated(tmp_path):
    store, db = _store(tmp_path)
    store.log_call("read_file", {"data": "A" * 1_000_000}, 1.0, False, "R" * 1_000_000)
    row = get_session_calls(store.session_id, db_path=db)[0]
    assert len(row["arguments_json"]) <= 4000
    assert json.loads(row["arguments_json"]) == {"_truncated": True}
    assert len(row["result_summary"]) <= 2000


def test_truncated_arguments_do_not_crash_feature_extraction(tmp_path):
    """Truncation can cut JSON in half (invalid JSON). Feature extraction must survive it."""
    store, db = _store(tmp_path)
    store.log_call("read_file", {"data": "A" * 100_000}, 1.0, False, "ok")
    store.log_call("report", {"summary": "done"}, 1.0, False, "ok")
    rows = get_session_calls(store.session_id, db_path=db)
    features = extract_session_features(store.session_id, rows)
    assert features.call_count == 2


def test_non_json_serializable_arguments_do_not_crash_logging(tmp_path):
    store, db = _store(tmp_path)
    store.log_call("read_file", {"obj": object(), "s": {1, 2, 3}}, 1.0, False, "ok")
    assert len(get_session_calls(store.session_id, db_path=db)) == 1
