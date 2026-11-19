from __future__ import annotations

import random
import sqlite3
from pathlib import Path

import pytest

from api.app import create_app
from core.detector import BehaviorAnomalyDetector
from core.features import extract_session_features
from core.telemetry import TelemetryStore, get_session_calls


def _persist_session(
    database: Path,
    agent_id: str,
    seed: int,
    calls: list[tuple[str, dict[str, str]]] | None = None,
) -> str:
    rng = random.Random(seed)
    if calls is None:
        calls = [
            ("read_file", {"path": "notes.txt"}),
            ("search_code", {"query": f"TODO-{seed}"}),
            ("report", {"summary": f"Reviewed-{seed}"}),
        ]

    store = TelemetryStore(agent_id, db_path=database)
    for tool_name, arguments in calls:
        store.log_call(tool_name, arguments, 5.0, False, "Observed result")

    timestamp = float(seed * 100)
    with sqlite3.connect(database) as connection:
        for sequence_num in range(1, len(calls) + 1):
            timestamp += rng.uniform(0.5, 3.0)
            connection.execute(
                """UPDATE tool_calls SET called_at = ?
                   WHERE session_id = ? AND sequence_num = ?""",
                (timestamp, store.session_id, sequence_num),
            )
    store.end_session()
    return store.session_id


@pytest.mark.parametrize("agent_id", ["gemini-agent", "generic-python-client"])
def test_untrained_real_sessions_are_unassessed_not_fabricated_as_low(
    tmp_path: Path, agent_id: str
) -> None:
    database = tmp_path / f"{agent_id}.db"
    session_id = _persist_session(database, agent_id, seed=41)
    client = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "MODEL_DIR": str(tmp_path / "models"),
        }
    ).test_client()

    response = client.get(f"/api/sessions/{session_id}/assessment")

    assert response.status_code == 200
    assessment = response.json
    assert assessment["agent_id"] == agent_id
    assert assessment["risk_level"] == "UNASSESSED"
    assert assessment["final_risk_score"] is None
    assert assessment["ml_risk_score"] is None
    assert assessment["availability"]["ml_assessment"] is False
    assert "No trained behavior model" in assessment["availability"]["reason"]
    assert assessment["policy_violations"] == []
    assert assessment["attack_chains"] == []
    assert assessment["contributing_signals"] == []
    assert assessment["evidence"] == []


def test_persisted_gemini_assessment_reports_baseline_and_attack_evidence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "gemini-risk.db"
    model_dir = tmp_path / "models"
    training_vectors = []
    for seed in range(30):
        baseline_id = _persist_session(database, "gemini-agent", seed)
        training_vectors.append(
            extract_session_features(
                baseline_id, get_session_calls(baseline_id, db_path=database)
            ).to_vector()
        )

    detector = BehaviorAnomalyDetector("gemini-agent", model_dir=model_dir)
    detector.fit(training_vectors)
    detector.save()

    benign_id = _persist_session(database, "gemini-agent", seed=101)
    attack_id = _persist_session(
        database,
        "gemini-agent",
        seed=102,
        calls=[
            ("read_file", {"path": "notes.txt"}),
            ("shell_execute", {"command": "id"}),
        ],
    )
    client = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "MODEL_DIR": str(model_dir),
        }
    ).test_client()

    benign = client.get(f"/api/sessions/{benign_id}/assessment").json
    assert benign["assessment_status"] == "complete"
    assert benign["availability"]["ml_assessment"] is True
    assert benign["risk_level"] == "LOW"
    assert benign["final_risk_score"] < 25
    assert benign["feature_contributions"]
    assert benign["policy_violations"] == []
    assert benign["attack_chains"] == []

    attack = client.get(f"/api/sessions/{attack_id}/assessment").json
    assert attack["risk_level"] == "CRITICAL"
    assert attack["final_risk_score"] >= 95
    assert attack["policy_violations"]
    assert any(chain["chain_id"] == "read_to_execute" for chain in attack["attack_chains"])
    assert {
        "policy_violation",
        "attack_chain",
    }.issubset({signal["type"] for signal in attack["contributing_signals"]})
    assert "baseline_deviation" in {
        signal["type"] for signal in attack["contributing_signals"]
    }
    assert {item["tool_name"] for item in attack["evidence"]} == {
        "read_file",
        "shell_execute",
    }
    assert all("arguments" not in item for item in attack["evidence"])
