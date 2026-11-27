from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("flask")

from api.app import create_app
from core.demo_mode import DEMO_SCENARIOS, DemoModeService, generate_scenario_events
from core.telemetry import TelemetryStore, init_db


@pytest.fixture()
def demo_environment(tmp_path):
    telemetry_db = tmp_path / "live-telemetry.sqlite3"
    auth_db = tmp_path / "users.sqlite3"
    demo_db = tmp_path / "demo-telemetry.sqlite3"
    init_db(telemetry_db)
    live_store = TelemetryStore("live-agent", db_path=telemetry_db)
    live_store.log_call("read_file", {"path": "normal.txt"}, 4.0, False, "Live record")
    live_store.end_session()
    app = create_app(
        {
            "TESTING": True,
            "AUTH_REQUIRED": True,
            "API_KEY": None,
            "SECRET_KEY": "test-demo-session-signing-secret-32-chars",
            "DATABASE": str(telemetry_db),
            "AUTH_DATABASE": str(auth_db),
            "DEMO_ENABLED": True,
            "DEMO_DATABASE": str(demo_db),
            "DEMO_MODEL_DIR": str(tmp_path / "ephemeral-model-location"),
            "MODEL_DIR": str(tmp_path / "existing-models"),
            "CORS_ORIGINS": {"http://127.0.0.1:5173"},
        }
    )
    return app.test_client(), telemetry_db, auth_db, demo_db


def _signup_and_get_csrf(client):
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    response = client.post(
        "/api/auth/signup",
        json={
            "name": "Demo Operator",
            "email": "demo-operator@example.com",
            "password": "SecureDemoPassphrase!42",
        },
        headers={"X-CSRF-Token": status.json["csrf_token"]},
    )
    assert response.status_code == 201
    return response.json["csrf_token"]


def _counts(database):
    with sqlite3.connect(database) as connection:
        return {
            "sessions": connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "calls": connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0],
        }


def test_scenario_generation_is_deterministic_and_returns_fresh_arguments():
    scenario_id = DEMO_SCENARIOS[0]["id"]
    first = generate_scenario_events(scenario_id)
    expected = generate_scenario_events(scenario_id)
    assert first == expected

    first[0]["arguments"]["path"] = "mutated"
    assert generate_scenario_events(scenario_id) == expected
    with pytest.raises(ValueError, match="Unknown demo scenario"):
        generate_scenario_events("unknown-scenario")


def test_demo_load_uses_real_assessment_pipeline_and_is_repeatable(demo_environment):
    client, telemetry_db, auth_db, demo_db = demo_environment
    assert client.get("/api/demo").status_code == 401
    csrf_token = _signup_and_get_csrf(client)
    assert client.post("/api/demo/load", json={}).status_code == 403

    live_counts = _counts(telemetry_db)
    first = client.post(
        "/api/demo/load",
        json={},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert first.status_code == 201
    first_data = first.json
    assert first_data["enabled"] is True
    assert first_data["classification"] == "SIMULATED"
    assert len(first_data["active_run"]["scenarios"]) == 4
    assert first_data["metrics"]["sessions_total"] == 4
    assert first_data["metrics"]["tool_calls_total"] == sum(
        len(item["calls"]) for item in first_data["active_run"]["scenarios"]
    )
    assert first_data["metrics"]["agents_total"] == 4

    by_id = {item["scenario_id"]: item for item in first_data["active_run"]["scenarios"]}
    assert set(by_id) == {scenario["id"] for scenario in DEMO_SCENARIOS}
    for session in by_id.values():
        assessment = session["assessment"]
        assert session["classification"] == "SIMULATED"
        assert assessment["availability"]["ml_assessment"] is True
        assert assessment["final_risk_score"] is not None
        assert assessment["ml_risk_score"] is not None
        assert all(
            "SIMULATED" in call["result_summary"]
            for call in session["calls"]
        )

    normal_review = by_id["scenario-a-normal-code-review"]
    normal_research = by_id["scenario-b-research-assistant"]
    assert normal_review["agent_id"] == "demo-code-reviewer"
    assert normal_review["assessment"]["policy_violations"] == []
    assert normal_review["assessment"]["attack_chains"] == []
    assert normal_review["assessment"]["risk_level"] == "LOW"
    assert normal_review["assessment"]["final_risk_score"] < 25
    assert normal_research["agent_id"] == "demo-research-assistant"
    assert normal_research["assessment"]["policy_violations"] == []
    assert normal_research["assessment"]["attack_chains"] == []
    assert normal_research["assessment"]["risk_level"] == "LOW"
    assert normal_research["assessment"]["final_risk_score"] < 25

    suspicious = by_id["scenario-c-suspicious-file-access"]["assessment"]
    assert suspicious["risk_level"] == "CRITICAL"
    assert suspicious["policy_violations"] or suspicious["attack_chains"]

    attack_chain = by_id["scenario-d-suspicious-outbound-attack-chain"]["assessment"]
    assert attack_chain["risk_level"] == "CRITICAL"
    assert {
        chain["chain_id"] for chain in attack_chain["attack_chains"]
    } >= {"sensitive_read_to_network", "read_to_execute"}

    assert first_data["metrics"]["alerts_total"] == len(first_data["alerts"])
    assert first_data["metrics"]["alerts_total"] >= 2
    assert _counts(telemetry_db) == live_counts
    assert not Path(client.application.config["DEMO_MODEL_DIR"]).exists()

    first_run_id = first_data["active_run"]["run_id"]
    second = client.post(
        "/api/demo/load",
        json={},
        headers={"X-CSRF-Token": first.json.get("csrf_token", csrf_token)},
    )
    assert second.status_code == 201
    assert second.json["active_run"]["run_id"] != first_run_id
    assert _counts(demo_db) == {
        "sessions": 4,
        "calls": sum(len(item["calls"]) for item in second.json["active_run"]["scenarios"]),
    }
    first_scores = {
        item["scenario_id"]: (
            item["assessment"]["ml_risk_score"],
            item["assessment"]["final_risk_score"],
            item["assessment"]["risk_level"],
        )
        for item in first_data["active_run"]["scenarios"]
    }
    second_scores = {
        item["scenario_id"]: (
            item["assessment"]["ml_risk_score"],
            item["assessment"]["final_risk_score"],
            item["assessment"]["risk_level"],
        )
        for item in second.json["active_run"]["scenarios"]
    }
    assert second_scores == first_scores
    assert _counts(telemetry_db) == live_counts
    with sqlite3.connect(auth_db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_demo_reset_is_scoped_to_run_and_preserves_accounts_and_live_telemetry(
    demo_environment,
):
    client, telemetry_db, auth_db, demo_db = demo_environment
    csrf_token = _signup_and_get_csrf(client)
    live_counts = _counts(telemetry_db)
    loaded = client.post(
        "/api/demo/load",
        json={"scenario_id": "scenario-d-suspicious-outbound-attack-chain"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert loaded.status_code == 201
    run = loaded.json["active_run"]
    assert len(run["scenarios"]) == 1
    session = run["scenarios"][0]

    reviewed = client.post(
        f"/api/demo/runs/{run['run_id']}/sessions/{session['session']['session_id']}/review",
        json={
            "decision": "rejected",
            "reviewer": "Demo Investigator",
            "note": "Reviewed simulated evidence.",
            "confirm_reviewed": True,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reviewed.status_code == 201
    assert reviewed.json["decision"] == "rejected"

    wrong_run = client.post(
        "/api/demo/reset",
        json={"run_id": "0" * 32},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert wrong_run.status_code == 404
    assert _counts(demo_db)["sessions"] == 1

    reset = client.post(
        "/api/demo/reset",
        json={"run_id": run["run_id"]},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reset.status_code == 200
    assert reset.json["active_run"] is None
    assert reset.json["metrics"]["sessions_total"] == 0
    assert _counts(demo_db) == {"sessions": 0, "calls": 0}
    assert _counts(telemetry_db) == live_counts
    with sqlite3.connect(auth_db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_demo_api_is_local_only_and_individual_scenario_load_is_supported(
    demo_environment,
):
    client, _telemetry_db, _auth_db, demo_db = demo_environment
    csrf_token = _signup_and_get_csrf(client)
    nonlocal_response = client.get(
        "/api/demo",
        environ_base={"REMOTE_ADDR": "192.0.2.20"},
    )
    assert nonlocal_response.status_code == 403

    loaded = client.post(
        "/api/demo/load",
        json={"scenario_id": "scenario-b-research-assistant"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert loaded.status_code == 201
    assert [item["agent_id"] for item in loaded.json["active_run"]["scenarios"]] == [
        "demo-research-assistant"
    ]
    assert _counts(demo_db)["sessions"] == 1


def test_demo_endpoints_report_disabled_without_creating_demo_store(tmp_path):
    database = tmp_path / "not-created.sqlite3"
    app = create_app(
        {
            "TESTING": True,
            "AUTH_REQUIRED": True,
            "API_KEY": None,
            "SECRET_KEY": "test-demo-session-signing-secret-32-chars",
            "AUTH_DATABASE": str(tmp_path / "users.sqlite3"),
            "DEMO_ENABLED": False,
            "DEMO_DATABASE": str(database),
        }
    )
    client = app.test_client()
    csrf_token = _signup_and_get_csrf(client)
    status = client.get("/api/demo")
    assert status.status_code == 200
    assert status.json["enabled"] is False
    assert status.json["active_run"] is None
    disabled_load = client.post(
        "/api/demo/load",
        json={},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert disabled_load.status_code == 404
    assert not database.exists()


def test_unrecognized_existing_demo_database_is_preserved(tmp_path):
    database = tmp_path / "existing-local-data.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE local_notes (value TEXT NOT NULL)")
        connection.execute("INSERT INTO local_notes (value) VALUES ('keep')")

    service = DemoModeService(database)
    with pytest.raises(RuntimeError, match="unrecognized existing demo database"):
        service.load()

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert tables == {"local_notes"}
        assert connection.execute("SELECT value FROM local_notes").fetchone()[0] == "keep"


def test_demo_api_refuses_to_alias_live_telemetry_database(tmp_path):
    database = tmp_path / "live.sqlite3"
    init_db(database)
    store = TelemetryStore("live-agent", db_path=database)
    store.log_call("read_file", {"path": "keep.txt"}, 3.0, False, "Keep live data")
    app = create_app(
        {
            "TESTING": True,
            "AUTH_REQUIRED": False,
            "DATABASE": str(database),
            "AUTH_DATABASE": str(tmp_path / "users.sqlite3"),
            "DEMO_ENABLED": True,
            "DEMO_DATABASE": str(database),
            "DEMO_MODEL_DIR": str(tmp_path / "models"),
            "SECRET_KEY": "test-demo-session-signing-secret-32-chars",
        }
    )
    client = app.test_client()

    assert client.get("/api/demo").status_code == 500
    assert client.post("/api/demo/load", json={}).status_code == 500
    assert _counts(database) == {"sessions": 1, "calls": 1}
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "demo_runs" not in tables
