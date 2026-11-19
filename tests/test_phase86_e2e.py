"""End-to-end API validation using real Phase 6 scenarios and the MCP proxy."""
from __future__ import annotations

import asyncio
import math
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("flask")

from api.app import create_app
from lab.scenario_loader import load_scenarios
from scripts.run_scenario import _execute


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT_ROOT / "models"
SCENARIO_PREFIXES = ("A1-", "A2-", "A3-", "A4-", "B1-")


def _is_optional_finite_number(value: object) -> bool:
    return value is None or (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def test_phase86_scenarios_are_visible_through_read_only_api(tmp_path: Path):
    database = tmp_path / "phase86-e2e.db"
    all_scenarios = load_scenarios()
    scenarios_by_prefix = {
        prefix: next(
            (scenario for scenario in all_scenarios if scenario["id"].startswith(prefix)),
            None,
        )
        for prefix in SCENARIO_PREFIXES
    }
    missing_prefixes = [
        prefix for prefix, scenario in scenarios_by_prefix.items() if scenario is None
    ]
    assert not missing_prefixes, (
        f"Expected scenario definitions for {', '.join(missing_prefixes)}; "
        f"loaded {len(all_scenarios)} scenarios."
    )
    scenarios = [scenarios_by_prefix[prefix] for prefix in SCENARIO_PREFIXES]

    session_ids: dict[str, str] = {}
    for scenario in scenarios:
        assert scenario is not None
        session_id, _timeline = asyncio.run(_execute(scenario, database))
        session_ids[scenario["id"]] = session_id

    assert len(set(session_ids.values())) == len(scenarios), (
        "Each real proxy scenario should persist a distinct session in the shared test database."
    )
    assert database.is_file(), "The real proxy should initialize its isolated test database."

    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "MODEL_DIR": str(MODEL_DIR),
        }
    )
    client = app.test_client()

    health = client.get("/api/health")
    assert health.status_code == 200, f"Health endpoint returned {health.status_code}: {health.json}"
    assert health.json["database"] == "connected", "API should see the initialized test database."

    agents_response = client.get("/api/agents")
    assert agents_response.status_code == 200, (
        f"Agent endpoint returned {agents_response.status_code}: {agents_response.json}"
    )
    actual_agents = {item["agent_id"] for item in agents_response.json}
    expected_agents = {scenario["agent_id"] for scenario in scenarios if scenario is not None}
    assert expected_agents <= actual_agents, (
        f"Expected scenario agents {sorted(expected_agents)} in API response; "
        f"received {sorted(actual_agents)}."
    )

    sessions_response = client.get("/api/sessions?limit=200")
    assert sessions_response.status_code == 200, (
        f"Sessions endpoint returned {sessions_response.status_code}: {sessions_response.json}"
    )
    sessions_by_id = {item["session_id"]: item for item in sessions_response.json}
    assert set(session_ids.values()) <= set(sessions_by_id), (
        "The sessions API omitted one or more sessions persisted by the five proxy scenarios."
    )

    overview_response = client.get("/api/dashboard/overview")
    assert overview_response.status_code == 200, (
        f"Overview endpoint returned {overview_response.status_code}: {overview_response.json}"
    )
    overview = overview_response.json
    assert overview["sessions_total"] == len(scenarios), (
        f"Overview should report {len(scenarios)} scenario sessions, got "
        f"{overview['sessions_total']}."
    )
    assert overview["tool_calls_total"] > 0, "Scenario execution should persist tool-call telemetry."

    distribution_response = client.get("/api/dashboard/risk-distribution")
    assert distribution_response.status_code == 200, (
        f"Risk distribution returned {distribution_response.status_code}: "
        f"{distribution_response.json}"
    )
    assert distribution_response.json["total_sessions"] == len(scenarios), (
        "Risk distribution should include all five scenario sessions."
    )

    details_by_scenario: dict[str, dict] = {}
    assessments_by_scenario: dict[str, dict] = {}
    for scenario in scenarios:
        assert scenario is not None
        scenario_id = scenario["id"]
        session_id = session_ids[scenario_id]
        detail_response = client.get(f"/api/sessions/{session_id}")
        assert detail_response.status_code == 200, (
            f"{scenario_id} detail request failed with {detail_response.status_code}: "
            f"{detail_response.json}"
        )
        detail = detail_response.json
        assert detail["session"]["session_id"] == session_id, (
            f"{scenario_id} detail returned a different session ID."
        )
        expected_tool_names = [step["tool"] for step in scenario["steps"]]
        actual_tool_names = [call["tool_name"] for call in detail["calls"]]
        assert actual_tool_names == expected_tool_names, (
            f"{scenario_id} API calls did not match scenario steps: "
            f"expected {expected_tool_names}, received {actual_tool_names}."
        )
        details_by_scenario[scenario_id] = detail

        assessment_response = client.get(f"/api/sessions/{session_id}/assessment")
        assert assessment_response.status_code == 200, (
            f"{scenario_id} assessment request failed with "
            f"{assessment_response.status_code}: {assessment_response.json}"
        )
        assessment = assessment_response.json
        assert assessment["session_id"] == session_id, (
            f"{scenario_id} assessment returned a different session ID."
        )
        assert isinstance(assessment["assessment_status"], str), (
            f"{scenario_id} assessment status should be a string."
        )
        assert isinstance(assessment["availability"]["ml_assessment"], bool), (
            f"{scenario_id} should explicitly report ML assessment availability."
        )
        assert _is_optional_finite_number(assessment["final_risk_score"]), (
            f"{scenario_id} final risk score must be null or a finite number; "
            "unavailable ML scores must not be replaced with a fabricated value."
        )
        assert _is_optional_finite_number(assessment["ml_risk_score"]), (
            f"{scenario_id} ML risk score must be null or a finite number."
        )
        assessments_by_scenario[scenario_id] = assessment

    a4 = next(scenario for scenario in scenarios if scenario and scenario["id"].startswith("A4-"))
    b1 = next(scenario for scenario in scenarios if scenario and scenario["id"].startswith("B1-"))
    assert a4 is not None and b1 is not None
    a4_id = session_ids[a4["id"]]
    b1_id = session_ids[b1["id"]]

    with sqlite3.connect(database) as connection:
        a4_events = connection.execute(
            """SELECT event_type FROM tool_definition_events
               WHERE session_id = ? ORDER BY sequence_num, id""",
            (a4_id,),
        ).fetchall()
        b1_events = connection.execute(
            "SELECT event_type FROM tool_definition_events WHERE session_id = ?",
            (b1_id,),
        ).fetchall()

    assert any(event_type == "tool_definition_changed" for (event_type,) in a4_events), (
        "A4 must persist a genuine tool_definition_changed event in SQLite."
    )
    assert details_by_scenario[a4["id"]]["tool_definition_events"], (
        "A4 session detail should expose the tool-definition change recorded by the proxy."
    )
    assert all(
        event["event_type"] == "tool_definition_changed"
        for event in details_by_scenario[a4["id"]]["tool_definition_events"]
    ), "A4 session detail should identify returned tool-definition events accurately."
    assert not b1_events, "B1 should not persist any tool-definition-change events."
    assert not details_by_scenario[b1["id"]]["tool_definition_events"], (
        "B1 session detail should not report tool-definition-change events."
    )

    chain_response = client.get("/api/dashboard/attack-chains")
    assert chain_response.status_code == 200, (
        f"Attack-chain endpoint returned {chain_response.status_code}: {chain_response.json}"
    )
    chain_pairs = {
        (finding["session_id"], finding["chain_id"])
        for finding in chain_response.json
    }
    for scenario in scenarios:
        assert scenario is not None
        expected_chain = scenario["expected"].get("expect_chain")
        if expected_chain is None:
            continue
        assessment_chains = assessments_by_scenario[scenario["id"]]["attack_chains"]
        supported_chains = {chain["chain_id"] for chain in assessment_chains}
        if expected_chain in supported_chains:
            assert (session_ids[scenario["id"]], expected_chain) in chain_pairs, (
                f"Global attack-chain results omitted {expected_chain!r} for "
                f"{scenario['id']}, although its assessment supports that chain."
            )
