"""Focused tests for the read-only Phase 7 telemetry API."""
from __future__ import annotations

import json
import sqlite3

import pytest

pytest.importorskip("flask")

from api.app import create_app
from core.telemetry import TelemetryStore, init_db


@pytest.fixture()
def client(tmp_path):
    database = tmp_path / "test.db"
    init_db(database)
    store = TelemetryStore("research-assistant", db_path=database)
    store.log_call(
        "read_document",
        {"doc_id": "q3-report"},
        4.2,
        False,
        "Document read",
    )
    store.log_tool_definition_change(
        "read_document",
        {"name": "read_document", "inputSchema": {"type": "object"}},
        {
            "name": "read_document",
            "inputSchema": {
                "type": "object",
                "required": ["include_secrets"],
            },
        },
        1.5,
    )
    store.log_call(
        "read_document",
        {"doc_id": "q3-report", "include_secrets": True},
        5.1,
        False,
        "Document read after schema change",
    )
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "MODEL_DIR": str(tmp_path / "models"),
        }
    )
    return app.test_client(), database, store


@pytest.fixture()
def empty_client(tmp_path):
    database = tmp_path / "empty.db"
    init_db(database)
    app = create_app({"TESTING": True, "DATABASE": str(database)})
    return app.test_client()


def test_health_and_security_headers(client):
    response = client[0].get("/api/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok", "database": "connected"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Cache-Control"] == "no-store"


def test_agents_and_sessions_use_persisted_telemetry(client):
    http, _database, store = client
    agents = http.get("/api/agents")
    assert agents.status_code == 200
    assert agents.json[0]["agent_id"] == "research-assistant"
    assert agents.json[0]["session_count"] == 1
    assert agents.json[0]["tool_call_count"] == 2

    sessions = http.get("/api/sessions?agent_id=research-assistant&limit=1")
    assert sessions.status_code == 200
    assert sessions.json[0]["session_id"] == store.session_id
    assert sessions.json[0]["call_count"] == 2
    assert sessions.json[0]["risk_level"] == "HIGH"
    assert sessions.json[0]["risk_score"] is None


def test_session_detail_and_assessment_use_genuine_tool_change_event(client):
    http, _database, store = client
    detail = http.get(f"/api/sessions/{store.session_id}")
    assert detail.status_code == 200
    assert detail.json["calls"][0]["arguments"] == {"doc_id": "q3-report"}
    assert (
        detail.json["tool_definition_events"][0]["after_schema"]["required"]
        == ["include_secrets"]
    )

    assessment = http.get(f"/api/sessions/{store.session_id}/assessment")
    assert assessment.status_code == 200
    assert assessment.json["risk_level"] == "HIGH"
    assert assessment.json["assessment_status"] == "chain_only"
    assert assessment.json["final_risk_score"] is None
    assert assessment.json["availability"]["ml_assessment"] is False
    assert assessment.json["attack_chains"][0]["chain_id"] == "tool_definition_changed"


def test_dashboard_endpoints_reflect_persisted_data(client):
    http, _database, _store = client

    overview = http.get("/api/dashboard/overview")
    assert overview.status_code == 200
    assert overview.json["sessions_total"] == 1
    assert overview.json["tool_calls_total"] == 2
    assert overview.json["tool_definition_changes"] == 1

    activity = http.get("/api/dashboard/activity")
    assert activity.status_code == 200
    assert {item["event_type"] for item in activity.json} == {
        "tool_call",
        "tool_definition_changed",
    }

    distribution = http.get("/api/dashboard/risk-distribution")
    assert distribution.status_code == 200
    assert distribution.json["distribution"]["HIGH"] == 1
    assert distribution.json["total_sessions"] == 1

    chains = http.get("/api/dashboard/attack-chains")
    assert chains.status_code == 200
    assert chains.json[0]["chain_id"] == "tool_definition_changed"


def test_mcp_endpoints_report_actual_availability_and_changes(client):
    http, _database, store = client

    servers = http.get("/api/mcp/servers")
    assert servers.status_code == 200
    assert servers.json["available"] is False
    assert servers.json["status"] == "empty"
    assert servers.json["servers"] == []

    changes = http.get("/api/mcp/tool-changes")
    assert changes.status_code == 200
    assert len(changes.json) == 1
    assert changes.json[0]["session_id"] == store.session_id
    assert changes.json[0]["notification_method"] == "notifications/tools/list_changed"
    assert changes.json[0]["after_schema"]["required"] == ["include_secrets"]


def test_empty_initialized_database_returns_empty_metrics(empty_client):
    assert empty_client.get("/api/health").status_code == 200
    assert empty_client.get("/api/agents").json == []
    assert empty_client.get("/api/sessions").json == []
    assert empty_client.get("/api/dashboard/activity").json == []
    assert empty_client.get("/api/dashboard/overview").json["sessions_total"] == 0
    assert empty_client.get("/api/dashboard/overview").json["tool_calls_total"] == 0
    assert empty_client.get("/api/dashboard/risk-distribution").json == {
        "distribution": {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
            "UNASSESSED": 0,
        },
        "total_sessions": 0,
    }
    assert empty_client.get("/api/dashboard/attack-chains").json == []
    assert empty_client.get("/api/mcp/tool-changes").json == []


def test_missing_database_is_not_created_and_reports_unavailable(tmp_path):
    database = tmp_path / "missing.db"
    app = create_app({"TESTING": True, "DATABASE": str(database)})
    response = app.test_client().get("/api/health")
    assert response.status_code == 503
    assert response.json["database"] == "unavailable"
    assert not database.exists()


def test_invalid_session_and_limit_values_are_rejected(client):
    http, _database, _store = client
    assert http.get("/api/sessions/invalid%2Fsession").status_code in (400, 404)
    assert http.get("/api/sessions/not*valid").status_code == 400
    assert http.get("/api/sessions?limit=9999").status_code == 400
    assert http.get("/api/sessions?limit=not-a-number").status_code == 400
    assert http.get("/api/dashboard/activity?limit=0").status_code == 400


def test_oversized_review_request_returns_json_error(client):
    http, _database, store = client

    response = http.post(
        f"/api/sessions/{store.session_id}/review",
        data=b"x" * (1024 * 1024 + 1),
        content_type="application/json",
    )

    assert response.status_code == 413
    assert response.json == {"error": "Request body exceeds the 1 MiB limit"}


def test_api_authentication_protects_sensitive_routes_but_not_health(tmp_path):
    database = tmp_path / "auth.db"
    init_db(database)
    key = "test-api-key-for-authentication-000000000000"
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "API_KEY": key,
            "CORS_ORIGINS": {"http://127.0.0.1:5173"},
        }
    )
    http = app.test_client()

    assert http.get("/api/health").status_code == 200
    auth_status = http.get("/api/auth/status").json
    assert auth_status["required"] is True
    assert auth_status["authenticated"] is False
    assert auth_status["user"] is None
    assert len(auth_status["csrf_token"]) >= 32
    protected_paths = (
        "/api/agents",
        "/api/sessions",
        "/api/dashboard/overview",
        "/api/dashboard/activity",
        "/api/dashboard/risk-distribution",
        "/api/dashboard/attack-chains",
        "/api/mcp/servers",
        "/api/mcp/tool-changes",
    )
    for path in protected_paths:
        response = http.get(path)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer ")
    assert http.get(
        "/api/agents", headers={"Authorization": "Bearer invalid"}
    ).status_code == 401
    assert http.get(
        "/api/agents", headers={"Authorization": f"Bearer {key}"}
    ).status_code == 200
    assert http.get(
        "/api/auth/verify", headers={"Authorization": f"Bearer {key}"}
    ).json == {"authenticated": True}


def test_api_cors_preflight_is_limited_to_configured_origin(tmp_path):
    database = tmp_path / "cors.db"
    init_db(database)
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "API_KEY": "test-api-key-for-cors-0000000000000000",
            "CORS_ORIGINS": {"http://127.0.0.1:5173"},
        }
    )
    http = app.test_client()

    allowed = http.options(
        "/api/agents",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert allowed.status_code == 204
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:5173"
    assert "Authorization" in allowed.headers["Access-Control-Allow-Headers"]
    assert "X-CSRF-Token" in allowed.headers["Access-Control-Allow-Headers"]
    assert allowed.headers["Access-Control-Allow-Credentials"] == "true"

    denied = http.options(
        "/api/agents",
        headers={"Origin": "https://untrusted.example"},
    )
    assert denied.status_code == 403
    assert "Access-Control-Allow-Origin" not in denied.headers

    denied_request = http.get(
        "/api/agents",
        headers={
            "Origin": "https://untrusted.example",
            "Authorization": "Bearer test-api-key-for-cors-0000000000000000",
        },
    )
    assert denied_request.status_code == 403


def test_session_data_redacts_secret_fields_and_keeps_api_json_inert(client):
    http, database, store = client
    store.log_call(
        "read_document",
        {"api_key": "sensitive-value", "query": "<script>alert(1)</script>"},
        1.0,
        False,
        "token=secret-value",
    )
    detail = http.get(f"/api/sessions/{store.session_id}")
    assert detail.mimetype == "application/json"
    assert detail.json["calls"][2]["arguments"]["api_key"] == "[REDACTED]"
    assert detail.json["calls"][2]["arguments"]["query"] == "<script>alert(1)</script>"
    assert "sensitive-value" not in json.dumps(detail.json)
    assert "token=[REDACTED]" in detail.json["calls"][2]["result_summary"]

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0] == 3


def test_oversized_arguments_are_valid_and_safe_in_session_detail(client):
    http, _database, store = client
    store.log_call("read_document", {"payload": "x" * 100_000}, 1.0, False, "done")

    response = http.get(f"/api/sessions/{store.session_id}")

    assert response.status_code == 200
    assert response.json["calls"][-1]["arguments"] == {"_truncated": True}


def test_legacy_truncated_arguments_do_not_break_session_detail(client):
    http, database, store = client
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE tool_calls SET arguments_json = ? WHERE session_id = ? AND sequence_num = 1",
            ('{"payload":"truncated', store.session_id),
        )

    response = http.get(f"/api/sessions/{store.session_id}")

    assert response.status_code == 200
    assert response.json["calls"][0]["arguments"] == {"_invalid_json": True}


def test_plain_text_credential_and_private_key_values_are_redacted(client):
    http, _database, store = client
    store.log_call(
        "read_document",
        {},
        1.0,
        False,
        "credential=credential-value private_key=private-value",
    )

    detail = http.get(f"/api/sessions/{store.session_id}")
    activity = http.get("/api/dashboard/activity")

    assert detail.status_code == 200
    assert "credential=[REDACTED]" in detail.json["calls"][-1]["result_summary"]
    assert "private_key=[REDACTED]" in detail.json["calls"][-1]["result_summary"]
    activity_text = json.dumps(activity.json)
    assert "credential-value" not in activity_text
    assert "private-value" not in activity_text


def test_default_app_is_not_in_debug_mode(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "unused.db"),
            "API_KEY": "test-key-for-debug-configuration-0000000000",
        }
    )
    assert app.debug is False
    assert app.config["DEBUG"] is False


def test_non_test_app_creates_persistent_session_secret_without_browser_api_key(tmp_path):
    secret_file = tmp_path / "session.secret"
    config = {
        "DATABASE": str(tmp_path / "telemetry.db"),
        "AUTH_DATABASE": str(tmp_path / "users.sqlite3"),
        "SESSION_SECRET_FILE": str(secret_file),
    }
    first = create_app(config)
    second = create_app(config)
    assert first.config["SECRET_KEY"] == second.config["SECRET_KEY"]
    assert len(first.config["SECRET_KEY"]) >= 32
    assert secret_file.is_file()
    assert first.debug is False
    assert first.config["DEBUG"] is False

    with pytest.raises(RuntimeError, match="only be disabled"):
        create_app(
            {
                **config,
                "AUTH_REQUIRED": False,
            }
        )
