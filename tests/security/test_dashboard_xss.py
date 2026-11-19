"""Security checks for untrusted telemetry returned by the JSON API."""
import pytest

pytest.importorskip("flask")

from api.app import create_app
from core.telemetry import TelemetryStore, init_db


@pytest.fixture()
def client(tmp_path):
    database = tmp_path / "security.db"
    init_db(database)
    store = TelemetryStore(agent_id="security-test-agent", db_path=database)
    store.log_call(
        "read_file",
        {"query": '<script>alert(1)</script>', "image": '"><img src=x onerror=alert(1)>'},
        1.0,
        False,
        "untrusted output",
    )
    app = create_app(
        {"TESTING": True, "DATABASE": str(database), "MODEL_DIR": str(tmp_path / "models")}
    )
    return app.test_client(), store


def test_untrusted_telemetry_is_returned_as_json_with_security_headers(client):
    http, store = client
    response = http.get(f"/api/sessions/{store.session_id}")

    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.get_data(as_text=True).lstrip().startswith("{")
    assert response.json["calls"][0]["arguments"]["query"] == "<script>alert(1)</script>"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers


def test_malformed_input_does_not_disclose_internal_details(client):
    http, _store = client
    for path in ("/api/sessions/not*valid", "/api/sessions?limit=9999"):
        response = http.get(path)
        assert response.status_code == 400
        assert "Traceback" not in response.get_data(as_text=True)
        assert "D:\\AGENT_SENTRY" not in response.get_data(as_text=True)


def test_api_debug_is_disabled_by_default(tmp_path):
    app = create_app(
        {
            "DATABASE": str(tmp_path / "unused.db"),
            "API_KEY": "test-key-for-xss-debug-check-0000000000",
        }
    )
    assert app.debug is False
    assert app.config["DEBUG"] is False
