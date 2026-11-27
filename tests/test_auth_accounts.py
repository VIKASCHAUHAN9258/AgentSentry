"""Tests for local AgentSentry user accounts and cookie sessions."""
from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("flask")

from api.app import create_app
from core.telemetry import init_db
from werkzeug.security import check_password_hash


@pytest.fixture()
def auth_client(tmp_path):
    telemetry_db = tmp_path / "telemetry.db"
    init_db(telemetry_db)
    app = create_app(
        {
            "TESTING": True,
            "AUTH_REQUIRED": True,
            "API_KEY": None,
            "DATABASE": str(telemetry_db),
            "AUTH_DATABASE": str(tmp_path / "users.sqlite3"),
            "SECRET_KEY": "test-session-signing-secret-at-least-32-chars",
            "CORS_ORIGINS": {"http://127.0.0.1:5173"},
        }
    )
    return app.test_client(), tmp_path / "users.sqlite3", app


def csrf_headers(client):
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    token = status.json["csrf_token"]
    return {"X-CSRF-Token": token}


def test_signup_creates_hashed_user_and_authenticated_session(auth_client):
    client, auth_db, _app = auth_client
    headers = csrf_headers(client)

    denied = client.get("/api/agents")
    assert denied.status_code == 401

    response = client.post(
        "/api/auth/signup",
        json={"name": "Demo Analyst", "email": "analyst@example.com", "password": "StrongPassphrase!42"},
        headers=headers,
    )
    assert response.status_code == 201
    assert response.json["authenticated"] is True
    assert response.json["user"]["email"] == "analyst@example.com"
    assert "password" not in response.json
    assert client.get("/api/agents").status_code == 200

    with sqlite3.connect(auth_db) as connection:
        row = connection.execute(
            "SELECT password_hash FROM users WHERE email = ?", ("analyst@example.com",)
        ).fetchone()
    assert row is not None
    assert row[0] != "StrongPassphrase!42"
    assert check_password_hash(row[0], "StrongPassphrase!42") is True


def test_signup_validates_input_and_prevents_duplicate_email(auth_client):
    client, _auth_db, _app = auth_client
    headers = csrf_headers(client)
    weak = client.post(
        "/api/auth/signup",
        json={"name": "A", "email": "a@example.com", "password": "short"},
        headers=headers,
    )
    assert weak.status_code == 400

    body = {"name": "Analyst", "email": "analyst@example.com", "password": "StrongPassphrase!42"}
    first = client.post("/api/auth/signup", json=body, headers=headers)
    assert first.status_code == 201
    headers = csrf_headers(client)
    duplicate = client.post("/api/auth/signup", json=body, headers=headers)
    assert duplicate.status_code == 409


def test_login_logout_and_restart_keep_user_account(auth_client):
    client, auth_db, app = auth_client
    headers = csrf_headers(client)
    payload = {"name": "Analyst", "email": "analyst@example.com", "password": "StrongPassphrase!42"}
    created = client.post("/api/auth/signup", json=payload, headers=headers)
    assert created.status_code == 201

    status = client.get("/api/auth/status")
    assert status.json["authenticated"] is True
    assert status.json["user"]["name"] == "Analyst"

    logout = client.post(
        "/api/auth/logout",
        json={},
        headers={"X-CSRF-Token": status.json["csrf_token"]},
    )
    assert logout.status_code == 200
    assert client.get("/api/auth/status").json["authenticated"] is False
    assert client.get("/api/agents").status_code == 401

    fresh_app = create_app(
        {
            "TESTING": True,
            "AUTH_REQUIRED": True,
            "API_KEY": None,
            "DATABASE": str(app.config["DATABASE"]),
            "AUTH_DATABASE": str(auth_db),
            "SECRET_KEY": app.config["SECRET_KEY"],
            "CORS_ORIGINS": app.config["CORS_ORIGINS"],
        }
    )
    fresh_client = fresh_app.test_client()
    login_headers = csrf_headers(fresh_client)
    bad = fresh_client.post(
        "/api/auth/login",
        json={"email": "analyst@example.com", "password": "incorrect-password"},
        headers=login_headers,
    )
    assert bad.status_code == 401
    good = fresh_client.post(
        "/api/auth/login",
        json={"email": "ANALYST@example.com", "password": "StrongPassphrase!42"},
        headers=login_headers,
    )
    assert good.status_code == 200
    assert fresh_client.get("/api/agents").status_code == 200


def test_cookie_authenticated_mutations_require_csrf(auth_client):
    client, _auth_db, _app = auth_client
    no_csrf = client.post(
        "/api/auth/signup",
        json={"name": "Analyst", "email": "analyst@example.com", "password": "StrongPassphrase!42"},
    )
    assert no_csrf.status_code == 403
    headers = csrf_headers(client)
    created = client.post(
        "/api/auth/signup",
        json={"name": "Analyst", "email": "analyst@example.com", "password": "StrongPassphrase!42"},
        headers=headers,
    )
    assert created.status_code == 201
    rejected = client.post("/api/auth/logout", json={})
    assert rejected.status_code == 403


def test_signed_browser_session_survives_app_restart(auth_client):
    client, auth_db, app = auth_client
    headers = csrf_headers(client)
    created = client.post(
        "/api/auth/signup",
        json={"name": "Analyst", "email": "persistent@example.com", "password": "StrongPassphrase!42"},
        headers=headers,
    )
    assert created.status_code == 201
    cookie = client.get_cookie("agentsentry_session")
    assert cookie is not None

    restarted_app = create_app(
        {
            "TESTING": True,
            "AUTH_REQUIRED": True,
            "API_KEY": None,
            "DATABASE": str(app.config["DATABASE"]),
            "AUTH_DATABASE": str(auth_db),
            "SECRET_KEY": app.config["SECRET_KEY"],
            "CORS_ORIGINS": app.config["CORS_ORIGINS"],
        }
    )
    restarted_client = restarted_app.test_client()
    restarted_client.set_cookie("agentsentry_session", cookie.value)
    assert restarted_client.get("/api/auth/status").json["authenticated"] is True
    assert restarted_client.get("/api/agents").status_code == 200
