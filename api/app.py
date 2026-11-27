"""AgentSentry Flask API for read-only telemetry and local account sessions."""
from __future__ import annotations

import json
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterator

from flask import Flask, jsonify, request, session
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

from core.chain_detector import detect_chains
from core.demo_mode import DemoModeService, list_demo_scenarios
from core.telemetry import DB_PATH
from core.session_review import get_review_status, review_session

IMPLEMENTED = True

_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SECRET_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|credential|api[_-]?key|access[_-]?key|private[_-]?key|authorization)",
    re.IGNORECASE,
)
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b((?:password|passwd|secret|token|credential|private[_-]?key|api[_-]?key|access[_-]?key|authorization)"
    r"\s*[:=]\s*)['\"]?[^\s,;'\"]+"
)
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200
_REQUIRED_TABLES = {"sessions", "tool_calls", "tool_definition_events"}
_LOCAL_CORS_ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173"}
_LOCAL_CLIENT_ADDRESSES = {"127.0.0.1", "::1", "localhost"}


def _default_demo_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "AgentSentry" / "demo"
    return Path.home() / ".local" / "share" / "agentsentry" / "demo"


def _json_load(value: str | None) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {"_invalid_json": True}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SECRET_KEY_RE.search(str(key)) else _redact(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact(child) for child in value]
    if isinstance(value, str):
        return _SECRET_TEXT_RE.sub(r"\1[REDACTED]", value)
    return value


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def _chain_dict(chain: Any) -> dict[str, Any]:
    return {
        "chain_id": chain.chain_id,
        "severity": chain.severity,
        "call_indices": chain.call_indices,
        "description": chain.description,
        "mitre_hint": chain.mitre_hint,
    }


def _evidence_item(row: dict[str, Any], index: int, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "index": index,
        "sequence_num": row["sequence_num"],
        "tool_name": row["tool_name"],
        "called_at": row["called_at"],
    }


def _assessment_signals(
    violations: list[Any],
    chains: list[Any],
    call_rows: list[dict[str, Any]],
    timeline_rows: list[dict[str, Any]],
    policy: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    signals: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    def add_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in items:
            if item not in evidence:
                evidence.append(item)
        return items

    from core.privilege import privilege_of

    for violation in violations:
        if violation.rule == "denied_tool":
            matching_calls = [
                (index, row)
                for index, row in enumerate(call_rows)
                if row["tool_name"] in policy.denied_tools
                and f"'{row['tool_name']}'" in violation.detail
            ]
        else:
            matching_calls = [
                (index, row)
                for index, row in enumerate(call_rows)
                if privilege_of(row["tool_name"]) > policy.max_allowed_privilege
            ]
        signal_evidence = add_evidence(
            [
                _evidence_item(row, index, "tool_call")
                for index, row in matching_calls
            ]
        )
        signals.append(
            {
                "type": "policy_violation",
                "signal": violation.rule,
                "severity": violation.severity,
                "detail": violation.detail,
                "evidence": signal_evidence,
            }
        )

    for chain in chains:
        signal_evidence = add_evidence(
            [
                _evidence_item(
                    timeline_rows[index],
                    index,
                    "tool_definition_change"
                    if timeline_rows[index].get("event_type")
                    else "tool_call",
                )
                for index in chain.call_indices
                if 0 <= index < len(timeline_rows)
            ]
        )
        signals.append(
            {
                "type": "attack_chain",
                "signal": chain.chain_id,
                "severity": chain.severity,
                "detail": chain.description,
                "evidence": signal_evidence,
            }
        )
    return signals, evidence


def _feature_evidence(
    feature: str,
    call_rows: list[dict[str, Any]],
    features: Any,
) -> list[dict[str, Any]]:
    if not call_rows:
        return []

    from core.privilege import privilege_of

    if feature == "start_privilege_level":
        indices = [0]
    elif feature == "end_privilege_level":
        indices = [len(call_rows) - 1]
    elif feature == "max_privilege_level":
        indices = [
            index
            for index, row in enumerate(call_rows)
            if privilege_of(row["tool_name"]) == features.max_privilege_level
        ]
    elif feature == "privilege_escalation_distance":
        levels = [privilege_of(row["tool_name"]) for row in call_rows]
        low_index = min(range(len(levels)), key=levels.__getitem__)
        high_index = max(range(len(levels)), key=levels.__getitem__)
        indices = sorted({low_index, high_index})
    else:
        indices = list(range(min(len(call_rows), 20)))

    return [
        _evidence_item(call_rows[index], index, "tool_call")
        for index in indices[:20]
    ]


def _risk_for_rows(
    agent_id: str,
    session_id: str,
    call_rows: list[dict[str, Any]],
    timeline_rows: list[dict[str, Any]],
    model_dir: Path,
    model_cache: dict[str, tuple[dict[str, str], Any | None]] | None = None,
) -> dict[str, Any]:
    chains = detect_chains(timeline_rows)
    chain_findings = [_chain_dict(chain) for chain in chains]
    policy_violations: list[dict[str, str]] = []
    reasons = [
        f"ATTACK CHAIN: {chain.chain_id} ({chain.severity}) — {chain.description}"
        for chain in chains
    ]
    risk_level = "UNASSESSED"
    if any(chain.severity.upper() == "CRITICAL" for chain in chains):
        risk_level = "CRITICAL"
    elif any(chain.severity.upper() == "HIGH" for chain in chains):
        risk_level = "HIGH"

    assessment_status = "chain_only" if chains else "not_assessed"
    availability_reason = "No trained behavior model is available for this agent."
    result: dict[str, Any] = {
        "session_id": session_id,
        "agent_id": agent_id,
        "assessment_status": assessment_status,
        "availability": {
            "ml_assessment": False,
            "model_status": "UNAVAILABLE",
            "reason": availability_reason if call_rows else "No tool-call telemetry is available.",
        },
        "risk_level": risk_level,
        "final_risk_score": None,
        "ml_risk_score": None,
        "policy_violations": policy_violations,
        "attack_chains": chain_findings,
        "why_flagged": reasons,
        "contributing_signals": [],
        "evidence": [],
        "feature_contributions": [],
    }

    if not call_rows:
        signals, evidence = _assessment_signals(
            [], chains, call_rows, timeline_rows, None
        )
        result["contributing_signals"] = signals
        result["evidence"] = evidence
        return result

    from core.features import extract_session_features
    from core.policy import evaluate_policy, get_policy

    features = extract_session_features(session_id, call_rows)
    policy = get_policy(agent_id)
    violations = evaluate_policy(features, policy)
    policy_violations = [
        {"rule": violation.rule, "detail": violation.detail, "severity": violation.severity}
        for violation in violations
    ]
    signals, evidence = _assessment_signals(
        violations, chains, call_rows, timeline_rows, policy
    )
    result["policy_violations"] = policy_violations
    result["contributing_signals"] = signals
    result["evidence"] = evidence
    result["why_flagged"] = [
        *(f"POLICY VIOLATION: {violation['detail']}" for violation in policy_violations),
        *reasons,
    ]
    if violations:
        result["risk_level"] = "CRITICAL"
        result["assessment_status"] = "policy_only" if not chains else "policy_and_chain_only"

    from core.detector import BehaviorAnomalyDetector, ModelCompatibilityError
    from core.risk_engine import assess_session

    if (
        not _AGENT_ID_RE.fullmatch(agent_id)
        or agent_id in {".", ".."}
        or Path(agent_id).name != agent_id
    ):
        result["availability"]["reason"] = "Invalid agent identifier; model lookup was rejected."
        return result

    cached_model = model_cache.get(agent_id) if model_cache is not None else None
    if cached_model is None:
        model_state = BehaviorAnomalyDetector.status(agent_id, model_dir=model_dir)
        detector = None
        if model_state["status"] == "LOADED":
            try:
                detector = BehaviorAnomalyDetector.load(agent_id, model_dir=model_dir)
            except (ModelCompatibilityError, OSError, ValueError) as exc:
                model_state = {
                    "status": "INCOMPATIBLE",
                    "reason": f"Baseline could not be loaded: {exc}",
                }
        if model_cache is not None:
            model_cache[agent_id] = (model_state, detector)
    else:
        model_state, detector = cached_model

    result["availability"]["model_status"] = model_state["status"]
    if detector is None:
        result["availability"]["reason"] = (
            availability_reason
            if model_state["status"] == "UNAVAILABLE"
            else model_state["reason"]
        )
        return result
    assessment = assess_session(
        session_id=session_id,
        features=features,
        detector=detector,
        policy=policy,
        rows=timeline_rows,
    )
    feature_contributions = [
        {
            "feature": item.feature,
            "value": round(float(item.value), 4),
            "baseline_mean": round(float(item.baseline_mean), 4),
            "z_score": round(float(item.z_score), 4),
        }
        for item in assessment.feature_contributions
    ]
    for contribution in assessment.feature_contributions:
        if abs(contribution.z_score) < 3.0:
            continue
        signal_evidence = _feature_evidence(
            contribution.feature, call_rows, features
        )
        for item in signal_evidence:
            if item not in result["evidence"]:
                result["evidence"].append(item)
        signals.append(
            {
                "type": "baseline_deviation",
                "signal": contribution.feature,
                "severity": assessment.risk_level,
                "detail": (
                    f"Observed value {contribution.value:.2f} is "
                    f"{abs(contribution.z_score):.1f} standard deviations from "
                    f"the trained baseline mean {contribution.baseline_mean:.2f}."
                ),
                "evidence": signal_evidence,
            }
        )
    if assessment.ml_risk_score > 0 and not any(
        signal["type"] == "baseline_deviation" for signal in signals
    ):
        signal_evidence = [
            _evidence_item(row, index, "tool_call")
            for index, row in enumerate(call_rows[:20])
        ]
        for item in signal_evidence:
            if item not in result["evidence"]:
                result["evidence"].append(item)
        signals.append(
            {
                "type": "behavioral_anomaly",
                "signal": "isolation_forest",
                "severity": assessment.risk_level,
                "detail": (
                    "The session fell below the trained behavior score band "
                    f"(ML risk score {assessment.ml_risk_score:.2f})."
                ),
                "evidence": signal_evidence,
            }
        )
    result.update(
        {
            "assessment_status": "complete",
            "availability": {"ml_assessment": True, "reason": None},
            "risk_level": assessment.risk_level,
            "final_risk_score": round(float(assessment.final_risk_score), 2),
            "ml_risk_score": round(float(assessment.ml_risk_score), 2),
            "policy_violations": [
                {"rule": item.rule, "detail": item.detail, "severity": item.severity}
                for item in assessment.policy_violations
            ],
            "attack_chains": [_chain_dict(chain) for chain in assessment.attack_chains],
            "why_flagged": assessment.why_flagged(),
            "contributing_signals": signals,
            "feature_contributions": feature_contributions,
        }
    )
    return result


def _load_or_create_session_secret(secret_path: Path) -> str:
    """Load a persistent cookie-signing secret, creating it once for local use."""
    secret_path = secret_path.expanduser().resolve()
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        value = secret_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = secrets.token_urlsafe(48)
        try:
            descriptor = os.open(secret_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            value = secret_path.read_text(encoding="utf-8").strip()
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(value + "\n")
    if len(value) < 32:
        raise RuntimeError(
            f"The AgentSentry session secret at {secret_path} is invalid. "
            "Remove that local file and restart to generate a new one."
        )
    return value


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    project_root = Path(__file__).resolve().parent.parent
    demo_data_dir = Path(
        os.environ.get("AGENTSENTRY_DEMO_DATA_DIR", str(_default_demo_data_dir()))
    ).expanduser()
    app.config.update(
        DATABASE=str(DB_PATH),
        AUTH_DATABASE=os.environ.get(
            "AGENTSENTRY_AUTH_DB_PATH", str(project_root / ".agentsentry_users.sqlite3")
        ),
        SESSION_SECRET_FILE=os.environ.get(
            "AGENTSENTRY_SESSION_SECRET_FILE", str(project_root / ".agentsentry_session_secret")
        ),
        SECRET_KEY=os.environ.get("AGENTSENTRY_SESSION_SECRET"),
        MODEL_DIR=os.environ.get(
            "AGENTSENTRY_MODEL_DIR",
            str(project_root / "models"),
        ),
        DEMO_ENABLED=os.environ.get("AGENTSENTRY_DEMO_MODE", "").strip() == "1",
        DEMO_DATABASE=os.environ.get(
            "AGENTSENTRY_DEMO_DATABASE", str(demo_data_dir / "telemetry.sqlite3")
        ),
        DEMO_MODEL_DIR=str(demo_data_dir / "in-memory-models"),
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
        # Optional legacy/service bearer key. Browser users authenticate with accounts.
        API_KEY=os.environ.get("AGENTSENTRY_API_KEY"),
        AUTH_REQUIRED=True,
        CORS_ORIGINS={
            origin.strip()
            for origin in os.environ.get(
                "AGENTSENTRY_CORS_ORIGINS",
                "http://127.0.0.1:5173,http://localhost:5173",
            ).split(",")
            if origin.strip()
        },
        SESSION_COOKIE_NAME="agentsentry_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("AGENTSENTRY_COOKIE_SECURE", "false").lower() == "true",
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        TESTING=False,
        DEBUG=False,
    )
    if test_config:
        app.config.update(test_config)
    if app.config["TESTING"] and not app.config["API_KEY"] and (
        not test_config or "AUTH_REQUIRED" not in test_config
    ):
        app.config["AUTH_REQUIRED"] = False
    if not app.config["AUTH_REQUIRED"] and not app.config["TESTING"]:
        raise RuntimeError("API authentication may only be disabled in explicit test mode.")

    # Tests use a deterministic throwaway key. Local runs create one persistent
    # secret file so signed browser sessions survive ordinary server restarts.
    if not app.config.get("SECRET_KEY"):
        if app.config["TESTING"]:
            app.config["SECRET_KEY"] = "agentsentry-test-only-session-secret"
        else:
            app.config["SECRET_KEY"] = _load_or_create_session_secret(
                Path(app.config["SESSION_SECRET_FILE"])
            )
    if not isinstance(app.config["SECRET_KEY"], str) or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("AGENTSENTRY_SESSION_SECRET must contain at least 32 characters.")

    app.config["SESSION_COOKIE_PATH"] = "/"

    def connect() -> sqlite3.Connection:
        database_uri = f"{Path(app.config['DATABASE']).resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(database_uri, uri=True, timeout=1.0)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def connection() -> Iterator[sqlite3.Connection]:
        conn = connect()
        try:
            yield conn
        finally:
            conn.close()

    def error(message: str, status: int):
        return jsonify({"error": message}), status

    def demo_service() -> DemoModeService:
        service = app.extensions.get("agentsentry_demo_service")
        database_path = Path(app.config["DEMO_DATABASE"]).expanduser().resolve()
        if not isinstance(service, DemoModeService) or service.database_path != database_path:
            service = DemoModeService(database_path)
            app.extensions["agentsentry_demo_service"] = service
        return service

    def demo_database_is_separate() -> bool:
        demo_database = Path(app.config["DEMO_DATABASE"]).expanduser().resolve()
        protected_databases = {
            Path(app.config["DATABASE"]).expanduser().resolve(),
            Path(app.config["AUTH_DATABASE"]).expanduser().resolve(),
        }
        if demo_database in protected_databases:
            return False
        return not any(
            protected.exists()
            and demo_database.exists()
            and os.path.samefile(demo_database, protected)
            for protected in protected_databases
        )

    def demo_access_error():
        if request.remote_addr not in _LOCAL_CLIENT_ADDRESSES:
            return error("SOC Demo Mode is restricted to localhost.", 403)
        if not app.config["DEMO_ENABLED"]:
            return error("SOC Demo Mode is disabled for this backend.", 404)
        if not demo_database_is_separate():
            return error(
                "The demo database must be separate from telemetry and user accounts.",
                500,
            )
        return None

    def demo_model_cache(agent_ids: set[str]) -> dict[str, tuple[dict[str, str], Any | None]]:
        cache = app.extensions.setdefault("agentsentry_demo_model_cache", {})
        from core.detector import BehaviorAnomalyDetector
        from core.features import extract_session_features
        from lab.synthetic import benign_sessions

        baseline_profiles = {
            "demo-code-reviewer": "demo-code-reviewer",
            "demo-research-assistant": "research-assistant",
            "demo-suspicious-agent": "demo-code-reviewer",
            "demo-attack-chain": "research-assistant",
        }
        for agent_id in sorted(agent_ids):
            if agent_id in cache:
                continue
            profile = baseline_profiles[agent_id]
            baseline_sessions = benign_sessions(profile, 40, seed_start=1000)
            vectors = [
                extract_session_features(f"demo-baseline-{index}", rows).to_vector()
                for index, rows in enumerate(baseline_sessions)
            ]
            detector = BehaviorAnomalyDetector(
                agent_id,
                model_dir=Path(app.config["DEMO_MODEL_DIR"]),
            )
            detector.fit(vectors)
            cache[agent_id] = (
                {
                    "status": "LOADED",
                    "reason": "Deterministic in-memory synthetic reference baseline.",
                },
                detector,
            )
        return cache

    def demo_payload(run_id: str | None = None) -> dict[str, Any]:
        base = {
            "enabled": bool(app.config["DEMO_ENABLED"]),
            "classification": "SIMULATED",
            "model_disclosure": (
                "Session features, policy rules, Isolation Forest scoring, and chain "
                "correlation use the production pipeline. The detector is fitted in "
                "memory to deterministic synthetic benign reference sessions; no "
                "model files are loaded or written, and these results are not "
                "real-world detections."
            ),
            "scenarios": list_demo_scenarios(),
            "active_run": None,
            "metrics": {
                "sessions_total": 0,
                "tool_calls_total": 0,
                "agents_total": 0,
                "alerts_total": 0,
            },
            "alerts": [],
        }
        if not app.config["DEMO_ENABLED"]:
            return base
        run = demo_service().read_run(run_id)
        if run is None:
            return base

        model_cache = demo_model_cache(
            {scenario["agent_id"] for scenario in run["scenarios"]}
        )
        assessed_scenarios = []
        alerts: list[dict[str, Any]] = []
        tool_call_total = 0
        for scenario in run["scenarios"]:
            session = scenario["session"]
            calls = scenario["calls"]
            timeline = build_timeline(calls, [])
            assessment = _risk_for_rows(
                scenario["agent_id"],
                session["session_id"],
                calls,
                timeline,
                Path(app.config["DEMO_MODEL_DIR"]),
                model_cache,
            )
            display_calls = []
            for call in calls:
                item = dict(call)
                item["arguments"] = _redact(_json_load(item.pop("arguments_json")))
                item["result_summary"] = _redact(item["result_summary"])
                item["classification"] = "SIMULATED"
                display_calls.append(item)
            tool_call_total += len(display_calls)
            assessment["classification"] = "SIMULATED"
            assessed = {
                "scenario_id": scenario["scenario_id"],
                "scenario_name": scenario["scenario_name"],
                "description": next(
                    item["description"]
                    for item in base["scenarios"]
                    if item["id"] == scenario["scenario_id"]
                ),
                "agent_id": scenario["agent_id"],
                "session": session,
                "calls": display_calls,
                "assessment": assessment,
                "review": scenario["review"],
                "classification": "SIMULATED",
            }
            assessed_scenarios.append(assessed)
            if (
                assessment["risk_level"] in {"HIGH", "CRITICAL"}
                or assessment["policy_violations"]
                or assessment["attack_chains"]
            ):
                alerts.append(
                    {
                        "alert_id": f"{run['run_id']}:{scenario['scenario_id']}",
                        "run_id": run["run_id"],
                        "scenario_id": scenario["scenario_id"],
                        "scenario_name": scenario["scenario_name"],
                        "agent_id": scenario["agent_id"],
                        "session_id": session["session_id"],
                        "risk_level": assessment["risk_level"],
                        "risk_score": assessment["final_risk_score"],
                        "why_flagged": assessment["why_flagged"],
                        "contributing_signals": assessment["contributing_signals"],
                        "classification": "SIMULATED",
                    }
                )
        base["active_run"] = {
            "run_id": run["run_id"],
            "created_at": run["created_at"],
            "scenarios": assessed_scenarios,
        }
        base["alerts"] = alerts
        base["metrics"] = {
            "sessions_total": len(assessed_scenarios),
            "tool_calls_total": tool_call_total,
            "agents_total": len({item["agent_id"] for item in assessed_scenarios}),
            "alerts_total": len(alerts),
        }
        return base

    def bearer_is_authenticated() -> bool:
        configured_key = app.config.get("API_KEY")
        if not isinstance(configured_key, str) or len(configured_key) < 32:
            return False
        authorization = request.headers.get("Authorization", "")
        scheme, separator, supplied_key = authorization.partition(" ")
        return bool(
            scheme == "Bearer"
            and separator
            and supplied_key
            and hmac.compare_digest(
                supplied_key.encode("utf-8"), configured_key.encode("utf-8")
            )
        )

    def current_user() -> dict[str, Any] | None:
        user = session.get("user")
        if not isinstance(user, dict):
            return None
        if not isinstance(user.get("id"), int) or not isinstance(user.get("email"), str):
            return None
        return {"id": user["id"], "name": str(user.get("name", "")), "email": user["email"]}

    def csrf_is_valid() -> bool:
        expected = session.get("csrf_token")
        supplied = request.headers.get("X-CSRF-Token", "")
        return bool(
            isinstance(expected, str)
            and expected
            and supplied
            and hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))
        )

    @app.before_request
    def enforce_api_access():
        if not request.path.startswith("/api/"):
            return None

        origin = request.headers.get("Origin")
        allowed_origins = app.config["CORS_ORIGINS"]
        if origin and origin not in allowed_origins:
            return error("Origin is not allowed", 403)

        if request.method == "OPTIONS":
            response = app.response_class(status=204)
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                "Accept, Authorization, Content-Type, X-CSRF-Token"
            )
            response.headers["Access-Control-Max-Age"] = "600"
            return response

        if request.path == "/api/health":
            return None
        if not app.config["AUTH_REQUIRED"]:
            return None

        # Account creation and login are public routes, protected by a short-lived
        # CSRF token issued by /api/auth/status and by the exact Origin allowlist.
        if request.path in {"/api/auth/status", "/api/auth/signup", "/api/auth/login"}:
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not csrf_is_valid():
                return error("A valid CSRF token is required. Refresh the page and try again.", 403)
            return None

        bearer_auth = bearer_is_authenticated()
        if not bearer_auth and current_user() is None:
            response, status = error("Sign in to access AgentSentry.", 401)
            response.headers["WWW-Authenticate"] = 'Bearer realm="AgentSentry API", Session realm="AgentSentry"'
            return response, status

        # Cookie-authenticated state-changing requests must prove same-session
        # intent. Bearer clients are exempt because the token is not ambient.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not bearer_auth:
            if not csrf_is_valid():
                return error("A valid CSRF token is required. Refresh the page and try again.", 403)
        return None

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        if origin and origin in app.config["CORS_ORIGINS"]:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Vary"] = "Origin"
        return response

    @contextmanager
    def auth_connection() -> Iterator[sqlite3.Connection]:
        auth_path = Path(app.config["AUTH_DATABASE"]).expanduser().resolve()
        auth_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(auth_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )"""
            )
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def establish_user(user_row: sqlite3.Row) -> dict[str, Any]:
        session.clear()
        session.permanent = True
        user = {
            "id": int(user_row["id"]),
            "name": str(user_row["name"]),
            "email": str(user_row["email"]),
        }
        session["user"] = user
        session["csrf_token"] = secrets.token_urlsafe(32)
        return user

    def schema_is_available(conn: sqlite3.Connection) -> bool:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        return _REQUIRED_TABLES.issubset({row["name"] for row in rows})

    def valid_session_id(value: str) -> bool:
        return bool(_SESSION_ID_RE.fullmatch(value or ""))

    def get_session_rows(conn: sqlite3.Connection, session_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """SELECT id, session_id, sequence_num, tool_name, arguments_json,
                      called_at, duration_ms, is_error, result_summary
               FROM tool_calls WHERE session_id = ? ORDER BY sequence_num ASC""",
            (session_id,),
        ).fetchall()
        return [_row_dict(row) for row in rows]

    def get_tool_events(conn: sqlite3.Connection, session_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """SELECT id, session_id, sequence_num, event_type, tool_name,
                      notification_method, before_definition_json, after_definition_json,
                      before_schema_json, after_schema_json, recorded_at
               FROM tool_definition_events WHERE session_id = ?
               ORDER BY sequence_num, id""",
            (session_id,),
        ).fetchall()
        return [_row_dict(row) for row in rows]

    def get_session_telemetry_batch(
        conn: sqlite3.Connection, session_ids: list[str]
    ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
        if not session_ids:
            return {}, {}
        placeholders = ",".join("?" for _ in session_ids)
        calls_by_session: dict[str, list[dict[str, Any]]] = {}
        events_by_session: dict[str, list[dict[str, Any]]] = {}
        calls = conn.execute(
            f"""SELECT id, session_id, sequence_num, tool_name, arguments_json,
                       called_at, duration_ms, is_error, result_summary
                FROM tool_calls WHERE session_id IN ({placeholders})
                ORDER BY session_id, sequence_num, id""",
            session_ids,
        ).fetchall()
        events = conn.execute(
            f"""SELECT id, session_id, sequence_num, event_type, tool_name,
                       notification_method, before_definition_json, after_definition_json,
                       before_schema_json, after_schema_json, recorded_at
                FROM tool_definition_events WHERE session_id IN ({placeholders})
                ORDER BY session_id, sequence_num, id""",
            session_ids,
        ).fetchall()
        for row in calls:
            calls_by_session.setdefault(row["session_id"], []).append(_row_dict(row))
        for row in events:
            events_by_session.setdefault(row["session_id"], []).append(_row_dict(row))
        return calls_by_session, events_by_session

    def build_timeline(
        calls: list[dict[str, Any]], events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        timeline = calls + [
            {
                **event,
                "called_at": event["recorded_at"],
                "arguments_json": "{}",
                "is_error": 0,
            }
            for event in events
        ]
        timeline.sort(key=lambda row: (row["sequence_num"], row.get("id", 0)))
        return timeline

    def assessment_for_session(
        conn: sqlite3.Connection,
        session_id: str,
        agent_id: str,
        call_rows: list[dict[str, Any]] | None = None,
        event_rows: list[dict[str, Any]] | None = None,
        model_cache: dict[str, tuple[dict[str, str], Any | None]] | None = None,
    ) -> dict[str, Any]:
        calls = call_rows if call_rows is not None else get_session_rows(conn, session_id)
        events = event_rows if event_rows is not None else get_tool_events(conn, session_id)
        return _risk_for_rows(
            agent_id,
            session_id,
            calls,
            build_timeline(calls, events),
            Path(app.config["MODEL_DIR"]),
            model_cache,
        )

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        try:
            with connection() as conn:
                available = schema_is_available(conn)
            if not available:
                return jsonify({"status": "unavailable", "database": "schema_unavailable"}), 503
            return jsonify({"status": "ok", "database": "connected"})
        except sqlite3.Error:
            return jsonify({"status": "unavailable", "database": "unavailable"}), 503

    @app.get("/api/auth/status")
    def auth_status():
        if not session.get("csrf_token"):
            session["csrf_token"] = secrets.token_urlsafe(32)
        user = current_user()
        authenticated = (
            not app.config["AUTH_REQUIRED"]
            or user is not None
            or bearer_is_authenticated()
        )
        return jsonify(
            {
                "required": bool(app.config["AUTH_REQUIRED"]),
                "authenticated": authenticated,
                "user": user,
                "csrf_token": session["csrf_token"],
            }
        )

    @app.post("/api/auth/signup")
    def auth_signup():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error("A JSON request body is required.", 400)
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip().lower()
        password = payload.get("password")
        if not name or len(name) > 80:
            return error("Name must contain between 1 and 80 characters.", 400)
        if len(email) > 254 or not _EMAIL_RE.fullmatch(email):
            return error("Enter a valid email address.", 400)
        if not isinstance(password, str) or len(password) < 12 or len(password) > 128:
            return error("Password must contain between 12 and 128 characters.", 400)
        try:
            with auth_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, strftime('%s','now'))",
                    (name, email, generate_password_hash(password, method="scrypt")),
                )
                user_row = conn.execute(
                    "SELECT id, name, email FROM users WHERE id = ?", (cursor.lastrowid,)
                ).fetchone()
        except sqlite3.IntegrityError:
            return error("An account with this email already exists. Sign in instead.", 409)
        except sqlite3.Error:
            app.logger.exception("Unable to create local AgentSentry account")
            return error("Unable to create the account. Try again.", 500)
        user = establish_user(user_row)
        return jsonify(
            {"authenticated": True, "user": user, "csrf_token": session["csrf_token"]}
        ), 201

    @app.post("/api/auth/login")
    def auth_login():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error("A JSON request body is required.", 400)
        email = str(payload.get("email", "")).strip().lower()
        password = payload.get("password")
        if len(email) > 254 or not _EMAIL_RE.fullmatch(email) or not isinstance(password, str):
            return error("Email or password is incorrect.", 401)
        try:
            with auth_connection() as conn:
                user_row = conn.execute(
                    "SELECT id, name, email, password_hash FROM users WHERE email = ? COLLATE NOCASE",
                    (email,),
                ).fetchone()
        except sqlite3.Error:
            app.logger.exception("Unable to read local AgentSentry account")
            return error("Unable to sign in. Try again.", 500)
        if user_row is None or not check_password_hash(user_row["password_hash"], password):
            return error("Email or password is incorrect.", 401)
        user = establish_user(user_row)
        return jsonify(
            {"authenticated": True, "user": user, "csrf_token": session["csrf_token"]}
        )

    @app.post("/api/auth/logout")
    def auth_logout():
        session.clear()
        return jsonify({"logged_out": True})

    @app.get("/api/auth/verify")
    def auth_verify():
        payload = {"authenticated": True}
        user = current_user()
        if user is not None:
            payload["user"] = user
        return jsonify(payload)

    @app.get("/api/demo")
    def get_demo_data():
        if request.remote_addr not in _LOCAL_CLIENT_ADDRESSES:
            return error("SOC Demo Mode is restricted to localhost.", 403)
        if app.config["DEMO_ENABLED"] and not demo_database_is_separate():
            return error(
                "The demo database must be separate from telemetry and user accounts.",
                500,
            )
        try:
            return jsonify(demo_payload())
        except (OSError, sqlite3.Error):
            app.logger.exception("Unable to read isolated SOC demo data")
            return error("Unable to read SOC demo data.", 500)

    @app.post("/api/demo/load")
    def load_demo_data():
        access_error = demo_access_error()
        if access_error:
            return access_error
        if not request.is_json:
            return error("Content-Type must be application/json.", 415)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error("A JSON request object is required.", 400)
        scenario_id = payload.get("scenario_id")
        if scenario_id is not None and not isinstance(scenario_id, str):
            return error("scenario_id must be text.", 400)
        try:
            run_id = demo_service().load(scenario_id)
            return jsonify(demo_payload(run_id)), 201
        except ValueError as exc:
            return error(str(exc), 400)
        except RuntimeError as exc:
            return error(str(exc), 409)
        except (OSError, sqlite3.Error):
            app.logger.exception("Unable to load isolated SOC demo data")
            return error("Unable to load SOC demo data.", 500)

    @app.post("/api/demo/reset")
    def reset_demo_data():
        access_error = demo_access_error()
        if access_error:
            return access_error
        if not request.is_json:
            return error("Content-Type must be application/json.", 415)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error("A JSON request object is required.", 400)
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
            return error("A valid demo run_id is required.", 400)
        try:
            if not demo_service().reset(run_id):
                return error("Demo run not found.", 404)
            return jsonify(demo_payload())
        except (OSError, sqlite3.Error, ValueError):
            app.logger.exception("Unable to reset isolated SOC demo data")
            return error("Unable to reset SOC demo data.", 500)

    @app.post("/api/demo/runs/<run_id>/sessions/<session_id>/review")
    def review_demo_session(run_id: str, session_id: str):
        access_error = demo_access_error()
        if access_error:
            return access_error
        if not re.fullmatch(r"[a-f0-9]{32}", run_id) or not valid_session_id(session_id):
            return error("Invalid demo run or session identifier.", 400)
        if not request.is_json:
            return error("Content-Type must be application/json.", 415)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error("A JSON review object is required.", 400)
        service = demo_service()
        if not service.session_belongs_to_run(run_id, session_id):
            return error("Demo session not found in this run.", 404)
        try:
            result = review_session(
                Path(app.config["DEMO_DATABASE"]),
                session_id,
                payload.get("decision"),
                payload.get("reviewer"),
                payload.get("note", ""),
                payload.get("confirm_reviewed") is True,
            )
            return jsonify(result), 201
        except ValueError as exc:
            return error(str(exc), 400)
        except (OSError, sqlite3.Error):
            app.logger.exception("Unable to record SOC demo investigation")
            return error("Unable to record the demo investigation.", 500)

    @app.get("/api/agents")
    def agents():
        try:
            with connection() as conn:
                rows = conn.execute(
                    """SELECT s.agent_id, COUNT(DISTINCT s.session_id) AS session_count,
                              COUNT(tc.id) AS tool_call_count,
                              MAX(s.started_at) AS last_seen
                       FROM sessions AS s
                       LEFT JOIN tool_calls AS tc ON tc.session_id = s.session_id
                       GROUP BY s.agent_id ORDER BY last_seen DESC"""
                ).fetchall()
            return jsonify([_row_dict(row) for row in rows])
        except sqlite3.Error:
            return error("Unable to read agent telemetry", 500)

    @app.get("/api/sessions")
    def sessions():
        agent_id = request.args.get("agent_id")
        if agent_id is not None and not _AGENT_ID_RE.fullmatch(agent_id):
            return error("Invalid agent_id", 400)
        try:
            limit = int(request.args.get("limit", _DEFAULT_LIMIT))
        except ValueError:
            return error("limit must be an integer", 400)
        if not 1 <= limit <= _MAX_LIMIT:
            return error(f"limit must be between 1 and {_MAX_LIMIT}", 400)
        try:
            with connection() as conn:
                query = """SELECT s.session_id, s.agent_id, s.started_at, s.ended_at,
                                   COUNT(tc.id) AS call_count
                            FROM sessions AS s
                            LEFT JOIN tool_calls AS tc ON tc.session_id = s.session_id"""
                params: list[Any] = []
                if agent_id is not None:
                    query += " WHERE s.agent_id = ?"
                    params.append(agent_id)
                query += " GROUP BY s.session_id ORDER BY s.started_at DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                session_ids = [row["session_id"] for row in rows]
                calls_by_session, events_by_session = get_session_telemetry_batch(
                    conn, session_ids
                )
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                has_reviews = "session_reviews" in tables
                model_cache: dict[str, tuple[dict[str, str], Any | None]] = {}
                payload = []
                for row in rows:
                    item = _row_dict(row)
                    assessment = assessment_for_session(
                        conn,
                        item["session_id"],
                        item["agent_id"],
                        calls_by_session.get(item["session_id"], []),
                        events_by_session.get(item["session_id"], []),
                        model_cache,
                    )
                    item.update(
                        risk_level=assessment["risk_level"],
                        risk_score=assessment["final_risk_score"],
                        assessment_status=assessment["assessment_status"],
                        review=get_review_status(conn, item["session_id"])
                        if has_reviews
                        else {"decision": "unreviewed", "reviewer": None, "reviewed_at": None, "review_note": "", "evidence_current": False},
                    )
                    payload.append(item)
            return jsonify(payload)
        except sqlite3.Error:
            return error("Unable to read sessions", 500)

    @app.get("/api/sessions/<session_id>")
    def session_detail(session_id: str):
        if not valid_session_id(session_id):
            return error("Invalid session_id", 400)
        try:
            with connection() as conn:
                session = conn.execute(
                    """SELECT session_id, agent_id, started_at, ended_at
                       FROM sessions WHERE session_id = ?""",
                    (session_id,),
                ).fetchone()
                if session is None:
                    return error("Session not found", 404)
                calls = get_session_rows(conn, session_id)
                events = get_tool_events(conn, session_id)
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                review = get_review_status(conn, session_id) if "session_reviews" in tables else {
                    "decision": "unreviewed", "reviewer": None, "reviewed_at": None,
                    "review_note": "", "evidence_current": False,
                }
            call_items = []
            for row in calls:
                item = dict(row)
                arguments = _json_load(item.pop("arguments_json"))
                item["arguments"] = _redact(arguments)
                item["result_summary"] = _redact(item["result_summary"])
                call_items.append(item)
            event_items = []
            for row in events:
                item = dict(row)
                for key in (
                    "before_definition_json",
                    "after_definition_json",
                    "before_schema_json",
                    "after_schema_json",
                ):
                    item[key.removesuffix("_json")] = _redact(_json_load(item.pop(key)))
                item["called_at"] = item.pop("recorded_at")
                event_items.append(item)
            return jsonify(
                {
                    "session": _row_dict(session),
                    "calls": call_items,
                    "tool_definition_events": event_items,
                    "review": review,
                }
            )
        except sqlite3.Error:
            return error("Unable to read session", 500)

    @app.get("/api/sessions/<session_id>/review")
    def session_review_status(session_id: str):
        if not valid_session_id(session_id):
            return error("Invalid session_id", 400)
        try:
            with connection() as conn:
                exists = conn.execute("SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if exists is None:
                    return error("Session not found", 404)
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "session_reviews" not in tables:
                    return jsonify({"decision": "unreviewed", "reviewer": None, "reviewed_at": None,
                                    "review_note": "", "evidence_current": False})
                return jsonify(get_review_status(conn, session_id))
        except sqlite3.Error:
            return error("Unable to read session review status", 500)

    @app.post("/api/sessions/<session_id>/review")
    def submit_session_review(session_id: str):
        if not valid_session_id(session_id):
            return error("Invalid session_id", 400)
        if request.remote_addr not in {"127.0.0.1", "::1", "localhost"}:
            return error("Session review is restricted to local operators", 403)
        if not request.is_json:
            return error("Content-Type must be application/json", 415)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error("A JSON review object is required", 400)
        try:
            result = review_session(
                Path(app.config["DATABASE"]), session_id,
                payload.get("decision"), payload.get("reviewer"),
                payload.get("note", ""), payload.get("confirm_reviewed") is True,
            )
            return jsonify(result), 201
        except ValueError as exc:
            message = str(exc)
            status = 404 if message == "Session not found." else 400
            return error(message, status)
        except (OSError, sqlite3.Error):
            return error("Unable to record session review", 500)

    @app.get("/api/sessions/<session_id>/assessment")
    def session_assessment(session_id: str):
        if not valid_session_id(session_id):
            return error("Invalid session_id", 400)
        try:
            with connection() as conn:
                session = conn.execute(
                    "SELECT agent_id FROM sessions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if session is None:
                    return error("Session not found", 404)
                result = assessment_for_session(conn, session_id, session["agent_id"])
            return jsonify(result)
        except sqlite3.Error:
            return error("Unable to assess session", 500)

    @app.get("/api/dashboard/overview")
    def overview():
        try:
            with connection() as conn:
                sessions_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                calls_count = conn.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
                agents_count = conn.execute(
                    "SELECT COUNT(DISTINCT agent_id) FROM sessions"
                ).fetchone()[0]
                active_count = conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL"
                ).fetchone()[0]
                changes_count = conn.execute(
                    "SELECT COUNT(*) FROM tool_definition_events"
                ).fetchone()[0]
            return jsonify(
                {
                    "sessions_total": sessions_count,
                    "tool_calls_total": calls_count,
                    "agents_total": agents_count,
                    "active_sessions": active_count,
                    "tool_definition_changes": changes_count,
                    "metrics_note": "Counts are derived from persisted SQLite telemetry.",
                }
            )
        except sqlite3.Error:
            return error("Unable to read dashboard overview", 500)

    @app.get("/api/dashboard/activity")
    def activity():
        try:
            limit = int(request.args.get("limit", _DEFAULT_LIMIT))
        except ValueError:
            return error("limit must be an integer", 400)
        if not 1 <= limit <= _MAX_LIMIT:
            return error(f"limit must be between 1 and {_MAX_LIMIT}", 400)
        try:
            with connection() as conn:
                calls = conn.execute(
                    """SELECT id, session_id, sequence_num, tool_name, called_at,
                              duration_ms, is_error, result_summary
                       FROM tool_calls ORDER BY called_at DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
                events = conn.execute(
                    """SELECT id, session_id, sequence_num, event_type, tool_name,
                              notification_method, recorded_at
                       FROM tool_definition_events ORDER BY recorded_at DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
            items = []
            for row in calls:
                item = _row_dict(row)
                item["result_summary"] = _redact(item["result_summary"])
                item["event_type"] = "tool_call"
                items.append(item)
            for row in events:
                item = _row_dict(row)
                item["called_at"] = item.pop("recorded_at")
                items.append(item)
            items.sort(key=lambda item: item["called_at"], reverse=True)
            return jsonify(items[:limit])
        except sqlite3.Error:
            return error("Unable to read activity", 500)

    @app.get("/api/dashboard/risk-distribution")
    def risk_distribution():
        try:
            with connection() as conn:
                sessions = conn.execute(
                    "SELECT session_id, agent_id FROM sessions ORDER BY started_at DESC"
                ).fetchall()
                model_cache: dict[str, tuple[dict[str, str], Any | None]] = {}
                counts = {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "CRITICAL": 0,
                    "UNASSESSED": 0,
                }
                for start in range(0, len(sessions), 200):
                    page = sessions[start : start + 200]
                    calls_by_session, events_by_session = get_session_telemetry_batch(
                        conn, [row["session_id"] for row in page]
                    )
                    for row in page:
                        assessment = assessment_for_session(
                            conn,
                            row["session_id"],
                            row["agent_id"],
                            calls_by_session.get(row["session_id"], []),
                            events_by_session.get(row["session_id"], []),
                            model_cache,
                        )
                        level = assessment["risk_level"]
                        counts[level] = counts.get(level, 0) + 1
            return jsonify({"distribution": counts, "total_sessions": len(sessions)})
        except sqlite3.Error:
            return error("Unable to calculate risk distribution", 500)

    @app.get("/api/dashboard/attack-chains")
    def attack_chains():
        try:
            with connection() as conn:
                sessions = conn.execute(
                    "SELECT session_id, agent_id FROM sessions ORDER BY started_at DESC"
                ).fetchall()
                findings = []
                for start in range(0, len(sessions), 200):
                    page = sessions[start : start + 200]
                    calls_by_session, events_by_session = get_session_telemetry_batch(
                        conn, [row["session_id"] for row in page]
                    )
                    for row in page:
                        timeline = build_timeline(
                            calls_by_session.get(row["session_id"], []),
                            events_by_session.get(row["session_id"], []),
                        )
                        for chain in detect_chains(timeline):
                            findings.append(
                                {
                                    "session_id": row["session_id"],
                                    "agent_id": row["agent_id"],
                                    **_chain_dict(chain),
                                }
                            )
            return jsonify(findings)
        except sqlite3.Error:
            return error("Unable to read attack chains", 500)

    @app.get("/api/mcp/servers")
    def mcp_servers():
        database_path = Path(app.config["DATABASE"]).resolve()
        if not database_path.is_file():
            return jsonify(
                {
                    "available": False,
                    "status": "unavailable",
                    "servers": [],
                    "reason": "Telemetry database is unavailable.",
                }
            )
        try:
            with connection() as conn:
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                required = {"mcp_servers", "mcp_server_connections"}
                if not required.issubset(tables):
                    return jsonify(
                        {
                            "available": False,
                            "status": "unavailable",
                            "servers": [],
                            "reason": "Persistent MCP server inventory is not initialized.",
                        }
                    )

                server_rows = conn.execute(
                    """SELECT server_id, server_name, transport, first_seen, last_seen,
                              connection_count
                       FROM mcp_servers ORDER BY last_seen DESC, server_id"""
                ).fetchall()
                servers = []
                for row in server_rows:
                    connections = conn.execute(
                        """SELECT c.session_id, c.connected_at, c.disconnected_at,
                                  s.agent_id
                           FROM mcp_server_connections AS c
                           JOIN sessions AS s ON s.session_id = c.session_id
                           WHERE c.server_id = ?
                           ORDER BY c.connected_at DESC, c.session_id""",
                        (row["server_id"],),
                    ).fetchall()
                    session_items = [
                        {
                            "session_id": connection_row["session_id"],
                            "agent_id": connection_row["agent_id"],
                            "connected_at": connection_row["connected_at"],
                            "disconnected_at": connection_row["disconnected_at"],
                            "connection_status": (
                                "connected"
                                if connection_row["disconnected_at"] is None
                                else "disconnected"
                            ),
                        }
                        for connection_row in connections
                    ]
                    agent_connections: dict[str, int] = {}
                    for item in session_items:
                        agent_id = item["agent_id"]
                        agent_connections[agent_id] = agent_connections.get(agent_id, 0) + 1
                    servers.append(
                        {
                            "server_id": row["server_id"],
                            "server_name": _redact(row["server_name"]),
                            "transport": row["transport"],
                            "first_seen": row["first_seen"],
                            "last_seen": row["last_seen"],
                            "connection_count": row["connection_count"],
                            "connection_status": (
                                "connected"
                                if any(
                                    item["connection_status"] == "connected"
                                    for item in session_items
                                )
                                else "disconnected"
                            ),
                            "agents": [
                                {"agent_id": agent_id, "connection_count": count}
                                for agent_id, count in sorted(agent_connections.items())
                            ],
                            "sessions": session_items,
                        }
                    )
            if not servers:
                return jsonify(
                    {
                        "available": False,
                        "status": "empty",
                        "servers": [],
                        "reason": "No MCP servers have been observed by the proxy.",
                    }
                )
            return jsonify(
                {"available": True, "status": "available", "servers": servers}
            )
        except sqlite3.OperationalError:
            return jsonify(
                {
                    "available": False,
                    "status": "unavailable",
                    "servers": [],
                    "reason": "Persistent MCP server inventory is unavailable.",
                }
            )
        except sqlite3.Error:
            return error("Unable to read MCP server inventory", 500)

    @app.get("/api/mcp/tool-changes")
    def tool_changes():
        try:
            with connection() as conn:
                rows = conn.execute(
                    """SELECT id, session_id, sequence_num, event_type, tool_name,
                              notification_method, before_definition_json, after_definition_json,
                              before_schema_json, after_schema_json, recorded_at
                       FROM tool_definition_events ORDER BY recorded_at DESC LIMIT 200"""
                ).fetchall()
            items = []
            for row in rows:
                item = _row_dict(row)
                for key in (
                    "before_definition_json",
                    "after_definition_json",
                    "before_schema_json",
                    "after_schema_json",
                ):
                    item[key.removesuffix("_json")] = _redact(_json_load(item.pop(key)))
                items.append(item)
            return jsonify(items)
        except sqlite3.Error:
            return error("Unable to read MCP tool changes", 500)

    @app.errorhandler(404)
    def not_found(_exc):
        return error("Not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(_exc):
        return error("Method not allowed", 405)

    @app.errorhandler(RequestEntityTooLarge)
    def request_entity_too_large(_exc):
        return error("Request body exceeds the 1 MiB limit", 413)

    @app.errorhandler(Exception)
    def unexpected_error(_exc):
        app.logger.exception("Unhandled API request error")
        return error("Internal server error", 500)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
