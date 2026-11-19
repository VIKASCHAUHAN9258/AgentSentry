# Phase 9.3 — Live Gemini Dashboard Verification

The Gemini agent's proxy uses the telemetry database path supplied to
`run_task(db_path=...)`. Without an override, the proxy uses the existing
`core.telemetry.DB_PATH`, which is also the Flask API's default database.
Telemetry uses the existing SQLite schema. The Flask API opens the database
read-only; a successful verification appends one Gemini session and its two
tool calls through the proxy.

## Automated coverage

The API verification helper is tested using a temporary SQLite database:

```powershell
.\venv\Scripts\python.exe -m pytest tests\test_gemini_dashboard_verification.py -v
```

The real Gemini test remains opt-in and writes only to a temporary database:

```powershell
$env:AGENTSENTRY_RUN_LIVE_GEMINI = "1"
.\venv\Scripts\python.exe -m pytest tests\test_gemini_agent_live.py -v
```

## Explicit production verification

This is the only workflow here that contacts the real Gemini API and appends
telemetry to the existing production database. It fails closed if that database
does not exist or is unavailable. It searches only the sandbox for `TODO`,
then reports the result. It does not initialize, seed, update, or delete
existing production records.

From the repository root in PowerShell:

```powershell
$env:GEMINI_API_KEY = "<your Gemini API key>"
.\venv\Scripts\python.exe scripts\verify_gemini_dashboard.py --run-live --confirm-production-write
```

To see the result in the existing React dashboard, start the Flask API and
dashboard in separate terminals before running the verification command:

```powershell
# Terminal 1, repository root
.\venv\Scripts\python.exe -m api.app
```

```powershell
# Terminal 2, repository root
Set-Location dashboard
npm run dev
```

Then open `http://127.0.0.1:5173`, refresh **Incident Management**, and confirm
the persisted metrics and activity timeline update. Open **Agent sessions**,
search for `gemini-code-agent`, and inspect the newest session. The verification
command confirms the exact session, `search_code` then `report` tool-call
sequence, and persisted metric counts through `/api/health`, `/api/agents`,
`/api/sessions`, `/api/dashboard/overview`, and `/api/dashboard/activity`.
It does not claim that a person has visually verified the browser dashboard.
