# AgentSentry Phase 7 REST API

The read-only Flask API serves persisted AgentSentry SQLite telemetry. It does
not create demo records or modify the database. MCP server inventory is
reported only after the proxy persists a downstream server observed during an
MCP initialize handshake.

## Setup and run

From PowerShell:

```powershell
Set-Location D:\AGENT_SENTRY
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements-phase7.txt
```

The API expects the existing Phase 2 telemetry schema. Initialize it before
starting the API when needed:

```powershell
python scripts\init_db.py
```

This command calls the existing `core.telemetry.init_db()` function. It uses
`CREATE ... IF NOT EXISTS`, so it is safe to run again: existing tables and
telemetry rows are preserved, and no session or event records are inserted.
The additive `mcp_servers` and `mcp_server_connections` tables store observed
server identity, stdio transport, first/last seen times, connection counts,
connection lifecycle, and associations to existing agent sessions.

Start the API:

```powershell
python -m api.app
```

It listens on `127.0.0.1:5000` with debug mode disabled. It does not expose
the database path or create sample telemetry. Normal telemetry is created by
the existing proxy when an agent session runs.

`GET /api/mcp/servers` distinguishes unavailable inventory schema, an
initialized-but-empty registry, and actual proxy-observed servers. Responses
contain associated agent/session identifiers but never command arguments or
environment values. Connection status is based on persisted proxy connection
and shutdown events; no sample servers or status values are synthesized.

## Endpoints

- `GET /api/health`
- `GET /api/agents`
- `GET /api/sessions?agent_id=&limit=`
- `GET /api/sessions/<session_id>`
- `GET /api/sessions/<session_id>/assessment`
- `GET /api/dashboard/overview`
- `GET /api/dashboard/activity`
- `GET /api/dashboard/risk-distribution`
- `GET /api/dashboard/attack-chains`
- `GET /api/mcp/servers`
- `GET /api/mcp/tool-changes`

Assessments use the existing risk engine when a trained per-agent model is
available. Without one, the API reports actual policy and attack-chain findings
without inventing ML scores; unavailable values are `null` and the response
includes an assessment/availability status. Tool-definition changes come only
from the proxy-observed `tool_definition_events` table.

Run focused API tests with:

```powershell
python -m pytest tests\test_api.py -q
```
