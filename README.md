# AgentSentry

**Runtime behavioral security monitor for AI agent (MCP) tool-call sessions.**

Static MCP security scanners (Snyk Agent Scan, Cisco MCP Scanner, mcp-audit) check whether a
tool's *definition* looks dangerous before an agent ever runs. None of them watch what an agent
actually *does* once it's live. AgentSentry sits between an AI agent and its MCP tool servers,
builds a behavioral baseline per agent/workflow, and flags sessions whose tool-call sequence,
privilege trajectory, or data-flow pattern deviates from that baseline — including multi-step
attack chains (e.g. sensitive-file-read → transform → outbound-network-call) that look harmless
call-by-call but malicious as a sequence.

> Current scope: Flask API, MCP proxy, SQLite telemetry and review workflow,
> simulated attack lab, and React dashboard are present. See
> [`docs/SECURITY.md`](docs/SECURITY.md) for security boundaries and
> [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md) for the latest
> verification status.

## What exists right now

**Phase 1 — Foundation**
- `mcp_lab/file_tools_server.py` — a minimal real MCP server (`read_file`, `search_code`, `report`)
  used as the lab target for everything AgentSentry monitors.
- `agent/demo_agent.py` — a scripted MCP client simulating a benign "CodeReviewer" agent session,
  plus a security smoke test for path traversal.
- Path-traversal / absolute-path protection built into the lab server itself.

**Phase 2 — Interception Proxy** (`core/proxy.py`, `core/telemetry.py`)
- A transparent MCP proxy: the agent connects to AgentSentry instead of the real server, sees the
  exact same tools and results, and never knows it's being monitored.
- Every tool call — name, arguments, timestamp, duration, success/error, result summary — is
  written to `agentsentry.db` (SQLite) **before** the result is returned to the agent, so a crash
  mid-call can never create a blind spot.
- Errors and blocked attacks (e.g. a rejected path-traversal attempt) are logged too, not just
  successful calls — verified by test, not assumed.

**Known limitation (documented, not hidden):** the lab server reports some failures as plain text
("ERROR: file not found") rather than an MCP protocol error, so the proxy's `is_error` flag alone
doesn't catch every failure case. Phase 3's feature engineering will also need to pattern-match
result text, not rely on `is_error` in isolation.

**Phase 3 — Feature Engineering** (`core/privilege.py`, `core/features.py`)
- `core/privilege.py` — a tool → privilege-level registry (READ / TRANSFORM / NETWORK / EXECUTE).
  Unknown tools default to **NETWORK**, not READ — a deliberate security decision documented in
  the file, so a session can't dodge the escalation-distance feature just by calling something
  outside the registry.
- `core/features.py` — converts raw `tool_calls` rows into a numeric feature vector per session:
  call-sequence bigrams, unique-tool count, error rate, session duration and inter-call timing,
  max privilege reached, privilege-escalation distance (largest jump anywhere in the session, not
  just the last step), and Shannon-entropy of argument values (flags encoded/obfuscated payloads —
  the "transform" step in a read → encode → network exfiltration chain).
- Fully decoupled from live MCP sessions: it works on `tool_calls` rows regardless of how they
  were logged, so it's tested with synthetic sessions (benign, privilege-escalation attack,
  exfiltration-chain pattern) as well as verified end-to-end against a real proxied session.

**Bug caught while building this phase (documented, not hidden):** the first version of the
entropy test used a hand-written "base64-looking" string padded with repeated characters, which
scored *lower* entropy than plain text — the opposite of what it was supposed to demonstrate.
Caught by actually running the test, not by inspection; fixed by using base64 of real random
bytes instead.

**Phase 4 — Hybrid Detection Engine** (`core/detector.py`, `core/policy.py`, `core/risk_engine.py`)
- `core/detector.py` — a per-agent Isolation Forest, trained on that agent's own benign session
  history (minimum 10 sessions — there is no public dataset of real agent-hijack sessions, so
  baselines are built from each agent's observed traffic). Produces a 0–100 risk score plus a
  ranked "why flagged" feature-contribution list (z-score against the training baseline — an
  honest heuristic, not a formally derived attribution like SHAP, documented as such in the code).
- `core/policy.py` — deterministic rules independent of the ML model: every agent has a privilege
  ceiling and a denied-tool list; violating either is a hard rule check, not a statistical guess.
- `core/risk_engine.py` — combines both: **a policy violation always forces CRITICAL risk (≥95),
  regardless of the ML score.** An ML model being wrong or under-trained should never be able to
  talk the system out of "a read-only agent just executed a shell command."
- Verified end-to-end on **real** proxied telemetry (12 live sessions through the Phase 2 proxy,
  not just synthetic test fixtures): a held-out real benign session scored LOW risk; a simulated
  privilege-escalation attack scored CRITICAL (100.0) with a correct, human-readable explanation.

**Bug caught while building this phase:** feature contribution z-scores could explode to absurd
magnitudes ("285716838761496.0 std devs") when a feature had ~zero variance in training (e.g.
every benign session used the same privilege level, so the div-by-zero guard's tiny epsilon std
dominates the ratio). The direction/ranking was still correct, but the raw number would look
broken on a dashboard. Fixed by clipping displayed z-scores to ±50 — caught by actually running
the pipeline against real data, not by reading the code.

## Phase 5 — Attack-chain correlation (implemented)

`core/chain_detector.py` correlates ordered telemetry rows, so individually permitted calls
can be assessed as a suspicious sequence. It currently implements:

- `sensitive_read_to_network` — sensitive local resource read followed by a network-capable
  call, allowing up to three unrelated calls between the steps (HIGH severity; MITRE hints
  T1005 and T1041).
- `read_to_execute` — a READ-level call followed by an EXECUTE-level call, with the same
  bounded gap (CRITICAL severity; MITRE hint T1059).
- `is_sensitive_path()` — conservative filename/path matching for `.env` variants, SSH
  private-key names, credential/token/password names, private-key file extensions and
  `/etc/shadow`. This is name-based detection, not secret-content inspection.

`core/risk_engine.assess_session(..., rows=...)` adds chain findings without breaking old
callers: CRITICAL chains impose a score floor of 90 and CRITICAL level; HIGH chains impose a
score floor of 70 and at least HIGH level. `RiskAssessment.attack_chains` and
`why_flagged()` expose the findings to the API and dashboard. The `research-assistant`
policy permits NETWORK-level tools so the A3 sequence is detected by correlation rather than
by a policy denial. Tool-definition-change events are also recorded by the proxy and exposed to
the investigation workflow.

## Scope and limitations

- Attack scenarios are simulation-only and do not establish production
  detection accuracy.
- The Flask API requires a configured bearer API key outside tests. The
  dashboard prompts for the key and keeps it in tab memory only. This is a
  local-operator control, not a multi-user identity or authorization system;
  keep the API bound to loopback.
- Baseline model files use joblib/pickle deserialization. Only load models from
  a trusted, write-restricted model directory; see
  [`docs/MODEL_SECURITY.md`](docs/MODEL_SECURITY.md).
- Resource/prompt MCP features and remote MCP transports are not proxied; see
  [`docs/GENERIC_MCP_CLIENTS.md`](docs/GENERIC_MCP_CLIENTS.md).

## Requirements

- Python 3.10+
- See `requirements.txt`

## Setup

```bash
python -m venv venv
```

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

On macOS/Linux:

```bash
source venv/bin/activate
python -m pip install -r requirements.txt
test -e .env || cp .env.example .env
```

Only create `.env` if it does not already exist. Never replace a file
containing real credentials with the example file. Set `AGENTSENTRY_API_KEY`
in `.env` to a randomly generated secret with at least 32 characters before
starting Flask. Keep `.env` private and out of source control. Configure
`AGENTSENTRY_CORS_ORIGINS` only with the trusted dashboard origins that need
browser access; the default allows the two loopback Vite origins.

## Run the application

Start the Flask API from the project root (PowerShell):

```powershell
# Or set AGENTSENTRY_API_KEY in the existing .env file before starting.
$env:AGENTSENTRY_API_KEY = (& .\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
.\venv\Scripts\python.exe -m flask --app api.app:create_app run --host 127.0.0.1 --port 5000
```

In another terminal, start the dashboard:

```powershell
cd dashboard
npm run dev
```

The Vite development server is available at `http://127.0.0.1:5173/`, proxies
`/api` requests to the loopback Flask API, and prompts for the API key. The key
is not embedded in the frontend or persisted in browser storage; reloads
require re-entry. For a production frontend, run `npm run build` in
`dashboard` and serve `dashboard/dist` through a trusted static server. The
Flask development server is not a production server; keep the API private and
use a separately reviewed deployment boundary before network exposure. See
[`docs/API_AUTHENTICATION.md`](docs/API_AUTHENTICATION.md).

## Run the demo agent

Direct (no monitoring — Phase 1 mode):
```bash
python agent/demo_agent.py
```
Expected: a benign session (read → search → report) followed by a path-traversal probe that gets
rejected.

Through the AgentSentry proxy (Phase 2 — monitored, logged to `agentsentry.db`):
```bash
python agent/demo_agent.py --proxy
```
Expected: identical session output, but every call is now logged. Inspect the log:
```bash
python -c "from core.telemetry import get_session_calls, DB_PATH; import sqlite3; c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; [print(dict(r)) for r in c.execute('SELECT tool_name, arguments_json, is_error, duration_ms FROM tool_calls')]"
```

You can also run the proxy standalone against any MCP server:
```bash
python -m core.proxy --agent-id my-agent -- python mcp_lab/file_tools_server.py
```

## Run the tests

Run the backend tests from the project root:

```powershell
.\venv\Scripts\python.exe -m pytest tests/ -q
```

Run dashboard checks from `dashboard`:

```powershell
npm ls
npm audit
npx tsc --noEmit
npm run build
```

The reproducible synthetic detection benchmark writes
[`docs/DETECTION_BENCHMARK.md`](docs/DETECTION_BENCHMARK.md):

```powershell
.\venv\Scripts\python.exe scripts\evaluate_detection.py
```

The additive SQLite index migration makes a verified timestamped backup
before changing indexes. See [`docs/DATABASE_OPTIMIZATION.md`](docs/DATABASE_OPTIMIZATION.md);
do not run it while the API or another writer is active.

## Project structure

```
agentsentry/
├── api/                 # Flask read-only telemetry, review, and MCP inventory endpoints
├── core/                # MCP proxy, SQLite telemetry, risk and chain detection
├── dashboard/           # React + TypeScript + Vite dashboard
├── agent/               # Demo MCP client/agent
├── lab/                 # Synthetic scenarios and attack-chain test data
├── lab_files/           # Bundled lab-only data and simulation outbox
├── mcp_lab/             # Bundled MCP servers used by the demo and scenarios
├── scripts/             # Scenario runner and utility scripts
├── tests/               # Backend, API, security, and integration tests
├── docs/                # Security, integration, and release documentation
├── requirements.txt
└── agentsentry.db       # Runtime telemetry database (never replace or reset)
```

## Implemented surfaces

- Read-only Flask API for dashboard metrics, agents, sessions, assessments,
  session review, MCP servers, and tool-definition changes.
- React dashboard for overview, agents/sessions, investigation findings,
  topology, and MCP inventory.
- Lazy-loaded topology/Three.js modules; they are requested on Overview, not
  on the Sessions route.
- The test and lab coverage is synthetic and does not represent a production
  deployment certification. See the release-readiness document for measured
  checks and remaining findings.


## Phase 6 — Simulated attack lab

The repository includes five repeatable scenarios in `lab/scenarios/`:
A1 indirect prompt injection, A2 privilege escalation, A3 sensitive-data exfiltration,
A4 simulated MCP tool-definition rug pull, and B1 benign code review.

Run all scenarios through the actual stdio proxy:
```powershell
.\venv\Scripts\python.exe scripts\run_scenario.py --all
```
Run one scenario:
```powershell
.\venv\Scripts\python.exe scripts\run_scenario.py A3-exfil-chain-allowed-network
```

**Safety:** all attack effects are simulated. `http_request` appends a record to a local
outbox file and never opens a network connection. `shell_execute` and `sudo_command`
return canned text and never spawn processes. `delete_file` never deletes files.
The bundled lab `.env` contains fake credentials only. The scenario runner uses a
temporary database, but HTTP simulation steps append to `lab_files/outbox.log`;
preserve or isolate this file if its existing contents matter. Docker Compose uses
`network_mode: none`, drops capabilities, runs as non-root, and applies resource limits.

**A4 scope:** the vulnerable lab server dynamically replaces its advertised
`read_document` schema and sends the MCP
`notifications/tools/list_changed` notification. The proxy reconciles the
downstream tool list, persists the before/after definition, and the scenario
checks the resulting chain. This interoperability test uses synthetic lab
data; it is not evidence of production detection accuracy.

The attack lab is a controlled security simulation, not a real-world accuracy claim.

## Phase 10.2 — Generic MCP stdio clients

The AgentSentry proxy is independent of Gemini and can be launched as a
standard MCP stdio server by generic clients. See
[`docs/GENERIC_MCP_CLIENTS.md`](docs/GENERIC_MCP_CLIENTS.md) for a Python MCP
client and Claude Desktop configuration, explicit downstream environment
allowlisting, and supported protocol limitations.
