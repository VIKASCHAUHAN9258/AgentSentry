# SOC Demo Mode

SOC Demo Mode is an opt-in, localhost-only demonstration that writes synthetic
sessions to a dedicated database. It does not modify the live telemetry
database, user-account database, session secret, environment files, or model
artifacts.

## Enable and start locally

Open a PowerShell terminal at `D:\AGENT_SENTRY` and enable the mode for the
backend process:

```powershell
$env:AGENTSENTRY_DEMO_MODE = '1'
.\venv\Scripts\python.exe -m api.app
```

The existing API entry point binds to `127.0.0.1:5000`. Keep that localhost
binding for the demonstration. Start the dashboard in another PowerShell
terminal:

```powershell
Set-Location 'D:\AGENT_SENTRY\dashboard'
npm run dev -- --host 127.0.0.1
```

Open the Vite localhost URL in the terminal output, then sign in or create a
local analyst account using the existing sign-up/sign-in screen. Demo endpoints
use the existing authenticated session and CSRF protections. No API key is
needed.

The backend defaults to a separate demo database under
`%LOCALAPPDATA%\AgentSentry\demo\telemetry.sqlite3`. To choose another local
location, set `AGENTSENTRY_DEMO_DATA_DIR` before starting the API. The
deterministic detector reference models are fitted in memory; no model files
are written. The feature is disabled unless `AGENTSENTRY_DEMO_MODE=1` is set,
and demo endpoints reject non-loopback clients.

## Load and reset scenarios

Choose **SOC Demo Mode** in the dashboard sidebar. The page shows a
`SIMULATED DATA` banner and a backend-reported enabled/disabled indicator.

- **Load Demo Data** loads all four scenarios into one uniquely identified run.
- **Load scenario** on a scenario card loads only that scenario.
- Loading again replaces only the previous active demo run; it does not create
  an accumulating set of duplicate demo sessions.
- **Reset Demo Data** removes the displayed run's sessions, tool calls, and
  any demo review records from the dedicated demo database only.
- Investigation decisions are recorded using the existing session-review
  service, in the demo database. Resetting that run removes those decisions.

Each persisted call has a `SIMULATED` result marker containing its run,
scenario, and event identifiers. The session agent IDs begin with `demo-`.
Scenario timestamps and call intervals are fixed so repeated runs use
reproducible feature values. Run IDs remain unique.

## Scenarios

| Scenario | Agent ID | Synthetic activity and intended demonstration |
| --- | --- | --- |
| A · Normal Code Review Agent | `demo-code-reviewer` | Source-file and project-file read metadata, code searches, and a report. The configured read-only policy and detector are expected to assess this as normal when its measured features fit the synthetic reference baseline. |
| B · Research Assistant | `demo-research-assistant` | File reads, code searches, and ordinary HTTP request metadata. No outbound request is made. It demonstrates a multi-call session without a sensitive-read chain. |
| C · Suspicious File Access | `demo-suspicious-agent` | A synthetic `.env` path, repeated rapid searches, and `shell_execute` metadata. The file is not accessed and the command string is never run. |
| D · Suspicious Outbound Activity / Attack Chain | `demo-attack-chain` | Synthetic sensitive-read, transform, command-tool, and HTTP-tool records in one session. No file is read, command executed, request sent, or data exfiltrated. |

## What the backend actually evaluates

The load endpoint records calls with the existing `TelemetryStore` and the
existing `sessions` and `tool_calls` schema, but points it at the dedicated
demo database. The API then passes those stored rows through the existing
`extract_session_features`, policy evaluation, `BehaviorAnomalyDetector`,
`assess_session`, and `detect_chains` pipeline. Risk scores, feature
contributions, policy findings, supported chains, alert counts, and dashboard
metrics are calculated from those responses; the UI does not inject scores or
findings.

For the demo only, each scenario's Isolation Forest is fitted in memory using
40 deterministic benign synthetic sessions from `lab.synthetic`. This uses the
production detector class and its current scoring behavior, but it is a
synthetic reference baseline—not a trained production model or evidence of
real-world detection accuracy. It does not load or overwrite files in
`models/`.

The existing correlation engine supports sensitive-read-to-network,
read-to-execute, and post-change invocation of a tool definition. Scenarios C
and D can exercise the first two relationships from synthetic tool-call rows.
The demo does not generate tool-definition change events. MITRE references,
where shown by the engine, are investigative hints rather than attribution.
Feature-contribution z-scores are the detector's documented heuristic
explanations.

## 4–5 minute video sequence

1. **0:00–0:30 — Establish the environment.** Sign in, open **SOC Demo Mode**,
   and point out the enabled indicator, `SIMULATED DATA` warning, and separate
   demo-store notice.
2. **0:30–1:10 — Load repeatable data.** Select **Load Demo Data**. Show the
   backend-derived session, tool-call, agent, and alert counts and the unique
   run ID.
3. **1:10–1:50 — Normal code review.** Expand Scenario A. Walk through its
   session timeline, measured risk score, policy result, and detector output.
   Describe the result as a synthetic baseline comparison.
4. **1:50–2:25 — Research session.** Show Scenario B's file/search/HTTP tool
   metadata and clarify that the URL is synthetic and no network request was
   sent.
5. **2:25–3:20 — Suspicious access.** Open Scenario C's alert and evidence.
   Show the synthetic `.env` path and command-tool metadata, and clarify that
   neither operation touched the host.
6. **3:20–4:20 — Correlated chain and investigation.** Open Scenario D, trace
   the sensitive-read → execution/network sequence, inspect the returned
   chain IDs, evidence, and feature contributions, then record an approve or
   reject investigation decision in the isolated demo store.
7. **4:20–4:40 — Reset.** Select **Reset Demo Data** and show that the demo
   counts return to zero while the normal dashboard and account remain
   separate.

## Limitations

All records are synthetic. The demo does not execute MCP tools, call external
services, read host files, or create production alerts. Only the existing
policy rules and correlation relationships are demonstrated; no new detector
thresholds or chain definitions are added. Normal live-dashboard endpoints
continue to read only the configured live telemetry database and do not merge
demo metrics.
