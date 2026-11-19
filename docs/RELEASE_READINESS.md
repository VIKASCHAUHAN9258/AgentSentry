# AgentSentry release readiness

## Assessment

**Not ready for internet-facing or untrusted multi-user deployment.** The
backend and dashboard changes are locally verified, API access now requires a
bearer key, and the existing SQLite database was backed up before additive
indexes were applied. However, npm still reports five HIGH findings for an
unpatched transitive ReDoS advisory, model artifacts use pickle-based
deserialization, and the Flask development server is not a production server.
Use only as a trusted local developer deployment until the outstanding
boundaries are addressed.

## Completed work

- Added required API-key authentication outside tests. The key must be at
  least 32 characters, is compared in constant time, and protects API routes
  except health and auth-status. CORS uses an explicit origin allowlist.
- Added a dashboard credential gate. The operator enters the API key; it is
  held in tab memory only, not bundled or persisted. Locking clears the key and
  query cache.
- Hardened model artifact handling with model-directory and artifact path
  checks, symbolic-link/Windows-junction rejection where supported, a 100 MiB
  size limit, schema/metadata validation, digest checking, and clearer
  deserialization errors. These checks do not make untrusted pickle files safe.
- Added `scripts/evaluate_detection.py` and generated the synthetic benchmark
  report. The evaluation uses a temporary isolated database and lab copy.
- Added SQLite performance indexes and an idempotent backup-before-migration
  utility. The current database was backed up, indexed, and verified without
  changing table row counts.
- Updated setup, API-authentication, model-security, database-optimization,
  dependency-security, and release-readiness documentation.

## Dependency status

### Dashboard

| Package | Installed |
|---|---:|
| Vite | `8.3.5` |
| `@vitejs/plugin-react` | `6.2.1` |
| `tinyglobby` | `0.2.17` |
| `fdir` | `6.5.0` |
| `picomatch` | `4.0.7` |

`npm ls` and the targeted dependency-tree check succeed with no invalid
dependency warnings. `npm audit` reports **5 HIGH findings**, all in the
transitive chain `vite → tinyglobby/fdir → picomatch`, for
[GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
(CVE-2026-112366). The GitHub advisory identifies versions through `4.0.7` as
affected and currently lists no first patched version. The configured official
npm registry publishes through `picomatch@4.0.7`; `picomatch@4.0.8` returns
E404. The audit's forced remediation proposes a breaking Vite downgrade to
`6.2.7`, so no forced downgrade or unverified override was applied. Recheck
the advisory and registry before future dependency updates. Keep the Vite
development server loopback-only and do not process untrusted project trees.

No frontend dependency manifests or lockfiles were changed.

### Python

`pip-audit -r requirements.txt` reports no known vulnerabilities.
`pip check` reports no broken requirements. No backend dependency upgrades
were needed for this work.

## Validation results

| Check | Result |
|---|---|
| Backend full suite, `.\venv\Scripts\python.exe -m pytest tests\ -q` | **143 passed, 5 skipped** |
| Focused auth/model/database/benchmark tests | **33 passed, 1 skipped** |
| Windows junction model-path regression test | **1 passed** |
| Python compile check | Passed |
| `npm ls` | Passed; no invalid dependency tree |
| Targeted Vite/transitive tree | Passed; confirms Vite `8.3.5`, plugin `6.2.1`, `picomatch@4.0.7`, `fdir@6.5.0`, `tinyglobby@0.2.17` |
| `npm audit` | **5 HIGH findings remain**, all from GHSA-fc5q-39xc-vjpf |
| `npx tsc --noEmit` | Passed |
| `npm run build` | Passed; Vite `8.3.5`, no chunk-size warning |
| `pip-audit -r requirements.txt` | No known vulnerabilities |
| `pip check` | No broken requirements |
| Live API checks | Health `200`; missing/invalid key `401`; valid key `200`; untrusted origin `403` |
| Production-browser check | API-key gate appeared; valid key opened Overview; dashboard Lock returned to the gate; local/session storage lengths were both `0`; Overview loaded topology/Three.js chunks |
| Live database and backup integrity | Both `PRAGMA integrity_check` results were `ok`; table row counts match |

The production bundle sizes were:

| Chunk | Size |
|---|---:|
| Main `index` | 346.43 kB |
| Lazy topology wrapper | 3.67 kB |
| Lazy topology scene | 6.07 kB |
| Three.js chunks | 190.20 kB + 352.56 kB |

The visualization remains deferred until the Overview topology is mounted.
Three.js vendor code still totals 542.76 kB for that visualization, but is not
part of the non-visualization route's initial requests. The production bundle
builds without increasing the chunk warning threshold.

The synthetic benchmark evaluated five scenarios (four attacks, one benign)
and reported 4 TP, 1 TN, 0 FP, 0 FN. Precision, recall, F1, and accuracy are
all 1.000 on that corpus only. Each attack category has a single scenario;
these values are not real-world detection estimates. See
[`DETECTION_BENCHMARK.md`](DETECTION_BENCHMARK.md).

## Database migration

`scripts/optimize_database.py` created and verified:
`agentsentry.db.pre-indexes-20261118T084815Z.bak`.

The applied migration preserved the observed row counts:

| Table | Rows |
|---|---:|
| `sessions` | 3 |
| `tool_calls` | 8 |
| `tool_definition_events` | 0 |
| `mcp_servers` | 1 |
| `mcp_server_connections` | 2 |

Query-plan checks confirmed the new covering/composite indexes were selected.
The migration adds indexes only; it does not delete or rewrite telemetry rows.
Keep the backup until the updated application has been verified against the
database.

## Findings and remaining limitations

1. **HIGH — unresolved picomatch ReDoS.** No fixed picomatch release is listed
   by the official advisory or available from the official npm registry at
   this verification point. Preserve Vite 8; do not force-downgrade or apply an
   unverified override.
2. **Shared-key scope.** API authentication is a local-operator control, not
   multi-user identity, role-based authorization, or production-ready secret
   rotation. Keep the API loopback-only.
3. **Pickle trust boundary.** Joblib can execute code during deserialization.
   Load models only from a trusted, write-restricted directory; the SHA-256
   sidecar is not a signature.
4. **Detection limits.** Risk and attack-chain signals are heuristics. The
   synthetic corpus is too small to estimate real-world performance, and
   baselines may be poisoned if untrusted activity is treated as benign.
5. **Scaling.** Risk and chain aggregation still evaluates stored sessions.
   Batched telemetry reads and request-scoped model caching reduce overhead,
   but large databases may increase API latency.
6. **Protocol boundary.** The stdio proxy does not proxy MCP resources,
   prompts, sampling, elicitation, or remote transports, and is not a sandbox
   for downstream MCP servers.
7. **Server boundary.** The documented Flask command uses Flask's development
   server. Do not expose it directly to a network.

See [`SECURITY.md`](SECURITY.md), [`API_AUTHENTICATION.md`](API_AUTHENTICATION.md),
and [`MODEL_SECURITY.md`](MODEL_SECURITY.md) for operational boundaries.

## Local startup

From `D:\AGENT_SENTRY`, with the existing virtual environment, database, and
private `.env` configured:

```powershell
.\venv\Scripts\python.exe -m flask --app api.app:create_app run --host 127.0.0.1 --port 5000
```

Set `AGENTSENTRY_API_KEY` in the environment or private `.env` first; it must
be a random value of at least 32 characters. To generate a fresh key in the
same PowerShell terminal without printing it:

```powershell
$env:AGENTSENTRY_API_KEY = (& .\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
```

In another terminal:

```powershell
Set-Location D:\AGENT_SENTRY\dashboard
npm run dev
```

Open `http://127.0.0.1:5173/` and enter the API key when prompted. Keep Flask
bound to loopback. Do not replace `.env` or reset/replace `agentsentry.db`.
Run the backend and dashboard checks from the commands in
[`README.md`](../README.md) before distributing a release.
