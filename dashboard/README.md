# Dashboard (Phase 7, Member 2)

Pages: (1) session list with risk badges, (2) **session replay** — timeline of calls, flagged calls highlighted,
"WHY FLAGGED" panel from `RiskAssessment.why_flagged()`, attack chain drawn as steps, (3) agent baseline summary.

Rules: design around the analyst's workflow (what do they need first?), not a generic admin template.
Everything shown from a tool call is untrusted text -> escape it. Keep it server-rendered (Jinja) or a tiny JS
file that only uses `textContent`, never `innerHTML` with data.

## Phase 8 frontend foundation

The React + Vite + TypeScript frontend uses the Phase 7 read-only API. From this
directory, run `npm install` once and `npm run dev` to start the local Vite
development server at `http://127.0.0.1:5173`. Vite forwards `/api` requests to
the Flask API at `http://127.0.0.1:5000`; start the backend separately.

Run `npm run typecheck` for strict TypeScript validation and `npm run build` for
a production bundle. The overview includes a backend connection check; full
session and MCP views are planned for subsequent milestones. No telemetry or
sample records are created by the frontend.
