# AgentSentry account authentication

The local dashboard uses account-based sign-up and sign-in. Browser users do
not need to paste `AGENTSENTRY_API_KEY` after every restart.

## Local accounts

- Create an account from the dashboard using a name, email address, and a
  password of at least 12 characters.
- Passwords are stored as Werkzeug `scrypt` password hashes. Plain-text
  passwords are never stored or returned by the API.
- Accounts live in `.agentsentry_users.sqlite3`, separate from the read-only
  telemetry database `agentsentry.db`.
- Successful sign-in creates a signed, HTTP-only, `SameSite=Lax` browser
  session cookie. Local sessions expire after seven days.
- The Flask cookie-signing secret is generated once in
  `.agentsentry_session_secret` and reused across backend restarts. Keep both
  local files out of source control and do not delete the secret file while
  active browser sessions need to remain valid.
- Sign out clears the browser session. The account itself remains available
  for the next sign-in.

The API exposes `GET /api/auth/status`, `POST /api/auth/signup`,
`POST /api/auth/login`, `POST /api/auth/logout`, and `GET /api/auth/verify`.
Mutating cookie-authenticated requests require a session-bound CSRF token.
The API accepts browser requests only from the exact origins configured in
`AGENTSENTRY_CORS_ORIGINS` (by default the two local Vite origins).

## Optional service bearer key

`AGENTSENTRY_API_KEY` remains an optional compatibility mechanism for trusted
non-browser clients that already use bearer authentication. It is not needed
for the React dashboard or ordinary local start-up. When configured, it must
contain at least 32 characters. Do not embed it in frontend code.

## Local start-up

From the project root in PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
python -m api.app
```

In a second terminal:

```powershell
cd dashboard
npm run dev
```

Open `http://127.0.0.1:5173/`, choose **Create account** for the first use,
and then use **Sign in** on later visits. No API key is pasted into the
browser. The local session and account database persist across restarts.

## Security boundary

The Flask development server binds to loopback in the documented command.
This account system is intended for a local development/demo environment. It
is not a reviewed public multi-tenant identity service. Do not expose the
Flask development server to an untrusted network. A networked deployment needs
TLS, registration controls, rate limiting, recovery flows, account lifecycle
management, and a separately reviewed operational security design.
