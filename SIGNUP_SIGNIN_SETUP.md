# AgentSentry: Sign-up and sign-in update

This patch replaces the browser API-key prompt with local user accounts.

## Apply the patch safely

1. Stop the currently running Flask backend and Vite frontend with `Ctrl+C` in
   their respective terminals.
2. Extract `AgentSentry_Signup_Signin_Patch.zip` into `D:\AGENT_SENTRY`.
3. When Windows asks, choose **Replace the files in the destination**.
4. Do not delete, replace, or move `agentsentry.db`. This patch does not alter
   telemetry records.

## Start AgentSentry

**Terminal 1 — backend**, from `D:\AGENT_SENTRY`:

```powershell
cd D:\AGENT_SENTRY
.\venv\Scripts\Activate.ps1
python -m api.app
```

The backend no longer requires `AGENTSENTRY_API_KEY` for browser sign-in. On
first start, it creates `.agentsentry_session_secret` once. The same secret is
reused after later restarts so the signed browser session remains valid.

**Terminal 2 — frontend**:

```powershell
cd D:\AGENT_SENTRY\dashboard
npm run dev
```

Open `http://127.0.0.1:5173/`.

## First use

1. Select **Create account** on the sign-in screen.
2. Enter your name, email and a password of at least 12 characters.
3. Select **Create account**. You will be signed in automatically.
4. On later visits use the same email and password with **Sign in**.
5. Use **Sign out** in the top bar when you want to end your session.

The browser session lasts up to seven days and is stored in an HTTP-only,
`SameSite=Lax` cookie. You should not need to paste or regenerate an API key
when restarting the application during that session.

## Local files to keep

- `.agentsentry_users.sqlite3` — account records and scrypt password hashes.
- `.agentsentry_session_secret` — persistent signing secret for browser sessions.
- `agentsentry.db` — existing AgentSentry telemetry database.

The user database is separate from the telemetry database. Keep all three
files in the project root and out of source control. Removing the user database
removes registered accounts; removing the session secret signs out existing
browser sessions. The sign-up/sign-in flow is intended for local loopback use,
not public internet deployment.

## Verify the update

From the project root:

```powershell
pytest tests -q
```

In another terminal:

```powershell
cd D:\AGENT_SENTRY\dashboard
npm run typecheck
npm run build
```
