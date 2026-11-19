# API authentication

The Flask API requires a bearer key for every `/api/*` route except
`/api/health` and `/api/auth/status`. `/api/auth/verify` is itself protected.
The key is read from `AGENTSENTRY_API_KEY`; application startup fails if it is
missing or shorter than 32 characters. Authentication cannot be disabled
outside explicit Flask test mode.

## Local setup

Set a randomly generated key in the process environment or in a private `.env`
file. For example, in PowerShell, generate a fresh key without printing it and
start Flask in the same terminal:

```powershell
$env:AGENTSENTRY_API_KEY = (& .\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
.\venv\Scripts\python.exe -m flask --app api.app:create_app run --host 127.0.0.1 --port 5000
```

The Flask CLI loads `.env` when `python-dotenv` is installed. Do not overwrite
an existing `.env`; keep the API key out of source control, logs, screenshots,
and support reports.

The dashboard asks the operator for this key, verifies it against the API, and
keeps it in JavaScript memory only. It is not compiled into the frontend and is
not written to local or session storage. Reloading the page requires entering
the key again. Locking the dashboard clears the in-memory key and React Query
cache. Public health/auth-status requests do not send the key.

## Browser origins and boundaries

`AGENTSENTRY_CORS_ORIGINS` is a comma-separated exact-origin allowlist. It
defaults to `http://127.0.0.1:5173,http://localhost:5173`. Configure it to
include only trusted dashboard origins. Wildcard origins are not used.
Requests carrying an origin outside the list are rejected; preflight requests
are handled before bearer authentication, while actual protected requests still
require the key.

The API binds to loopback in the documented development command. Bearer-key
authentication is a local-operator boundary, not a multi-user identity,
role-based authorization, or production deployment design. Do not expose the
Flask development server directly to an untrusted network. A networked
deployment needs a separately reviewed TLS, identity, authorization, secret
rotation, and operational logging design.

## Checks

The API tests cover missing, invalid, and valid credentials, public endpoints,
production startup configuration, and CORS allow/deny and preflight behavior.
