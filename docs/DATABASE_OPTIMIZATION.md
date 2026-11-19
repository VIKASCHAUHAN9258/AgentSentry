# SQLite query indexes

The telemetry schema has additive indexes for session recency, sessions by
agent, recent calls, recent tool-definition changes, and per-session call
ordering. The per-session composite call index replaces the older
session-only index because its leading `session_id` column also supports
session-filtered lookups.

## Applying to an existing database

Stop Flask and any other process that writes telemetry before running the
migration. From the project root:

```powershell
.\venv\Scripts\python.exe scripts\optimize_database.py
```

The script refuses to overwrite an existing backup, creates a timestamped
sibling `.bak` using SQLite's backup API, verifies backup integrity and table
row counts, applies indexes in a transaction, checks query plans, then confirms
the live database row counts are unchanged. If verification fails, retain the
backup and investigate; do not reset or replace the telemetry database.

An alternate database can be selected with `--db PATH`; an explicit new backup
path can be supplied with `--backup PATH`. The existing telemetry rows are not
rewritten by this index-only migration.

## Applied to the current project database

The migration completed on 2026-11-18. It preserved these row counts:

| Table | Rows |
|---|---:|
| `sessions` | 3 |
| `tool_calls` | 8 |
| `tool_definition_events` | 0 |
| `mcp_servers` | 1 |
| `mcp_server_connections` | 2 |

Verified query plans use covering indexes for latest sessions and sessions by
agent, the composite index for calls by session, and timestamp indexes for
recent calls and tool changes. The retained backup is
`agentsentry.db.pre-indexes-20261118T084815Z.bak` in the project root.

The script is idempotent for index creation and does not overwrite that
existing backup. A later run generates a new timestamped backup.
