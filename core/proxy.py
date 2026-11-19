"""
AgentSentry — Phase 2 interception proxy.

This is the core piece that makes AgentSentry different from a static
scanner: it sits BETWEEN the agent and the real MCP server, transparently
passing every request through, while logging each tool call's name,
arguments, timing, and outcome to telemetry.py.

The agent is never aware it's talking to a proxy instead of the real
server — same tool list, same behavior, same results. The only difference
is that every call now has a permanent, ordered record.

Design choice: built on mcp.server.lowlevel.Server's on_list_tools /
on_call_tool hooks (NOT the high-level MCPServer decorator API), because
a proxy must forward an arbitrary, dynamically-discovered tool set —
it cannot know the downstream server's tools ahead of time the way
file_tools_server.py's static @server.tool() functions can.

Logging-before-returning ordering (see telemetry.py's docstring) means:
if the downstream call throws, we still log it as an error call. A tool
call that never gets logged is a blind spot, and a runtime security
monitor cannot have blind spots.

Run:
    python core/proxy.py --agent-id demo-code-reviewer -- python mcp_lab/file_tools_server.py

Pass downstream credentials by environment name, not argv:
    python core/proxy.py --agent-id api-client --pass-env SERVICE_TOKEN -- python server.py

Everything after `--` is the command to launch the real (downstream) MCP
server. The proxy itself speaks MCP over stdio to whatever connects to it
(e.g. demo_agent.py), exactly like the real server would.
"""

from __future__ import annotations

import argparse
import anyio
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from mcp import ClientSession, StdioServerParameters, stdio_client, stdio_server, types
from mcp.server import NotificationOptions
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.session import ServerSession
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler, ToolsListChanged
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from core.telemetry import DB_PATH, TelemetryStore


class AgentSentryProxy:
    """Transparent MCP proxy with tool-call telemetry logging."""

    def __init__(
        self,
        agent_id: str,
        downstream_command: str,
        downstream_args: list[str],
        db_path: Path | None = None,
        downstream_env: dict[str, str] | None = None,
    ):
        self.agent_id = agent_id
        child_env = dict(downstream_env or {})
        if "AGENTSENTRY_LAB_RUG_PULL_AFTER_CALLS" in os.environ:
            child_env["AGENTSENTRY_LAB_RUG_PULL_AFTER_CALLS"] = os.environ[
                "AGENTSENTRY_LAB_RUG_PULL_AFTER_CALLS"
            ]
        self.downstream_params = StdioServerParameters(
            command=downstream_command, args=downstream_args, env=child_env
        )
        self._sensitive_values = tuple(
            value for value in child_env.values() if value
        )
        # AGENTSENTRY_DB_PATH lets tests (running the proxy as a real subprocess)
        # redirect telemetry to a throwaway DB instead of the shared default —
        # a plain monkeypatch in the parent test process cannot reach a subprocess.
        resolved_db_path = db_path or Path(os.environ.get("AGENTSENTRY_DB_PATH", str(DB_PATH)))
        self.telemetry = TelemetryStore(agent_id=agent_id, db_path=resolved_db_path)
        self.downstream_session: ClientSession | None = None
        self.upstream_session: ServerSession | None = None
        self._subscriptions = InMemorySubscriptionBus()
        self._known_tool_definitions: dict[str, dict[str, Any]] = {}
        self._tool_change_condition = anyio.Condition()
        self._downstream_change_count = 0
        self._processed_change_count = 0

    async def _on_list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        assert self.downstream_session is not None
        self.upstream_session = ctx.session
        return await self.downstream_session.list_tools(params=params)

    async def _on_call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        assert self.downstream_session is not None
        self.upstream_session = ctx.session
        tool_name = params.name
        arguments: dict[str, Any] = params.arguments or {}

        async with self._tool_change_condition:
            pending_changes = self._downstream_change_count
            await self._tool_change_condition.wait_for(
                lambda: self._processed_change_count >= pending_changes
            )
            sequence_num = self.telemetry.reserve_call_sequence()

        start = time.perf_counter()
        is_error = False
        result_text = ""
        try:
            result = await self.downstream_session.call_tool(tool_name, arguments)
            async with self._tool_change_condition:
                pending_changes = self._downstream_change_count
                await self._tool_change_condition.wait_for(
                    lambda: self._processed_change_count >= pending_changes
                )
            is_error = bool(result.is_error)
            result_text = _extract_text(result)
            return result
        except Exception as exc:  # noqa: BLE001 — a downstream failure must still be logged
            is_error = True
            result_text = f"PROXY_CAUGHT_EXCEPTION: {type(exc).__name__}"
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=result_text)],
                is_error=True,
            )
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            self.telemetry.log_call(
                tool_name=tool_name,
                arguments=arguments,
                duration_ms=duration_ms,
                is_error=is_error,
                result_summary=result_text,
                sensitive_values=self._sensitive_values,
                sequence_num=sequence_num,
            )

    async def _on_downstream_message(self, message: types.ServerNotification | Exception) -> None:
        if isinstance(message, Exception):
            return
        if isinstance(message, types.ToolListChangedNotification):
            async with self._tool_change_condition:
                self._downstream_change_count += 1
                self._tool_change_condition.notify_all()
            return
        if isinstance(message, types.LoggingMessageNotification):
            if self.upstream_session is not None:
                await self.upstream_session.send_notification(message)

    async def _watch_downstream_changes(self) -> None:
        while True:
            async with self._tool_change_condition:
                await self._tool_change_condition.wait_for(
                    lambda: self._downstream_change_count > self._processed_change_count
                )
                target_count = self._downstream_change_count

            await self._reconcile_tool_definitions()

            async with self._tool_change_condition:
                self._processed_change_count = target_count
                self._tool_change_condition.notify_all()

    async def _reconcile_tool_definitions(self) -> None:
        updated_definitions = await self._fetch_tool_definitions()
        changes = _changed_tool_definitions(self._known_tool_definitions, updated_definitions)

        sequence_num = self.telemetry.call_count() + 0.5
        for tool_name, before, after in changes:
            self.telemetry.log_tool_definition_change(
                tool_name=tool_name,
                before_definition=before,
                after_definition=after,
                sequence_num=sequence_num,
            )
        self._known_tool_definitions = updated_definitions

        if self.upstream_session is None:
            raise RuntimeError("Cannot forward downstream tools/list_changed before an upstream request")
        if self.upstream_session.protocol_version in MODERN_PROTOCOL_VERSIONS:
            await self._subscriptions.publish(ToolsListChanged())
        else:
            await self.upstream_session.send_tool_list_changed()

    async def _fetch_tool_definitions(self) -> dict[str, dict[str, Any]]:
        assert self.downstream_session is not None
        tools: list[types.Tool] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
            result = await self.downstream_session.list_tools(params=params)
            tools.extend(result.tools)
            if result.next_cursor is None:
                return _tool_definitions(tools)
            if result.next_cursor in seen_cursors:
                raise RuntimeError("Downstream tools/list returned a repeated pagination cursor")
            seen_cursors.add(result.next_cursor)
            cursor = result.next_cursor

    async def run(self) -> None:
        server_registered = False
        try:
            async with stdio_client(self.downstream_params) as (down_read, down_write):
                async with ClientSession(
                    down_read, down_write, message_handler=self._on_downstream_message
                ) as down_session:
                    initialize_result = await down_session.initialize()
                    server_identity = initialize_result.server_info
                    if not server_identity.name.strip():
                        raise RuntimeError("Downstream MCP server supplied an empty identity")
                    self.telemetry.register_mcp_server(
                        server_name=server_identity.name,
                        transport="stdio",
                    )
                    server_registered = True
                    self.downstream_session = down_session
                    self._known_tool_definitions = await self._fetch_tool_definitions()

                    proxy_server = Server(
                        name="agentsentry-proxy",
                        description="AgentSentry runtime security proxy (transparent MCP passthrough + telemetry)",
                        on_list_tools=self._on_list_tools,
                        on_call_tool=self._on_call_tool,
                        on_subscriptions_listen=ListenHandler(self._subscriptions),
                    )

                    async with stdio_server() as (up_read, up_write):
                        async with anyio.create_task_group() as task_group:
                            task_group.start_soon(self._watch_downstream_changes)
                            try:
                                await proxy_server.run(
                                    up_read,
                                    up_write,
                                    proxy_server.create_initialization_options(
                                        notification_options=NotificationOptions(tools_changed=True)
                                    ),
                                )
                            finally:
                                task_group.cancel_scope.cancel()
        finally:
            try:
                if server_registered:
                    self.telemetry.disconnect_mcp_server()
            finally:
                self.telemetry.end_session()


def _extract_text(result: types.CallToolResult) -> str:
    parts = []
    for block in result.content or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return " | ".join(parts)


def _tool_definitions(tools: Sequence[types.Tool]) -> dict[str, dict[str, Any]]:
    return {
        tool.name: tool.model_dump(by_alias=True, mode="json", exclude_none=True)
        for tool in tools
    }


def _changed_tool_definitions(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[tuple[str, dict[str, Any] | None, dict[str, Any] | None]]:
    return [
        (name, before.get(name), after.get(name))
        for name in sorted(before.keys() | after.keys())
        if before.get(name) != after.get(name)
    ]


_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parse_args(argv: list[str]) -> tuple[str, str, list[str], dict[str, str]]:
    if "--" not in argv:
        raise SystemExit(
            "Usage: python core/proxy.py --agent-id <id> -- <downstream command> [args...]"
        )
    split_at = argv.index("--")
    proxy_argv, downstream_argv = argv[:split_at], argv[split_at + 1 :]

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument(
        "--pass-env",
        action="append",
        default=[],
        metavar="NAME",
        help="Explicitly pass this environment variable to the downstream MCP server",
    )
    parsed = parser.parse_args(proxy_argv)

    if not downstream_argv:
        raise SystemExit("No downstream command given after '--'")
    downstream_env: dict[str, str] = {}
    for name in parsed.pass_env:
        if not _ENV_NAME_RE.fullmatch(name):
            raise SystemExit(f"Invalid environment variable name for --pass-env: {name!r}")
        if name not in os.environ:
            raise SystemExit(f"Requested downstream environment variable is not set: {name}")
        downstream_env[name] = os.environ[name]
    return parsed.agent_id, downstream_argv[0], downstream_argv[1:], downstream_env


async def main_async() -> None:
    agent_id, cmd, cmd_args, downstream_env = _parse_args(sys.argv[1:])
    proxy = AgentSentryProxy(
        agent_id=agent_id,
        downstream_command=cmd,
        downstream_args=cmd_args,
        downstream_env=downstream_env,
    )
    await proxy.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main_async())
