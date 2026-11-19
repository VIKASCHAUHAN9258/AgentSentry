"""Configurable AgentSentry demo MCP client.

Examples:
    python agent/demo_agent.py --proxy
    python agent/demo_agent.py --proxy --agent-id demo-code-reviewer --file benign_review.txt --query "input validation"
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

PROJECT_ROOT = Path(__file__).parent.parent
SERVER_SCRIPT = PROJECT_ROOT / "mcp_lab" / "file_tools_server.py"


def _direct_server_params() -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=[str(SERVER_SCRIPT)])


def _proxied_server_params(agent_id: str = "demo-code-reviewer", db_path: str | None = None) -> StdioServerParameters:
    env = os.environ.copy()
    if db_path:
        env["AGENTSENTRY_DB_PATH"] = db_path
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "core.proxy", "--agent-id", agent_id, "--", sys.executable, str(SERVER_SCRIPT)],
        cwd=str(PROJECT_ROOT),
        env=env,
    )


async def run_benign_session(
    server_params: StdioServerParameters | None = None,
    target_file: str = "notes.txt",
    query: str = "TODO",
) -> None:
    """Run a read/search/report workflow against a selected lab file."""
    server_params = server_params or _direct_server_params()
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"[agent] connected. available tools: {[t.name for t in tools.tools]}")

            print(f"[agent] calling read_file({target_file!r})")
            result = await session.call_tool("read_file", {"path": target_file})
            print(f"[agent] -> {result.content}")
            if result.is_error:
                raise RuntimeError(f"read_file failed for {target_file!r}")

            print(f"[agent] calling search_code({query!r})")
            result = await session.call_tool("search_code", {"query": query})
            print(f"[agent] -> {result.content}")
            if result.is_error:
                raise RuntimeError("search_code failed")

            summary = f"Reviewed {target_file}; searched for {query}; recorded routine code-quality observations."
            print("[agent] calling report(...)")
            result = await session.call_tool("report", {"summary": summary})
            print(f"[agent] -> {result.content}")
            if result.is_error:
                raise RuntimeError("report failed")


async def run_path_traversal_probe() -> None:
    server_params = _direct_server_params()
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print("[agent] probing path traversal: read_file('../../../etc/passwd')")
            result = await session.call_tool("read_file", {"path": "../../../etc/passwd"})
            print(f"[agent] -> {result.content}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a scripted AgentSentry MCP demo session")
    parser.add_argument("--proxy", action="store_true", help="route through AgentSentry proxy and record telemetry")
    parser.add_argument("--agent-id", default="demo-code-reviewer", help="telemetry agent ID when using --proxy")
    parser.add_argument("--db-path", help="optional telemetry DB path for isolated testing")
    parser.add_argument("--file", default="notes.txt", help="relative file inside lab_files to read")
    parser.add_argument("--query", default="TODO", help="substring to search with search_code")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    params = _proxied_server_params(args.agent_id, args.db_path) if args.proxy else _direct_server_params()
    if args.proxy:
        print("[agent] connecting THROUGH AgentSentry proxy (core/proxy.py)\n")
    else:
        print("[agent] connecting DIRECTLY to lab server (no monitoring) — pass --proxy to route through AgentSentry\n")
    asyncio.run(run_benign_session(params, target_file=args.file, query=args.query))
    if not args.proxy and args.file == "notes.txt":
        print("\n--- security smoke test ---")
        asyncio.run(run_path_traversal_probe())
