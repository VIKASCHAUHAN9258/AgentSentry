"""
Phase 1 tests: MCP plumbing + baseline security control.

Run:
    pytest tests/ -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters, stdio_client

SERVER_SCRIPT = Path(__file__).parent.parent / "mcp_lab" / "file_tools_server.py"


def _server_params() -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=[str(SERVER_SCRIPT)])


@pytest.mark.asyncio
async def test_server_lists_expected_tools():
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = {t.name for t in tools.tools}
            assert tool_names == {"read_file", "search_code", "report"}


@pytest.mark.asyncio
async def test_read_file_normal_flow():
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "notes.txt"})
            text = result.content[0].text
            assert "TODO" in text


@pytest.mark.asyncio
async def test_read_file_missing_file_returns_error_not_exception():
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "does_not_exist.txt"})
            text = result.content[0].text
            assert "ERROR" in text or "not found" in text.lower()


@pytest.mark.asyncio
async def test_path_traversal_is_blocked():
    """Security test: relative traversal outside the lab sandbox must fail."""
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "../../../etc/passwd"})
            text = result.content[0].text
            assert "traversal blocked" in text.lower() or "error" in text.lower()
            assert "root:" not in text  # never actually returned /etc/passwd contents


@pytest.mark.asyncio
async def test_absolute_path_is_blocked():
    """Security test: an absolute path attempt must also fail closed."""
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "/etc/passwd"})
            text = result.content[0].text
            assert "root:" not in text


@pytest.mark.asyncio
async def test_search_code_finds_known_match():
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool("search_code", {"query": "TODO"})
            text = result.content[0].text
            assert "notes.txt" in text
