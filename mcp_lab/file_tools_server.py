"""
AgentSentry — Phase 1 lab MCP server.

A minimal, intentionally-simple MCP server exposing three tools that a
"CodeReviewer" style agent would normally use:

    read_file(path)      -> read a text file's contents
    search_code(query)   -> naive substring search across the lab sandbox
    report(summary)      -> record a final summary (terminal tool)

SECURITY NOTE (Phase 1 scope):
All file access is confined to LAB_ROOT. Path traversal, absolute paths,
and symlink escapes are rejected before the filesystem is ever touched.
This is deliberately built in now (not bolted on later) because Phase 6
will point malicious agent behavior at this exact server, and the base
server itself must not be the vulnerability.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

LAB_ROOT = Path(__file__).parent.parent / "lab_files"
LAB_ROOT.mkdir(exist_ok=True)

server = MCPServer(
    name="agentsentry-lab-file-tools",
    description="Lab MCP server (file/code tools) used to build and test AgentSentry.",
)


def _resolve_safe_path(user_path: str) -> Path:
    """Resolve user_path against LAB_ROOT, rejecting any escape attempt.

    Raises ValueError instead of returning a possibly-unsafe path, so
    every caller is forced to handle the rejection explicitly.
    """
    candidate = (LAB_ROOT / user_path).resolve()
    lab_root_resolved = LAB_ROOT.resolve()
    if lab_root_resolved not in candidate.parents and candidate != lab_root_resolved:
        raise ValueError(f"Path traversal blocked: '{user_path}' escapes the lab sandbox")
    if not str(candidate).startswith(str(lab_root_resolved)):
        raise ValueError(f"Path traversal blocked: '{user_path}' escapes the lab sandbox")
    return candidate


@server.tool()
def read_file(path: str) -> str:
    """Read a text file from the lab sandbox.

    Args:
        path: relative path inside the lab sandbox, e.g. "notes.txt"
    """
    try:
        safe_path = _resolve_safe_path(path)
    except ValueError as exc:
        raise ToolError("Path traversal blocked: requested file is outside the lab sandbox") from exc
    if not safe_path.exists() or not safe_path.is_file():
        return f"ERROR: file not found: {path}"
    try:
        return safe_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"ERROR: could not read file: {exc}"


@server.tool()
def search_code(query: str) -> str:
    """Search for a substring across every file in the lab sandbox.

    Args:
        query: text to search for
    """
    matches: list[str] = []
    for file_path in LAB_ROOT.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if query in text:
            rel = file_path.relative_to(LAB_ROOT)
            matches.append(str(rel))
    if not matches:
        return f"No matches for '{query}'"
    return "Matches:\n" + "\n".join(matches)


@server.tool()
def report(summary: str) -> str:
    """Record a final summary for the current session (terminal tool).

    Args:
        summary: the agent's final summary/output
    """
    return f"Report recorded ({len(summary)} chars)."


if __name__ == "__main__":
    server.run()
