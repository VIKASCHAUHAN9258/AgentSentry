"""
AgentSentry — Phase 3 privilege registry.

Assigns every known tool a privilege level. This is the basis for the
privilege-escalation-distance feature: an agent whose session jumps from a
low-privilege tool (read a file) to a high-privilege one (execute a shell
command) is behaving very differently than one that only ever reads files,
even if each individual call looks "valid."

Levels (low to high):
    1 = READ       — read-only, no state change (read_file, search_code)
    2 = TRANSFORM  — local data transformation, no I/O beyond the call itself
                      (encode_data, decode_data) — flagged separately from
                      READ because transform steps are the middle link in the
                      documented "sensitive-read -> transform -> network"
                      exfiltration chain pattern.
    3 = NETWORK    — outbound communication (http_request, send_email)
    4 = EXECUTE    — arbitrary code/command execution or destructive file
                      ops (shell_execute, sudo_command, delete_file)

SECURITY DECISION: an unrecognized tool name defaults to level 3 (NETWORK),
not level 1. Defaulting unknown tools to the LOWEST privilege would let an
attacker (or a rug-pulled MCP server, see Phase 6) evade the
escalation-distance feature simply by calling something not in this
registry. Defaulting high is the conservative, secure choice — it may
produce false positives for legitimate new tools, which is an accepted
tradeoff and documented as a limitation, not hidden.

Some tool names below (shell_execute, http_request, encode_data,
sudo_command, delete_file) don't exist in mcp_lab/file_tools_server.py yet —
they're registered now because Phase 6's attack lab will introduce them, and
the feature-extraction logic should not need to change when that happens.
"""

from __future__ import annotations

from enum import IntEnum


class PrivilegeLevel(IntEnum):
    READ = 1
    TRANSFORM = 2
    NETWORK = 3
    EXECUTE = 4


UNKNOWN_TOOL_DEFAULT = PrivilegeLevel.NETWORK  # see SECURITY DECISION above

TOOL_PRIVILEGE_REGISTRY: dict[str, PrivilegeLevel] = {
    # Phase 1/2 lab tools (mcp_lab/file_tools_server.py) — currently exist
    "read_file": PrivilegeLevel.READ,
    "search_code": PrivilegeLevel.READ,
    "report": PrivilegeLevel.READ,
    # Phase 6 attack-lab tools (planned, not yet implemented) — registered
    # ahead of time so features.py doesn't change shape later
    "encode_data": PrivilegeLevel.TRANSFORM,
    "decode_data": PrivilegeLevel.TRANSFORM,
    "http_request": PrivilegeLevel.NETWORK,
    "send_email": PrivilegeLevel.NETWORK,
    "write_file": PrivilegeLevel.TRANSFORM,
    "delete_file": PrivilegeLevel.EXECUTE,
    "shell_execute": PrivilegeLevel.EXECUTE,
    "sudo_command": PrivilegeLevel.EXECUTE,
}


def privilege_of(tool_name: str) -> int:
    """Look up a tool's privilege level, defaulting unknown tools conservatively high."""
    return int(TOOL_PRIVILEGE_REGISTRY.get(tool_name, UNKNOWN_TOOL_DEFAULT))
