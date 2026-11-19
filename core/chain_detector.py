"""Phase 5: data-driven correlation of multi-call MCP attack chains.

A tool call can be individually permitted while its position in a sequence is
malicious. This module correlates ordered telemetry rows without changing the
Phase 2 telemetry schema.

Contract: ``detect_chains(rows) -> list[AttackChain]``. ``rows`` may contain
sqlite3.Row objects or ordinary mappings as returned by telemetry.

The matcher permits up to ``max_gap_calls`` unrelated calls between adjacent
steps. Failed calls are intentionally retained: an attempted attack is still
security-relevant even when a downstream tool blocks it.

MITRE mappings are investigative hints, not proof of attribution:
* T1005 — Data from Local System
* T1041 — Exfiltration Over C2 Channel
* T1059 — Command and Scripting Interpreter
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from core.privilege import PrivilegeLevel, privilege_of


@dataclass(frozen=True)
class AttackChain:
    chain_id: str
    severity: str                 # HIGH or CRITICAL
    call_indices: list[int]       # 0-based positions in the supplied rows
    description: str
    mitre_hint: str = ""


@dataclass(frozen=True)
class ChainDefinition:
    chain_id: str
    severity: str
    description: str
    steps: list[Callable[[Mapping[str, Any]], bool]] = field(default_factory=list)
    max_gap_calls: int = 3
    mitre_hint: str = ""


def _normalise_path(value: str) -> str:
    value = value.strip().strip('"\'`').replace("\\", "/").lower()
    while "//" in value:
        value = value.replace("//", "/")
    return value


_SENSITIVE_EXACT_NAMES = {
    ".env", ".env.local", ".env.production", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
    "credentials", "credentials.json", "secrets", "secrets.json",
    "token", "tokens", "password", "passwd", "shadow", "private_key",
}
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore")
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|[._-])(credentials?|secrets?|tokens?|passwords?|api[_-]?keys?|private[_-]?keys?)(?:$|[._-])",
    re.IGNORECASE,
)


def is_sensitive_path(path: str) -> bool:
    """Return whether a path/name points at a likely secret or private credential.

    The check is deliberately conservative and name-based; it can flag benign
    files named ``token.txt`` and cannot identify secrets stored under arbitrary
    names. It never reads the referenced file.
    """
    if not isinstance(path, str) or not path.strip():
        return False
    value = _normalise_path(path)
    # Strip query/fragment for URL-like resource identifiers without treating
    # the URL host itself as a filesystem path.
    value = value.split("?", 1)[0].split("#", 1)[0]
    segments = [part for part in value.split("/") if part not in ("", ".")]
    if not segments:
        return False
    for segment in segments:
        name = segment.rsplit("/", 1)[-1]
        if name in _SENSITIVE_EXACT_NAMES:
            return True
        if name.startswith(".env.") or name == ".env":
            return True
        if name.endswith(_SENSITIVE_SUFFIXES):
            return True
        if _SENSITIVE_NAME_RE.search(name):
            return True
    return value == "/etc/shadow" or value.endswith("/etc/shadow")


def _arguments(row: Mapping[str, Any]) -> dict[str, Any]:
    raw = row.get("arguments_json", "{}")
    if isinstance(raw, Mapping):
        return dict(raw)
    try:
        parsed = json.loads(raw or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _walk_values(value: Any):
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_values(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_values(child)


def _sensitive_read(row: Mapping[str, Any]) -> bool:
    if privilege_of(str(row.get("tool_name", ""))) != int(PrivilegeLevel.READ):
        return False
    args = _arguments(row)
    # Inspect path-like fields first, then nested string values. Restricting the
    # initial keys avoids matching an incidental mention in a search query.
    path_keys = {"path", "file", "filename", "filepath", "resource", "resource_uri", "uri"}
    for key, value in _walk_values(args):
        if isinstance(value, str) and (key.lower() in path_keys or is_sensitive_path(value)):
            if is_sensitive_path(value):
                return True
    return False


def _read_call(row: Mapping[str, Any]) -> bool:
    return privilege_of(str(row.get("tool_name", ""))) == int(PrivilegeLevel.READ)


def _network_call(row: Mapping[str, Any]) -> bool:
    return privilege_of(str(row.get("tool_name", ""))) == int(PrivilegeLevel.NETWORK)


def _execute_call(row: Mapping[str, Any]) -> bool:
    return privilege_of(str(row.get("tool_name", ""))) == int(PrivilegeLevel.EXECUTE)


CHAIN_DEFINITIONS: tuple[ChainDefinition, ...] = (
    ChainDefinition(
        chain_id="sensitive_read_to_network",
        severity="HIGH",
        description=(
            "A sensitive local resource was read and a subsequent network-capable "
            "tool was invoked in the same session (possible data exfiltration)."
        ),
        steps=[_sensitive_read, _network_call],
        max_gap_calls=3,
        mitre_hint="T1005 (Data from Local System); T1041 (Exfiltration Over C2 Channel)",
    ),
    ChainDefinition(
        chain_id="read_to_execute",
        severity="CRITICAL",
        description=(
            "A session progressed from a read operation to an execution-capable "
            "tool (possible privilege escalation or command execution)."
        ),
        steps=[_read_call, _execute_call],
        max_gap_calls=3,
        mitre_hint="T1059 (Command and Scripting Interpreter)",
    ),
)


def _match_definition(rows: Sequence[Mapping[str, Any]], definition: ChainDefinition) -> list[AttackChain]:
    if len(definition.steps) < 2:
        return []
    found: list[AttackChain] = []
    last_start = len(rows) - 1
    for start_index, row in enumerate(rows):
        if not definition.steps[0](row):
            continue
        indices = [start_index]
        previous = start_index
        matched = True
        for predicate in definition.steps[1:]:
            stop = min(len(rows), previous + definition.max_gap_calls + 2)
            next_index = next(
                (idx for idx in range(previous + 1, stop) if predicate(rows[idx])),
                None,
            )
            if next_index is None:
                matched = False
                break
            indices.append(next_index)
            previous = next_index
        if matched:
            found.append(AttackChain(
                chain_id=definition.chain_id,
                severity=definition.severity,
                call_indices=indices,
                description=definition.description,
                mitre_hint=definition.mitre_hint,
            ))
    return found


def detect_chains(rows) -> list[AttackChain]:
    """Detect every supported attack chain in ordered session telemetry.

    Accepts dict/sqlite3.Row-like rows. Input is copied to plain dictionaries
    and sorted by sequence_num when present; otherwise caller order is retained.
    Empty or malformed input safely returns an empty list.
    """
    if not rows:
        return []
    normalised: list[dict[str, Any]] = []
    for row in rows:
        try:
            normalised.append({key: row[key] for key in row.keys()})
        except (AttributeError, TypeError):
            if isinstance(row, Mapping):
                normalised.append(dict(row))
            else:
                continue
    if not normalised:
        return []
    if all(row.get("sequence_num") is not None for row in normalised):
        normalised.sort(key=lambda item: item["sequence_num"])

    chains: list[AttackChain] = []
    for definition in CHAIN_DEFINITIONS:
        chains.extend(_match_definition(normalised, definition))

    changed_at = [
        (idx, row) for idx, row in enumerate(normalised)
        if row.get("event_type") == "tool_definition_changed"
    ]
    for changed_index, event in changed_at:
        changed_tool = event.get("tool_name")
        if not isinstance(changed_tool, str):
            continue
        invocation_index = next(
            (
                idx for idx in range(changed_index + 1, len(normalised))
                if normalised[idx].get("event_type") != "tool_definition_changed"
                and normalised[idx].get("tool_name") == changed_tool
            ),
            None,
        )
        if invocation_index is not None:
            chains.append(AttackChain(
                chain_id="tool_definition_changed",
                severity="HIGH",
                call_indices=[changed_index, invocation_index],
                description="The MCP server tool definition changed during the session and was used afterward.",
                mitre_hint="",
            ))
    return chains
