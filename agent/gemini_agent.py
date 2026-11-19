"""Bounded Gemini MCP agent routed through the AgentSentry proxy."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

import anyio
from dotenv import load_dotenv
from google import genai
from google.genai import types as gtypes
from mcp import ClientSession, StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
AGENT_ID = "gemini-code-agent"
DEFAULT_MODEL = "gemini-flash-lite-latest"
ALLOWED_TOOLS = frozenset({"read_file", "search_code", "report"})
MAX_TOOL_CALLS = 8
logger = logging.getLogger("agentsentry.gemini_agent")


class AgentError(RuntimeError):
    """Safe, user-facing agent error."""


def _schema(tool: Any) -> dict[str, Any]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
    if schema is None and hasattr(tool, "model_dump"):
        dumped = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
        schema = dumped.get("inputSchema") or dumped.get("input_schema")
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        raise AgentError(f"Invalid MCP input schema for {getattr(tool, 'name', 'unknown')}")
    return schema


def mcp_tools_to_gemini(tools: Iterable[Any]) -> list[gtypes.FunctionDeclaration]:
    declarations = []
    for tool in tools:
        if getattr(tool, "name", None) not in ALLOWED_TOOLS:
            continue
        declarations.append(gtypes.FunctionDeclaration(
            name=tool.name,
            description=(getattr(tool, "description", None) or f"MCP tool {tool.name}")[:1024],
            parameters_json_schema=_schema(tool),
        ))
    return declarations


def _validate(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    checks = {
        "object": lambda x: isinstance(x, dict),
        "array": lambda x: isinstance(x, list),
        "string": lambda x: isinstance(x, str),
        "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
        "number": lambda x: isinstance(x, (int, float)) and not isinstance(x, bool),
        "boolean": lambda x: isinstance(x, bool),
        "null": lambda x: x is None,
    }
    kind = schema.get("type")
    if kind:
        if kind not in checks:
            raise AgentError(f"Unsupported schema type {kind!r} at {path}")
        if not checks[kind](value):
            raise AgentError(f"Invalid {path}: expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise AgentError(f"Invalid {path}: value is not in enum")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(props, dict) or not isinstance(required, list):
            raise AgentError(f"Malformed object schema at {path}")
        missing = [k for k in required if k not in value]
        if missing:
            raise AgentError(f"Missing required argument(s) at {path}: {', '.join(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise AgentError(f"Unexpected argument(s) at {path}: {', '.join(sorted(extra))}")
        for key, item in value.items():
            if key in props:
                if not isinstance(props[key], dict):
                    raise AgentError(f"Malformed schema for {path}.{key}")
                _validate(item, props[key], f"{path}.{key}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for i, item in enumerate(value):
            _validate(item, schema["items"], f"{path}[{i}]")


def validate_tool_call(name: str, args: Any, discovered: dict[str, Any]) -> dict[str, Any]:
    if name not in ALLOWED_TOOLS or name not in discovered:
        raise AgentError(f"Tool is not permitted: {name}")
    if not isinstance(args, dict):
        raise AgentError("Tool arguments must be a JSON object")
    _validate(args, _schema(discovered[name]))
    return args


def _result_json(result: Any) -> dict[str, Any]:
    out = {"isError": bool(getattr(result, "isError", False)), "content": []}
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text is not None:
            out["content"].append({"type": "text", "text": str(text)[:12000]})
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        out["structuredContent"] = structured
    return out


def _calls(response: Any) -> list[Any]:
    found = []
    for candidate in getattr(response, "candidates", None) or []:
        for part in getattr(getattr(candidate, "content", None), "parts", None) or []:
            call = getattr(part, "function_call", None)
            if call is not None and getattr(call, "name", None):
                found.append(call)
    return found


def _text(response: Any) -> str:
    value = getattr(response, "text", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    for candidate in getattr(response, "candidates", None) or []:
        for part in getattr(getattr(candidate, "content", None), "parts", None) or []:
            if getattr(part, "text", None):
                return part.text.strip()
    return ""


async def _generate(client: genai.Client, model: str, contents: list[Any], declarations: list[Any]) -> Any:
    config = gtypes.GenerateContentConfig(
        tools=[gtypes.Tool(function_declarations=declarations)],
        automatic_function_calling=gtypes.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.2,
    )
    with anyio.fail_after(60):
        return await anyio.to_thread.run_sync(
            lambda: client.models.generate_content(model=model, contents=contents, config=config)
        )


async def run_task(
    task: str,
    *,
    db_path: str | None = None,
    required_tool_sequence: Sequence[str] | None = None,
) -> dict[str, Any]:
    if not task.strip():
        raise AgentError("Task cannot be empty")
    if required_tool_sequence is not None and (
        not required_tool_sequence
        or any(name not in ALLOWED_TOOLS for name in required_tool_sequence)
    ):
        raise AgentError("Required tool sequence must contain permitted tools")
    load_dotenv(ROOT / ".env")
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise AgentError("GEMINI_API_KEY is missing from the project .env file")
    model = os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    child_env = os.environ.copy()
    child_env.pop("GEMINI_API_KEY", None)
    if db_path:
        child_env["AGENTSENTRY_DB_PATH"] = str(Path(db_path).resolve())

    client = genai.Client(api_key=key)
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "core.proxy", "--agent-id", AGENT_ID, "--",
            sys.executable, str(ROOT / "mcp_lab" / "file_tools_server.py"),
        ],
        cwd=str(ROOT),
        env=child_env,
    )
    calls_made = 0
    final_result: dict[str, Any] | None = None
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            discovered_result = await session.list_tools()
            tools = {t.name: t for t in discovered_result.tools if t.name in ALLOWED_TOOLS}
            declarations = mcp_tools_to_gemini(discovered_result.tools)
            if not declarations:
                raise AgentError("Proxy exposed no permitted sandbox MCP tools")

            contents: list[Any] = [
                "You are a constrained AgentSentry assistant. Use only the supplied sandbox tools. "
                "Never claim success without tool evidence. Do not attempt shell execution, arbitrary "
                "code execution, arbitrary filesystem access, or external network access.\n\n"
                f"Task:\n{task}"
            ]
            while True:
                try:
                    response = await _generate(client, model, contents, declarations)
                except TimeoutError as exc:
                    raise AgentError("Gemini request timed out") from exc
                except Exception as exc:
                    logger.exception("Gemini request failed")
                    raise AgentError(f"Gemini request failed ({type(exc).__name__})") from exc

                function_calls = _calls(response)
                if not function_calls:
                    if (
                        required_tool_sequence is not None
                        and calls_made != len(required_tool_sequence)
                    ):
                        raise AgentError("Gemini did not complete the required tool sequence")
                    answer = _text(response)
                    if not answer:
                        raise AgentError("Gemini returned no text or function call")
                    final_result = {
                        "status": "completed",
                        "agent_id": AGENT_ID,
                        "model": model,
                        "tool_calls": calls_made,
                        "response": answer,
                    }
                    break

                candidates = getattr(response, "candidates", None) or []
                model_content = getattr(candidates[0], "content", None) if candidates else None
                if model_content is not None:
                    contents.append(model_content)

                responses = []
                for call in function_calls:
                    if required_tool_sequence is not None and (
                        calls_made >= len(required_tool_sequence)
                        or str(call.name) != required_tool_sequence[calls_made]
                    ):
                        raise AgentError("Gemini requested a tool outside the required sequence")
                    if calls_made >= MAX_TOOL_CALLS:
                        raise AgentError(f"Maximum tool-call limit ({MAX_TOOL_CALLS}) reached")
                    args = getattr(call, "args", {}) or {}
                    if hasattr(args, "model_dump"):
                        args = args.model_dump(exclude_none=True)
                    valid_args = validate_tool_call(str(call.name), args, tools)
                    try:
                        with anyio.fail_after(30):
                            result = await session.call_tool(str(call.name), valid_args)
                        payload = _result_json(result)
                    except TimeoutError:
                        payload = {"isError": True, "error": "MCP tool timed out"}
                    except Exception as exc:
                        logger.exception("MCP tool call failed: %s", call.name)
                        payload = {"isError": True, "error": f"Tool failed ({type(exc).__name__})"}
                    calls_made += 1
                    responses.append(gtypes.Part.from_function_response(
                        name=str(call.name), response={"result": payload}
                    ))
                contents.append(gtypes.Content(role="user", parts=responses))

    if final_result is None:
        raise RuntimeError("Gemini task exited without a result")
    return final_result


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gemini agent through AgentSentry MCP proxy")
    parser.add_argument("--task", help="Natural-language task")
    parser.add_argument(
        "--db-path",
        help="Telemetry database path (defaults to the AgentSentry production database)",
    )
    return parser.parse_args()


async def _main() -> int:
    args = _args()
    task = args.task or input("AgentSentry task> ").strip()
    try:
        result = await run_task(task, db_path=args.db_path)
    except AgentError as exc:
        print(f"AgentSentry error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("AGENTSENTRY_LOG_LEVEL", "WARNING"))
    raise SystemExit(asyncio.run(_main()))
