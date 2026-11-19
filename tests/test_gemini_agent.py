from types import SimpleNamespace
import pytest

from agent.gemini_agent import AgentError, validate_tool_call, _validate


def make_tool(name="read_file"):
    return SimpleNamespace(
        name=name,
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    )


def test_valid_tool_call():
    assert validate_tool_call("read_file", {"path": "README.md"}, {"read_file": make_tool()}) == {"path": "README.md"}


def test_unknown_tool_rejected():
    with pytest.raises(AgentError, match="not permitted"):
        validate_tool_call("exec", {}, {"exec": make_tool("exec")})


def test_required_argument_enforced():
    with pytest.raises(AgentError, match="Missing required"):
        validate_tool_call("read_file", {}, {"read_file": make_tool()})


def test_extra_argument_rejected():
    with pytest.raises(AgentError, match="Unexpected argument"):
        validate_tool_call("read_file", {"path": "x", "cmd": "whoami"}, {"read_file": make_tool()})


def test_nested_array_items_validated():
    schema = {"type": "object", "properties": {"xs": {"type": "array", "items": {"type": "integer"}}}}
    _validate({"xs": [1, 2]}, schema)
    with pytest.raises(AgentError, match="expected integer"):
        _validate({"xs": [1, "bad"]}, schema)


def test_bool_is_not_integer():
    with pytest.raises(AgentError, match="expected integer"):
        _validate(True, {"type": "integer"})
