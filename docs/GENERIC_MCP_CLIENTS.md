# Generic MCP clients through AgentSentry

AgentSentry's proxy is an MCP stdio server and does not depend on Gemini or
another model SDK. A client starts `core.proxy` as its MCP server process; the
proxy starts the configured downstream MCP server directly with an executable
and argv (never through a shell), forwards tool discovery/calls, records the
configured agent identity and observed downstream server, then closes the
downstream process when the client closes stdio.

The proxy currently forwards the MCP tool surface: initialize, `tools/list`,
`tools/call`, downstream `notifications/tools/list_changed`, and downstream
`notifications/message` logging notifications. Tool errors are returned as
MCP tool errors and recorded in telemetry; subprocess exceptions use a
redacted type-only message. Stdio closure shuts down the downstream server and
closes the inventory connection. Inventory identifies the downstream server
from its initialize `serverInfo.name`; the upstream initialize response names
AgentSentry itself (`agentsentry-proxy`).

Resources, prompts, sampling, elicitation, server-to-client requests, and
non-tool capabilities are not currently proxied. Clients requiring those
features should connect directly to a server that implements them or use a
proxy version that explicitly supports those methods. Streamable HTTP and
remote MCP transports are also outside this stdio integration.

## Python MCP client

Install the project's pinned MCP SDK (`mcp==2.2.0`) in the client environment.
This example uses the standard Python SDK client independently of Gemini:

```python
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

root = Path(r"D:\AGENT_SENTRY")
params = StdioServerParameters(
    command=sys.executable,
    args=[
        "-m", "core.proxy",
        "--agent-id", "python-research-client",
        "--pass-env", "DOCS_API_TOKEN",
        "--",
        sys.executable, str(root / "mcp_lab" / "file_tools_server.py"),
    ],
    cwd=str(root),
    env={
        "PYTHONPATH": str(root),
        "AGENTSENTRY_DB_PATH": str(root / "agentsentry.db"),
        "DOCS_API_TOKEN": os.environ["DOCS_API_TOKEN"],
    },
)


async def main():
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            print([tool.name for tool in tools.tools])
            result = await session.call_tool("search_code", {"query": "TODO"})
            print(result)


asyncio.run(main())
```

Use an environment variable or platform secret store for tokens. `--pass-env`
allows only explicitly named variables into the downstream server; without it,
downstream servers receive the MCP SDK's safe default process environment and
the existing lab-only rug-pull setting. Passed values are never written to
proxy logs, telemetry arguments/results, or inventory. Avoid putting secrets in
command-line arguments because process listings may reveal them.

## Claude Desktop (Windows)

Merge an entry like this into Claude Desktop's `claude_desktop_config.json`,
replacing paths with the actual Python executable and checkout location:

```json
{
  "mcpServers": {
    "agentsentry-python-tools": {
      "command": "C:\\Users\\you\\AGENT_SENTRY\\venv\\Scripts\\python.exe",
      "args": [
        "-m", "core.proxy",
        "--agent-id", "claude-desktop",
        "--",
        "C:\\Users\\you\\AGENT_SENTRY\\venv\\Scripts\\python.exe",
        "C:\\Users\\you\\AGENT_SENTRY\\mcp_lab\\file_tools_server.py"
      ],
      "env": {
        "PYTHONPATH": "C:\\Users\\you\\AGENT_SENTRY",
        "AGENTSENTRY_DB_PATH": "C:\\Users\\you\\AGENT_SENTRY\\agentsentry.db"
      }
    }
  }
}
```

Restart Claude Desktop after changing its configuration. Claude's MCP stdio
configuration supplies command, argument array, and environment values, which
map to the proxy CLI. If a downstream server needs a credential, put it in
Claude's `env` object and explicitly add `"--pass-env", "VARIABLE_NAME"` before
the `"--"` separator. Do not put credentials in the downstream argv.

Claude Desktop does not provide a portable `cwd` field in this configuration;
the example sets `PYTHONPATH` so Python can import `core.proxy`. This does not
change the downstream executable or grant it shell access. The bundled
`file_tools_server.py` remains confined to `lab_files` and preserves its path
traversal/symlink checks. A different downstream server retains that server's
own security boundary; routing it through AgentSentry adds telemetry, not a
sandbox or authorization policy.

Only servers actually initialized behind the proxy appear in `/api/mcp/servers`.
`--agent-id` becomes the session identity used for inventory associations.
