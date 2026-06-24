"""
mcp_client.py — Datadog MCP Server subprocess manager
======================================================
Manages a long-lived `npx @datadog/mcp-server-datadog` subprocess using the
Anthropic MCP Python SDK (stdio transport).  Exposes:

  - DatadogMCPClient.list_tools()         → list available MCP tools
  - DatadogMCPClient.call_tool(name, args) → invoke a tool, returns JSON string
  - DatadogMCPClient as async context manager (handles subprocess lifecycle)

Every tool call is wrapped in a ddtrace span tagged as 'mcp.tool_call' so it
appears as a named child span inside the Datadog LLM trace waterfall.

Environment variables consumed (forwarded to the npx subprocess):
  DD_API_KEY   – Datadog API key          (required)
  DD_APP_KEY   – Datadog Application key  (required)
  DD_SITE      – Datadog site, default datadoghq.com
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

from ddtrace import tracer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP subprocess command
# ---------------------------------------------------------------------------
_MCP_COMMAND = "npx"
_MCP_ARGS    = ["-y", "@datadog/mcp-server-datadog"]

# ---------------------------------------------------------------------------
# Tool Selection Failure sentinel
# ---------------------------------------------------------------------------
_TOOL_FAILURE_PREFIX = "tool_selection_failure"


class MCPToolError(Exception):
    """Raised when the MCP server returns an error result for a tool call."""

    def __init__(self, tool_name: str, reason: str) -> None:
        super().__init__(f"Tool '{tool_name}' failed: {reason}")
        self.tool_name = tool_name
        self.reason    = reason


class DatadogMCPClient:
    """
    Async context-manager that owns one `npx @datadog/mcp-server-datadog`
    subprocess per instance lifetime.

    Usage:
        async with DatadogMCPClient() as client:
            tools   = await client.list_tools()
            result  = await client.call_tool("logs_list_events", {...})
    """

    def __init__(
        self,
        dd_api_key: str | None = None,
        dd_app_key: str | None = None,
        dd_site:    str | None = None,
    ) -> None:
        # Pull credentials from env if not passed explicitly
        self._dd_api_key = dd_api_key or os.environ.get("DD_API_KEY", "")
        self._dd_app_key = dd_app_key or os.environ.get("DD_APP_KEY", "")
        self._dd_site    = dd_site    or os.environ.get("DD_SITE", "datadoghq.com")

        self._session: ClientSession | None = None
        self._exit_stack_cm = None

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "DatadogMCPClient":
        await self._start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._stop()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _start(self) -> None:
        """Spawn the MCP subprocess and initialise the protocol session."""
        if not self._dd_api_key:
            raise EnvironmentError(
                "DD_API_KEY is not set. The Datadog MCP server requires it."
            )
        if not self._dd_app_key:
            raise EnvironmentError(
                "DD_APP_KEY is not set. The Datadog MCP server requires it."
            )

        # Build the env dict forwarded to the subprocess.
        # Only pass what the Datadog MCP server needs – never forward
        # AWS_* or other secrets to an external subprocess.
        subprocess_env = {
            **os.environ,                         # base: inherit PATH, HOME, etc.
            "DD_API_KEY": self._dd_api_key,
            "DD_APP_KEY": self._dd_app_key,
            "DD_SITE":    self._dd_site,
        }

        server_params = StdioServerParameters(
            command=_MCP_COMMAND,
            args=_MCP_ARGS,
            env=subprocess_env,
        )

        logger.info(
            "[MCP] Starting subprocess: %s %s (site=%s)",
            _MCP_COMMAND, " ".join(_MCP_ARGS), self._dd_site,
        )

        # stdio_client is itself an async context manager that owns the process
        self._exit_stack_cm = stdio_client(server_params)
        read_stream, write_stream = await self._exit_stack_cm.__aenter__()

        # Initialise the MCP protocol handshake
        self._session = ClientSession(read_stream, write_stream)
        await self._session.__aenter__()
        await self._session.initialize()

        logger.info("[MCP] Session initialised successfully.")

    async def _stop(self) -> None:
        """Gracefully tear down the MCP session and subprocess."""
        if self._session is not None:
            try:
                await self._session.__aexit__(None, None, None)
            except Exception as exc:
                logger.warning("[MCP] Error closing session: %s", exc)
            self._session = None

        if self._exit_stack_cm is not None:
            try:
                await self._exit_stack_cm.__aexit__(None, None, None)
            except Exception as exc:
                logger.warning("[MCP] Error terminating subprocess: %s", exc)
            self._exit_stack_cm = None

        logger.info("[MCP] Subprocess terminated.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def list_tools(self) -> list[dict]:
        """
        Return a list of available MCP tool descriptors.

        Each item is a dict with keys: name, description, inputSchema.
        Safe to call repeatedly – results are NOT cached because the server
        may update its tool manifest after credential validation.
        """
        self._assert_ready()

        with tracer.trace("mcp.list_tools", service="sre-agent-ecs") as span:
            response = await self._session.list_tools()
            tools = [
                {
                    "name":        t.name,
                    "description": t.description or "",
                    "inputSchema": t.inputSchema if hasattr(t, "inputSchema") else {},
                }
                for t in response.tools
            ]
            span.set_tag("mcp.tool_count", len(tools))
            logger.info("[MCP] %d tool(s) available.", len(tools))
            return tools

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        """
        Invoke an MCP tool and return its output as a JSON string.

        Wraps the call in a ddtrace span named 'mcp.tool_call'.
        Raises MCPToolError when the server signals an error result, so the
        caller can tag the span as 'tool_selection_failure' and return a
        structured error payload to Bedrock instead of crashing.

        Args:
            tool_name:  The exact MCP tool name, e.g. 'logs_list_events'.
            arguments:  Dict of arguments matching the tool's inputSchema.

        Returns:
            JSON string containing the tool output.
        """
        self._assert_ready()

        with tracer.trace(
            "mcp.tool_call",
            service="sre-agent-ecs",
            resource=tool_name,
        ) as span:
            span.set_tag("mcp.tool.name",  tool_name)
            span.set_tag("mcp.tool.input", json.dumps(arguments, default=str))
            span.set_tag("mcp.dd_site",    self._dd_site)

            logger.info("[MCP] Calling tool '%s' with args: %s", tool_name, arguments)

            try:
                result: CallToolResult = await self._session.call_tool(
                    tool_name, arguments=arguments
                )
            except Exception as exc:
                # Network / protocol level failure
                span.set_tag("tool.status", _TOOL_FAILURE_PREFIX)
                span.set_tag("error", True)
                span.set_tag("error.type",    type(exc).__name__)
                span.set_tag("error.message", str(exc))
                logger.error(
                    "[MCP] Protocol error calling '%s': %s", tool_name, exc
                )
                raise MCPToolError(tool_name, str(exc)) from exc

            # MCP result-level error (isError flag)
            if getattr(result, "isError", False):
                error_text = _extract_result_text(result) or "Unknown MCP error"
                span.set_tag("tool.status", _TOOL_FAILURE_PREFIX)
                span.set_tag("error", True)
                span.set_tag("error.message", error_text)
                logger.error(
                    "[MCP] Tool '%s' returned error: %s", tool_name, error_text
                )
                raise MCPToolError(tool_name, error_text)

            # Success path
            output_text = _extract_result_text(result)
            output_size = len(output_text.encode()) if output_text else 0
            span.set_tag("tool.status",             "success")
            span.set_tag("mcp.tool.output_bytes",   output_size)
            logger.info(
                "[MCP] Tool '%s' succeeded (%d bytes).", tool_name, output_size
            )
            return output_text

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_ready(self) -> None:
        if self._session is None:
            raise RuntimeError(
                "DatadogMCPClient is not started. "
                "Use it as 'async with DatadogMCPClient() as client:'"
            )


# ---------------------------------------------------------------------------
# Module-level convenience: async context manager factory
# ---------------------------------------------------------------------------

@asynccontextmanager
async def get_mcp_client() -> AsyncIterator[DatadogMCPClient]:
    """
    FastAPI dependency / context-manager factory.

    Usage in a route:
        async with get_mcp_client() as mcp:
            tools = await mcp.list_tools()
    """
    async with DatadogMCPClient() as client:
        yield client


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_result_text(result: CallToolResult) -> str:
    """
    Pull concatenated text from a CallToolResult.
    Handles both TextContent items and raw string content.
    """
    parts: list[str] = []
    for item in result.content:
        if isinstance(item, TextContent):
            parts.append(item.text)
        elif isinstance(item, str):
            parts.append(item)
        elif hasattr(item, "text"):
            parts.append(str(item.text))
        else:
            # Fallback: JSON-serialize non-text blocks (e.g. ImageContent)
            try:
                parts.append(json.dumps(item, default=str))
            except Exception:
                parts.append(str(item))
    return "\n".join(parts)
