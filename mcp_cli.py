#!/usr/bin/env python3
"""
Qwen MCP CLI
============

Standalone Python CLI that connects to the deployed Remote MCP server at

    https://mcp-swart-pi.vercel.app/mcp

using the *Streamable HTTP* MCP transport (the transport that server
actually implements) and talks to its `qwen_chat` tool.

Why not `requests.get(url)` / a plain REST client?
---------------------------------------------------
The deployed server is built with the official MCP Python SDK's
`FastMCP(...).streamable_http_app()`, which is NOT a normal JSON REST API.
Per the MCP "Streamable HTTP" transport spec, POSTs to `/mcp` are only
accepted if the client's `Accept` header includes BOTH:

    Accept: application/json, text/event-stream

If a client omits `text/event-stream` (e.g. a naive `requests.post(url,
json=...)` call, which defaults to `Accept: */*`... actually the SDK
explicitly rejects the request unless `text/event-stream` is listed),
the server replies with the exact error this CLI was built to avoid:

    {"error": {"code": -32600, "message": "Not Acceptable: Client must
    accept text/event-stream"}}

The response body itself is then a `text/event-stream` SSE stream of
`event: message` / `data: <json-rpc>` frames (even for what is logically
a single response), so the client must parse SSE, not `resp.json()`.

This CLI therefore uses the OFFICIAL `mcp` Python SDK's own streamable-HTTP
client transport (`mcp.client.streamable_http.streamablehttp_client`) and
`mcp.ClientSession`, which:

  * sends the correct `Accept: application/json, text/event-stream` header,
  * performs MCP `initialize` + protocol version negotiation,
  * establishes/reuses the `Mcp-Session-Id` if the server issues one,
  * decodes SSE frames back into JSON-RPC responses,
  * exposes typed `session.list_tools()` / `session.call_tool()` helpers
    instead of hand-rolled JSON-RPC.

This is the same library the server is built with, so the wire format is
guaranteed to match on both ends.

Server-side note
-----------------
This server is deployed with `stateless_http=True`, so every request is
independent -- there is no server-side conversation memory tied to a
session. This CLI keeps conversation history locally and, if the
`qwen_chat` tool's discovered schema accepts a `messages` array, replays
the full history on every call so multi-turn context still works. No
change to the deployed server was needed or made.

Usage (Termux / any Python 3.10+ environment)
-----------------------------------------------
    pip install -r requirements.txt
    python mcp_cli.py
    python mcp_cli.py --debug          # verbose connection/protocol logs
    MCP_API_KEY=xxxx python mcp_cli.py # only if the server enforces one
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import timedelta
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

SERVER_URL = "https://mcp-swart-pi.vercel.app/mcp"
TARGET_TOOL_NAME = "qwen_chat"
HISTORY_LIMIT = 50  # matches MAX_MESSAGES on the server; keep local history in sync

logger = logging.getLogger("qwen-mcp-cli")


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Never print secret-bearing header values, even in --debug mode."""
    redacted = {}
    for k, v in headers.items():
        if k.lower() in ("authorization", "x-mcp-api-key", "cookie"):
            redacted[k] = "<redacted>"
        else:
            redacted[k] = v
    return redacted


def _build_auth_headers() -> dict[str, str]:
    """Build optional auth headers from MCP_API_KEY, if set.

    The deployed server's APIKeyAuthMiddleware only enforces this when
    MCP_API_KEY is configured server-side; if it's unset there, the server
    accepts unauthenticated requests and these headers are simply ignored.
    Never hard-code a key here -- always read it from the environment.
    """
    api_key = os.environ.get("MCP_API_KEY", "").strip()
    if not api_key:
        return {}
    return {"Authorization": f"Bearer {api_key}"}


def _extract_tool_text(result: Any) -> str:
    """Pull plain text out of an MCP CallToolResult.

    Tool results are a list of content blocks (text / image / resource).
    The qwen_chat tool returns a single string, which the SDK wraps as one
    TextContent block; join defensively in case of future multi-block
    responses.
    """
    if getattr(result, "isError", False):
        parts = [getattr(c, "text", str(c)) for c in result.content]
        raise RuntimeError("Tool call failed: " + " ".join(parts) or "unknown tool error")
    texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    return "\n".join(texts) if texts else ""


class QwenMCPClient:
    """Thin wrapper around an active MCP ClientSession for one CLI run."""

    def __init__(self, session: ClientSession, tool_schema: dict[str, Any], debug: bool):
        self.session = session
        self.tool_schema = tool_schema
        self.debug = debug
        # Does the discovered tool schema accept a "messages" array?
        props = tool_schema.get("properties", {}) if tool_schema else {}
        self.supports_messages = "messages" in props
        self.history: list[dict[str, str]] = []

    def reset(self) -> None:
        self.history = []

    async def send(self, user_text: str) -> str:
        self.history.append({"role": "user", "content": user_text})
        self.history = self.history[-HISTORY_LIMIT:]

        if self.supports_messages:
            arguments: dict[str, Any] = {"messages": self.history}
        else:
            # Tool only accepts a single message; history is kept locally
            # for /clear-style bookkeeping but only the latest turn is sent.
            arguments = {"message": user_text}

        if self.debug:
            logger.info("tools/call qwen_chat arguments=%s", json.dumps(arguments)[:500])

        result = await self.session.call_tool(TARGET_TOOL_NAME, arguments)

        if self.debug:
            logger.info("tools/call result isError=%s", getattr(result, "isError", False))

        answer = _extract_tool_text(result)
        self.history.append({"role": "assistant", "content": answer})
        self.history = self.history[-HISTORY_LIMIT:]
        return answer


def _print_banner(server_url: str, tool_names: list[str]) -> None:
    print("=" * 50)
    print("        QWEN MCP CLI")
    print("=" * 50)
    print(f"\nConnected to:\n{server_url}\n")
    print("Available tools:")
    for name in tool_names:
        print(f"- {name}")
    print()
    print("Commands: /tools  /reset  /clear  /exit\n")


def _print_tools(tools: list[Any]) -> None:
    for t in tools:
        print(f"- {t.name}: {t.description or '(no description)'}")


async def run_cli(debug: bool) -> int:
    logging.basicConfig(
        level=logging.INFO if debug else logging.WARNING,
        format="[%(levelname)s] %(message)s",
    )

    auth_headers = _build_auth_headers()
    if debug:
        logger.info("Connecting to %s", SERVER_URL)
        logger.info("Request headers: %s", _redact_headers(auth_headers))

    try:
        async with streamablehttp_client(
            SERVER_URL,
            headers=auth_headers or None,
        ) as (read_stream, write_stream, get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                if debug:
                    logger.info("Sending MCP initialize request...")

                init_result = await session.initialize()

                if debug:
                    logger.info(
                        "Initialized. protocolVersion=%s serverInfo=%s",
                        init_result.protocolVersion,
                        init_result.serverInfo,
                    )
                    session_id = get_session_id() if get_session_id else None
                    if session_id:
                        logger.info("Session established: mcp-session-id present")
                    else:
                        logger.info("Server did not issue an Mcp-Session-Id (stateless mode)")

                if debug:
                    logger.info("Calling tools/list...")

                tools_result = await session.list_tools()
                tools = tools_result.tools

                if debug:
                    logger.info("Discovered %d tool(s): %s", len(tools), [t.name for t in tools])

                target = next((t for t in tools if t.name == TARGET_TOOL_NAME), None)
                if target is None:
                    print(
                        f"Error: server did not expose a '{TARGET_TOOL_NAME}' tool. "
                        f"Available tools: {[t.name for t in tools]}"
                    )
                    return 1

                tool_schema = target.inputSchema or {}
                client = QwenMCPClient(session, tool_schema, debug)

                _print_banner(SERVER_URL, [t.name for t in tools])

                while True:
                    try:
                        user_text = input("You: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break

                    if not user_text:
                        continue

                    if user_text == "/exit":
                        break
                    if user_text == "/tools":
                        _print_tools(tools)
                        continue
                    if user_text in ("/reset", "/clear"):
                        client.reset()
                        print("(conversation history cleared)\n")
                        continue

                    try:
                        answer = await client.send(user_text)
                    except Exception as e:  # noqa: BLE001 - surface any tool/transport error to the user
                        print(f"Qwen: [error] {e}\n")
                        continue

                    print(f"Qwen: {answer}\n")

    except Exception as e:  # noqa: BLE001 - top-level connection failure
        print(f"Failed to connect to MCP server at {SERVER_URL}: {e}")
        if debug:
            logger.exception("Connection failure detail")
        return 1

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Qwen MCP CLI client")
    parser.add_argument(
        "--debug", action="store_true",
        help="Show connection/protocol debug info (never prints secrets).",
    )
    args = parser.parse_args()

    exit_code = asyncio.run(run_cli(args.debug))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
