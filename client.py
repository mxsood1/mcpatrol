"""
Lightweight MCP client for HTTP and Streamable-HTTP/SSE transports.

We don't use the official `mcp` SDK on purpose — we want raw control over
what's sent on the wire so we can probe edge cases and time individual calls.
"""

import json
import time
import asyncio
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

import httpx


class MCPClientError(Exception):
    pass


class MCPClient:
    """
    Minimal MCP client over HTTP. Supports the Streamable-HTTP transport which
    is what most modern MCP servers expose.
    """

    def __init__(self, url: str, headers: Optional[dict] = None, timeout: float = 30.0):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise MCPClientError(
                f"unsupported scheme '{parsed.scheme}' — provide an http:// or https:// URL"
            )
        self.url = url
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **(headers or {}),
        }
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self.headers,
            follow_redirects=True,
        )
        # MCP initialize handshake
        result = await self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcpatrol", "version": "0.1.0"},
        })
        self._server_info_cache = result
        # Spec requires an initialized notification right after initialize
        try:
            await self._notify("notifications/initialized", {})
        except Exception:
            pass  # not all servers care, don't fail audit on this

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_server_info(self) -> dict:
        return getattr(self, "_server_info_cache", {})

    async def list_tools(self) -> list:
        result = await self._rpc("tools/list", {})
        return result.get("tools", [])

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self._rpc("tools/call", {"name": name, "arguments": arguments})

    async def time_call(self, name: str, arguments: dict) -> tuple[float, Optional[dict], Optional[str]]:
        """Returns (elapsed_ms, result_or_None, error_or_None)."""
        start = time.perf_counter()
        try:
            result = await self._rpc("tools/call", {"name": name, "arguments": arguments})
            return (time.perf_counter() - start) * 1000, result, None
        except Exception as e:
            return (time.perf_counter() - start) * 1000, None, str(e)

    # --- internals ---

    async def _rpc(self, method: str, params: dict) -> dict:
        if self._client is None:
            raise MCPClientError("client not connected")

        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
        }
        headers = {}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        try:
            resp = await self._client.post(self.url, json=payload, headers=headers)
        except httpx.HTTPError as e:
            raise MCPClientError(f"network error: {e}") from e

        # Capture session id from initialize response if server provides one
        if "Mcp-Session-Id" in resp.headers and not self.session_id:
            self.session_id = resp.headers["Mcp-Session-Id"]

        if resp.status_code >= 400:
            raise MCPClientError(f"HTTP {resp.status_code}: {resp.text[:200]}")

        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            # SSE response — find the first JSON-RPC message in the stream
            data = self._parse_sse_response(resp.text)
        else:
            try:
                data = resp.json()
            except Exception as e:
                raise MCPClientError(f"non-JSON response: {resp.text[:200]}") from e

        if "error" in data:
            err = data["error"]
            raise MCPClientError(f"RPC error {err.get('code')}: {err.get('message')}")

        return data.get("result", {})

    async def _notify(self, method: str, params: dict) -> None:
        if self._client is None:
            return
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        headers = {}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        try:
            await self._client.post(self.url, json=payload, headers=headers)
        except Exception:
            pass

    @staticmethod
    def _parse_sse_response(text: str) -> dict:
        """Pull the first JSON-RPC message out of an SSE stream."""
        for line in text.splitlines():
            if line.startswith("data:"):
                data_str = line[5:].strip()
                if not data_str:
                    continue
                try:
                    return json.loads(data_str)
                except json.JSONDecodeError:
                    continue
        raise MCPClientError(f"no JSON-RPC message in SSE response: {text[:200]}")
