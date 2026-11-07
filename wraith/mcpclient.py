"""A minimal MCP client over Streamable HTTP, stdlib only.

Supports the JSON and the SSE response shapes, carries Mcp-Session-Id, and
gives up cleanly instead of hanging on a server that never answers.
"""
from __future__ import annotations

import json
import socket
import time
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "wraith", "version": "0.1.0"}


class MCPError(RuntimeError):
    """Raised when a target is not a reachable, speaking MCP endpoint."""


class MCPClient:
    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        headers: Optional[Dict[str, str]] = None,
        transcript: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self.protocol_version: Optional[str] = None
        self.server_info: Dict[str, Any] = {}
        self.capabilities: Dict[str, Any] = {}
        self._next_id = 0
        self._headers = {"User-Agent": "wraith/0.1.0", "Accept": "application/json, text/event-stream"}
        if headers:
            self._headers.update(headers)
        self.transcript: List[Dict[str, Any]] = transcript if transcript is not None else []

    # -- transport ---------------------------------------------------------
    def _request_headers(self) -> Dict[str, str]:
        headers = dict(self._headers)
        headers["Content-Type"] = "application/json"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return headers

    def _post(self, payload: Dict[str, Any], expect_reply: bool = True) -> Optional[Dict[str, Any]]:
        body = json.dumps(payload).encode()
        started = time.time()
        try:
            request = Request(self.url, data=body, headers=self._request_headers(), method="POST")
            with urlopen(request, timeout=self.timeout) as response:
                session = response.headers.get("Mcp-Session-Id")
                if session:
                    self.session_id = session
                content_type = (response.headers.get("Content-Type") or "").lower()
                raw = response.read()
        except HTTPError as error:
            detail = ""
            try:
                detail = error.read().decode("utf-8", "replace")[:200]
            except Exception:  # pragma: no cover - best effort
                pass
            raise MCPError(f"HTTP {error.code} from {self.url}: {detail or error.reason}") from error
        except (URLError, socket.timeout) as error:
            raise MCPError(f"cannot reach {self.url}: {getattr(error, 'reason', error)}") from error
        except OSError as error:
            raise MCPError(f"connection failed for {self.url}: {error}") from error
        except ValueError as error:
            raise MCPError(f"invalid target URL {self.url!r}: {error}") from error

        elapsed = round((time.time() - started) * 1000)
        entry = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request": payload,
            "http_status": 200,
            "elapsed_ms": elapsed,
            "content_type": content_type,
        }
        if not expect_reply or not raw:
            entry["response"] = None
            self.transcript.append(entry)
            return None

        message = self._parse_body(raw, content_type, payload.get("id"))
        entry["response"] = message
        self.transcript.append(entry)
        if message is None:
            return None
        if "error" in message:
            error = message["error"]
            raise MCPError(f"JSON-RPC error {error.get('code')}: {error.get('message')}")
        return message

    @staticmethod
    def _select(message: Any, want_id: Any) -> Optional[Dict[str, Any]]:
        """Pick our JSON-RPC object out of a single reply or a batched one."""
        if isinstance(message, dict):
            return message
        if isinstance(message, list):
            objects = [item for item in message if isinstance(item, dict)]
            for item in objects:
                if want_id is not None and item.get("id") == want_id:
                    return item
            return objects[0] if objects else None
        return None

    @staticmethod
    def _parse_body(raw: bytes, content_type: str, want_id: Any) -> Optional[Dict[str, Any]]:
        text = raw.decode("utf-8", "replace").strip()
        if not text:
            return None
        if "event-stream" in content_type or text.startswith("data:"):
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                chunk = line[5:].strip()
                if not chunk or chunk == "[DONE]":
                    continue
                try:
                    message = json.loads(chunk)
                except json.JSONDecodeError:
                    continue
                selected = MCPClient._select(message, want_id)
                if selected is None:
                    continue
                if want_id is None or selected.get("id") == want_id:
                    return selected
            return None
        try:
            message = json.loads(text)
        except json.JSONDecodeError as error:
            raise MCPError(f"target did not return JSON-RPC (content-type: {content_type})") from error
        selected = MCPClient._select(message, want_id)
        if selected is None:
            raise MCPError(f"target did not return JSON-RPC (content-type: {content_type})")
        return selected

    def _rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            payload["params"] = params
        message = self._post(payload)
        if message is None:
            raise MCPError(f"no response to {method}")
        return message.get("result") or {}

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._post(payload, expect_reply=False)

    # -- MCP surface -------------------------------------------------------
    def initialize(self) -> Dict[str, Any]:
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": False}},
                "clientInfo": CLIENT_INFO,
            },
        )
        self.protocol_version = result.get("protocolVersion") or PROTOCOL_VERSION
        self.server_info = result.get("serverInfo") or {}
        self.capabilities = result.get("capabilities") or {}
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        tools: List[Dict[str, Any]] = []
        cursor = None
        for _ in range(20):
            params = {"cursor": cursor} if cursor else {}
            result = self._rpc("tools/list", params)
            tools.extend([t for t in result.get("tools", []) if isinstance(t, dict)])
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})
