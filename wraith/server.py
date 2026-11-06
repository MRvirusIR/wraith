"""Wraith as an MCP server (stdio transport).

This is the distribution trick that matters in 2026: an agent can drive the
whole hunt. Claude Code, Cursor or any MCP client adds one line to its config
and gets scope checking, probing, drift detection and report generation as
tools.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from wraith import __version__, evidence, report, rulebook, rules, scope, store
from wraith.findings import Finding, dedupe, summarize
from wraith.mcpclient import MCPClient, MCPError

SERVER_INFO = {"name": "wraith", "version": __version__}
PROTOCOL_VERSION = "2025-06-18"

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "wraith_scope_check",
        "description": (
            "Check whether a URL is inside an authorised bug bounty scope before touching it. "
            "Always call this before probing a new host."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Target URL or host"}},
            "required": ["url"],
        },
    },
    {
        "name": "wraith_probe",
        "description": (
            "Probe an MCP endpoint: connect, list tools, and analyse the definitions for tool "
            "poisoning, hidden unicode, credential references, egress sinks, capability "
            "mismatches, schema weaknesses and shadowing. Writes an evidence bundle."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "MCP endpoint, e.g. https://host/mcp"},
                "timeout": {"type": "number", "description": "Per-request timeout in seconds", "default": 10},
                "diff": {"type": "boolean", "description": "Also report drift against the last pin", "default": True},
                "evidence_dir": {"type": "string", "default": "runs"},
                "i_own_this_target": {
                    "type": "boolean",
                    "description": "Bypass the scope check. Only for targets you own or lab servers.",
                    "default": False,
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "wraith_analyze",
        "description": "Analyse a tools/list JSON payload offline (no network) and return findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tools_json": {"type": "string", "description": "JSON string: {\"tools\": [...]} or a list of tools"},
                "target": {"type": "string", "default": "pasted"},
            },
            "required": ["tools_json"],
        },
    },
    {
        "name": "wraith_pin",
        "description": "Pin the current tool definitions of a target so later drift can be detected.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "i_own_this_target": {"type": "boolean", "default": False},
            },
            "required": ["url"],
        },
    },
    {
        "name": "wraith_diff",
        "description": "Compare a target's current tool definitions with its pin and report changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "i_own_this_target": {"type": "boolean", "default": False},
            },
            "required": ["url"],
        },
    },
    {
        "name": "wraith_report",
        "description": "Render or refresh the bounty-ready report.md for an evidence bundle directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_dir": {"type": "string"},
                "platform": {"type": "string", "enum": ["generic", "h1", "bugcrowd"], "default": "generic"},
            },
            "required": ["run_dir"],
        },
    },
    {
        "name": "wraith_lab",
        "description": (
            "Describe how to start the built-in poisoned lab server for a safe, offline demo. "
            "Wraith never attacks third parties; the lab is the sanctioned target."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _text(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, str):
        payload = json.dumps(payload, indent=2, ensure_ascii=False)
    return {"content": [{"type": "text", "text": payload}]}


def _scope_or_raise(url: str, allow_any: bool) -> None:
    state = scope.load(scope.SCOPE_FILE)
    allowed, reason, _program = scope.check(url, state, allow_any)
    if not allowed:
        raise MCPError(f"out of scope: {reason}. Add it with `wraith scope add` or pass i_own_this_target=true.")


def call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "wraith_scope_check":
        state = scope.load(scope.SCOPE_FILE)
        allowed, reason, program = scope.check(str(arguments.get("url", "")), state)
        return _text({"allowed": allowed, "reason": reason, "program": program})

    if name == "wraith_probe":
        url = str(arguments["url"])
        allow_any = bool(arguments.get("i_own_this_target", False))
        _scope_or_raise(url, allow_any)
        client = MCPClient(url, timeout=float(arguments.get("timeout", 10)))
        transcript: List[Dict[str, Any]] = []
        client.transcript = transcript
        client.initialize()
        tools = client.list_tools()
        findings = rules.analyze_tools(tools, url)
        if arguments.get("diff", True):
            findings.extend(rules.drift(store.previous_hashes(store.load("."), url), tools, url))
        findings = dedupe(findings)
        meta = {
            "server": client.server_info,
            "protocol": client.protocol_version,
            "tool_count": len(tools),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        run_dir = evidence.create_run_dir(str(arguments.get("evidence_dir", "runs")), url)
        markdown = report.build(url, findings, meta)
        evidence.write_bundle(run_dir, url, tools, [f.to_dict() for f in findings], transcript, meta, markdown)
        return _text(
            {
                "target": url,
                "server": client.server_info,
                "tool_count": len(tools),
                "summary": summarize(findings),
                "findings": [f.to_dict() for f in findings],
                "evidence_dir": run_dir,
                "report": os.path.join(run_dir, "report.md"),
            }
        )

    if name == "wraith_analyze":
        raw = arguments.get("tools_json", "{}")
        data = json.loads(raw) if isinstance(raw, str) else raw
        tools = data.get("tools") if isinstance(data, dict) else data
        findings = dedupe(rules.analyze_tools(tools or [], str(arguments.get("target", "pasted"))))
        return _text({"summary": summarize(findings), "findings": [f.to_dict() for f in findings]})

    if name == "wraith_pin":
        url = str(arguments["url"])
        _scope_or_raise(url, bool(arguments.get("i_own_this_target", False)))
        client = MCPClient(url)
        client.initialize()
        tools = client.list_tools()
        data = store.load(".")
        record = store.pin(data, url, tools, rules.definition_hash)
        store.save(data, ".")
        return _text({"pinned": record})

    if name == "wraith_diff":
        url = str(arguments["url"])
        _scope_or_raise(url, bool(arguments.get("i_own_this_target", False)))
        previous = store.previous_hashes(store.load("."), url)
        client = MCPClient(url)
        client.initialize()
        tools = client.list_tools()
        findings = rules.drift(previous, tools, url)
        return _text({"summary": summarize(findings), "findings": [f.to_dict() for f in findings]})

    if name == "wraith_report":
        run_dir = str(arguments["run_dir"])
        findings_path = os.path.join(run_dir, "findings.json")
        with open(findings_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        findings = [
            Finding(
                rule=item["rule"],
                severity=item["severity"],
                title=item["title"],
                target=item["target"],
                detail=item["detail"],
                location=item.get("location", ""),
                tool=item.get("tool"),
                evidence=item.get("evidence", ""),
                remediation=item.get("remediation", ""),
                cwe=item.get("cwe"),
            )
            for item in raw
        ]
        target, meta = "unknown", {}
        target_path = os.path.join(run_dir, "target.json")
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            target = data.get("target", target)
            meta = data.get("meta", {})
        markdown = report.build(target, findings, meta, platform=str(arguments.get("platform", "generic")))
        path = os.path.join(run_dir, "report.md")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(markdown)
        evidence.manifest(run_dir)
        return _text({"report": path})

    if name == "wraith_lab":
        return _text(
            "Run `wraith lab --port 8787` in a terminal, then call wraith_probe on "
            "http://127.0.0.1:8787/mcp with i_own_this_target=true. The lab server is deliberately "
            "poisoned and safe to test against."
        )

    if name == "wraith_rules":
        return _text([{"rule": r, "description": d} for r, d in rulebook.CATALOG])

    raise MCPError(f"unknown tool: {name}")


def handle(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        try:
            result = call_tool(str(params.get("name")), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except MCPError as error:
            return {"jsonrpc": "2.0", "id": request_id, "result": {"isError": True, "content": [{"type": "text", "text": str(error)}]}}
        except Exception as error:  # pragma: no cover - defensive
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"isError": True, "content": [{"type": "text", "text": f"{type(error).__name__}: {error}"}]},
            }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def serve() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(message)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0
