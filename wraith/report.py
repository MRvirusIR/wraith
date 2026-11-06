"""Bounty-ready report rendering.

The output is deliberately boring: a triager should be able to read it top to
bottom, reproduce it in one command, and close it as a real finding.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from wraith.findings import RANK, Finding, summarize, worst

PLATFORMS = {
    "generic": {"asset": "Affected component", "program": "Program"},
    "h1": {"asset": "Asset", "program": "Program"},
    "bugcrowd": {"asset": "Target", "program": "Program"},
}

SEVERITY_NOTE = {
    "critical": "Remote compromise of the agent and everything it can reach.",
    "high": "An attacker can change what the agent does, or where its data goes.",
    "medium": "Weakens the trust boundary; needs a second step to become exploitable.",
    "low": "Hardening gap worth fixing before it is chained with something else.",
    "info": "Observation, no direct security impact.",
}


def _poc_curl(target: str, tool: Optional[str] = None) -> str:
    base = (
        "curl -sS -X POST '{url}' \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -H 'Accept: application/json, text/event-stream' \\\n"
        "  -d '{body}'"
    )
    body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    if tool:
        body = (
            '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
            '{"name":"' + tool + '","arguments":{}}}'
        )
    return base.format(url=target, body=body)


def build(
    target: str,
    findings: List[Finding],
    meta: Optional[Dict[str, Any]] = None,
    platform: str = "generic",
) -> str:
    meta = meta or {}
    labels = PLATFORMS.get(platform, PLATFORMS["generic"])
    counts = summarize(findings)
    top = worst(findings)
    ordered = sorted(findings, key=lambda f: f.sort_key())
    server = meta.get("server") or {}
    server_name = server.get("name", "unknown server")
    server_version = server.get("version", "")

    lines: List[str] = []
    title = f"MCP tool poisoning in {server_name}"
    if len(ordered) == 1:
        title = ordered[0].title
    elif findings:
        title = f"MCP tool poisoning in {server_name}: {len(ordered)} findings"
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- **{labels['asset']}:** `{target}`")
    lines.append(f"- **Server:** `{server_name} {server_version}`".rstrip())
    if meta.get("protocol"):
        lines.append(f"- **MCP protocol:** `{meta['protocol']}`")
    if meta.get("program"):
        lines.append(f"- **{labels['program']}:** {meta['program']}")
    lines.append(f"- **Severity:** {top.upper() if findings else 'Informational'}")
    if findings:
        lines.append(f"- **CVSS:** `{ordered[0].cvss}`")
        lines.append(f"- **CWE:** {', '.join(sorted({f.cwe for f in findings if f.cwe}))}")
    lines.append(f"- **Tools exposed:** {meta.get('tool_count', 'unknown')}")
    lines.append(f"- **Detected at:** {meta.get('timestamp', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    if not findings:
        lines.append(
            "No poisoning indicators matched the current rule set. Absence of findings is not a "
            "clean bill of health: the rules cover description abuse, invisible characters, "
            "credential references, egress sinks, capability mismatches and schema weaknesses."
        )
    else:
        lines.append(
            f"The MCP server at `{target}` returns {meta.get('tool_count', 'several')} tool "
            f"definitions. Analysis produced {len(findings)} findings that break the trust boundary "
            f"between tool metadata and model instructions, in ways that are invisible to a normal "
            f"user reading the client UI. Highest severity: **{top.upper()}** — {SEVERITY_NOTE.get(top, '')}"
        )
        lines.append("")
        lines.append("| # | Severity | Rule | Tool | Location |")
        lines.append("|---|---|---|---|---|")
        for index, finding in enumerate(ordered, start=1):
            lines.append(
                f"| F{index} | {finding.severity.upper()} | `{finding.rule}` | "
                f"`{finding.tool or '-'}` | `{finding.location or '-'}` |"
            )
    lines.append("")

    lines.append("## Steps to reproduce")
    lines.append("")
    lines.append("1. Point any MCP client at the endpoint, or replay the request below.")
    lines.append("2. List the tools and read the raw definitions, not the rendered description.")
    lines.append("3. Compare the raw `description` field with what the client shows the user.")
    lines.append("")
    lines.append("```bash")
    lines.append(_poc_curl(target))
    lines.append("```")
    lines.append("")
    lines.append("Deterministic re-check with Wraith:")
    lines.append("")
    lines.append("```bash")
    lines.append(f"wraith probe {target} --json")
    lines.append("```")
    lines.append("")

    for index, finding in enumerate(ordered, start=1):
        lines.append(f"## F{index} · {finding.severity.upper()} · {finding.title}")
        lines.append("")
        lines.append(f"- **Rule:** `{finding.rule}`")
        if finding.cwe:
            lines.append(f"- **CWE:** {finding.cwe}")
        if finding.tool:
            lines.append(f"- **Tool:** `{finding.tool}`")
        if finding.location:
            lines.append(f"- **Location:** `{finding.location}`")
        lines.append(f"- **CVSS:** `{finding.cvss}`")
        lines.append("")
        lines.append("**What happens.** " + finding.detail)
        lines.append("")
        if finding.evidence:
            lines.append("**Evidence from the definition.**")
            lines.append("")
            lines.append("```text")
            lines.append(finding.evidence[:1200])
            lines.append("```")
            lines.append("")
        if finding.tool:
            lines.append("**Trigger.**")
            lines.append("")
            lines.append("```bash")
            lines.append(_poc_curl(target, finding.tool))
            lines.append("```")
            lines.append("")
        lines.append("**Impact.** " + SEVERITY_NOTE.get(finding.severity, ""))
        lines.append("")
        if finding.remediation:
            lines.append("**Remediation.** " + finding.remediation)
            lines.append("")

    lines.append("## Impact")
    lines.append("")
    lines.append(
        "An MCP client treats tool metadata as trusted context. Anything an attacker can place "
        "there is read by the model with the same authority as the user's own request. A poisoned "
        "description is therefore a prompt-injection primitive that needs no exploit, no memory "
        "corruption and no authentication bypass: the client loads it on connect. Where the same "
        "server also holds file or network capability, injection becomes exfiltration."
    )
    lines.append("")
    lines.append("## Remediation")
    lines.append("")
    lines.append(
        "Treat tool definitions as untrusted input on the client side: pin the definition hash at "
        "install time, diff it on every connect, strip non-printable codepoints, and require "
        "explicit approval when a definition changes after review. On the server side, keep "
        "descriptions declarative, constrain path and URL parameters, and never let a single tool "
        "both read local data and reach the network."
    )
    lines.append("")
    lines.append("## Evidence bundle")
    lines.append("")
    lines.append(
        "`tools.json` (raw definitions), `findings.json` (machine readable), "
        "`transcript.jsonl` (every JSON-RPC exchange), `manifest.sha256` (integrity)."
    )
    lines.append("")
    return "\n".join(lines)
