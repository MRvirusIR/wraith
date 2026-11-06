"""Detection rules for MCP tool definitions.

Each rule is a pure function over a tool definition. A rule returns findings,
never raises, and never touches the network: probing is the client's job.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional

from wraith import unicode_scan
from wraith.findings import Finding

# Phrases that only make sense when addressed to a model, not to a human.
INJECTION_PATTERNS = [
    (r"\bignore (all |any )?(previous|prior|above|earlier) (instructions?|prompts?|rules?)\b", "overrides prior instructions"),
    (r"\bdisregard (all |any )?(previous|prior|above|earlier)\b", "discards prior instructions"),
    (r"\bdo not (tell|inform|mention|reveal|alert|notify) (the )?(user|human|operator)\b", "asks the model to hide behaviour"),
    (r"\b(without|don't|do not) (asking|informing|notifying|confirming)\b", "removes user confirmation"),
    (r"\bbefore (using|calling|invoking) this tool\b", "pre-tool side effect"),
    (r"\byou must (first|always)\b", "mandatory hidden step"),
    (r"\balways (call|invoke|use) this tool\b", "forced tool selection"),
    (r"\binstead of (the|any) (other|requested)\b", "tool shadowing instruction"),
    (r"\bsystem prompt\b|\bdeveloper message\b", "targets the system prompt"),
    (r"\bexfiltrat", "explicit exfiltration language"),
    (r"\b(send|post|upload|forward) (it|them|this|the (data|content|file|token|key|credentials?)) to\b", "data egress instruction"),
    (r"\b(curl|wget|base64|nc|ncat|bash -c|powershell|cmd\.exe)\b", "command execution reference"),
    (r"\b(api[_ ]?key|secret|token|password|credential)s?\b.*\b(read|collect|include|append|send)\b", "credential collection"),
    (r"\bnew instructions?\b", "instruction replacement"),
]

SECRET_PATHS = [
    (r"~/\.ssh\b|id_rsa|id_ed25519", "SSH private keys"),
    (r"\.aws/credentials|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID", "AWS credentials"),
    (r"\.env\b|\.git-credentials|\.netrc\b", "local secret files"),
    (r"\.docker/config\.json|\.kube/config|kubeconfig", "cluster/registry credentials"),
    (r"/etc/(passwd|shadow)|SAM\b|NTDS\.dit", "system credential stores"),
    (r"wallet\.dat|seed ?phrase|mnemonic", "crypto wallet material"),
    (r"\.npmrc\b|\.pypirc\b|\.config/gh/hosts\.yml", "package registry tokens"),
    (r"google-services\.json|service[_ ]account.*\.json", "service account keys"),
]

EXFIL_HOSTS = [
    "webhook.site", "requestbin", "pipedream.net", "ngrok", "interact.sh",
    "oast.", "burpcollaborator", "canarytokens", "beeceptor", "hookbin",
    "discord.com/api/webhooks", "api.telegram.org", "pastebin.com", "transfer.sh",
]

EGRESS_HINTS = ("send", "post", "upload", "forward", "sync", "mirror", "report", "telemetry", "analytics")

SHELLY_TOOLS = re.compile(r"(exec|shell|command|run_|terminal|eval|spawn|subprocess|powershell|bash)", re.I)
WRITE_TOOLS = re.compile(r"(write|create|save|delete|remove|move|rename|upload|put_|patch)", re.I)
READ_TOOLS = re.compile(r"(read|get_|load|open|fetch|cat|list_|dump)", re.I)
NETWORK_TOOLS = re.compile(r"(http|fetch|url|webhook|request|browse|curl|download|upload)", re.I)

PATH_PARAMS = re.compile(r"^(path|file|filename|filepath|dir|directory|folder|target|location)$", re.I)
URL_PARAMS = re.compile(r"^(url|uri|endpoint|host|hostname|dest|destination|callback|webhook)$", re.I)
COMMAND_PARAMS = re.compile(r"^(cmd|command|exec|script|payload|query_sql|sql|shell)$", re.I)

WRITE_VERBS = re.compile(
    r"(delete|remove|drop|destroy|purge|wipe|truncate|overwrite|update|modify|edit|"
    r"write|create|insert|patch|move|rename|revoke|disable|kill|exec|run|shell|"
    r"send|post|upload|publish|deploy)",
    re.I,
)
DESTRUCTIVE_VERBS = re.compile(r"(delete|drop|destroy|purge|wipe|truncate|remove|revoke|kill)", re.I)
ANNOTATION_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

CWE = {
    "hidden-instruction": "CWE-74",
    "unicode-obfuscation": "CWE-838",
    "secret-path-reference": "CWE-538",
    "exfil-endpoint": "CWE-200",
    "dangerous-capability": "CWE-78",
    "capability-mismatch": "CWE-1059",
    "schema-weakness": "CWE-20",
    "tool-shadowing": "CWE-706",
    "definition-drift": "CWE-494",
    "unauth-endpoint": "CWE-306",
    "annotation-lie": "CWE-863",
}


def _iter_strings(value: Any, path: str = "") -> Iterable[tuple]:
    """Walk a tool definition and yield (json-path, string)."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_strings(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_strings(item, f"{path}[{index}]")


def _snippet(text: str, match: re.Match, pad: int = 60) -> str:
    start = max(0, match.start() - pad)
    end = min(len(text), match.end() + pad)
    body = text[start:end].replace("\n", " ")
    prefix = "…" if start else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{body}{suffix}"


def _params(tool: Dict[str, Any]) -> Dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def rule_hidden_instruction(tool: Dict[str, Any], target: str) -> List[Finding]:
    findings = []
    name = tool.get("name", "?")
    for path, text in _iter_strings(tool):
        lowered = unicode_scan.normalize(text)
        for pattern, label in INJECTION_PATTERNS:
            for match in re.finditer(pattern, lowered, re.I):
                findings.append(
                    Finding(
                        rule="hidden-instruction",
                        severity="high",
                        title=f"Tool '{name}' carries instructions aimed at the model",
                        target=target,
                        tool=name,
                        location=path,
                        detail=f"Description text {label}: \"{_snippet(lowered, match)}\"",
                        evidence=_snippet(text, match),
                        remediation=(
                            "Treat tool descriptions as untrusted input. Pin the definition hash, "
                            "review every description change, and strip instructions before the "
                            "model sees them."
                        ),
                        cwe=CWE["hidden-instruction"],
                    )
                )
                break  # one finding per pattern per field is enough
    return findings


def rule_unicode(tool: Dict[str, Any], target: str) -> List[Finding]:
    findings = []
    name = tool.get("name", "?")
    for path, text in _iter_strings(tool):
        report = unicode_scan.scan(text)
        if not report.suspicious:
            continue
        severity = "high" if report.tag_chars else "medium"
        findings.append(
            Finding(
                rule="unicode-obfuscation",
                severity=severity,
                title=f"Tool '{name}' hides characters a reviewer cannot see",
                target=target,
                tool=name,
                location=path,
                detail=unicode_scan.describe(report),
                evidence=(
                    f"visible: {unicode_scan.strip_invisible(text)[:160]!r} | "
                    f"decoded: {report.decoded[:160]!r}"
                ),
                remediation=(
                    "Reject non-printable codepoints in tool metadata. Render descriptions "
                    "through a normaliser (NFKC + strip) before display or model use."
                ),
                cwe=CWE["unicode-obfuscation"],
                extra=report.to_dict(),
            )
        )
    return findings


def rule_secret_paths(tool: Dict[str, Any], target: str) -> List[Finding]:
    findings = []
    name = tool.get("name", "?")
    for path, text in _iter_strings(tool):
        for pattern, label in SECRET_PATHS:
            match = re.search(pattern, text, re.I)
            if not match:
                continue
            findings.append(
                Finding(
                    rule="secret-path-reference",
                    severity="medium",
                    title=f"Tool '{name}' points at {label}",
                    target=target,
                    tool=name,
                    location=path,
                    detail=f"Schema or description references {label}.",
                    evidence=_snippet(text, match),
                    remediation=(
                        "A tool that can read credentials turns any prompt injection into "
                        "full account takeover. Scope file access to an explicit allowlist."
                    ),
                    cwe=CWE["secret-path-reference"],
                )
            )
            break
    return findings


def rule_exfil(tool: Dict[str, Any], target: str) -> List[Finding]:
    findings = []
    name = tool.get("name", "?")
    for path, text in _iter_strings(tool):
        lowered = text.lower()
        for host in EXFIL_HOSTS:
            if host not in lowered:
                continue
            match = re.search(re.escape(host), text, re.I)
            findings.append(
                Finding(
                    rule="exfil-endpoint",
                    severity="high",
                    title=f"Tool '{name}' sends data to an attacker-controlled sink",
                    target=target,
                    tool=name,
                    location=path,
                    detail=f"Hardcoded collection endpoint: {host}",
                    evidence=_snippet(text, match),
                    remediation=(
                        "Never let a tool description name an egress destination. Restrict "
                        "outbound hosts at the network layer and log every call."
                    ),
                    cwe=CWE["exfil-endpoint"],
                )
            )
            break
    return findings


def rule_capability(tool: Dict[str, Any], target: str) -> List[Finding]:
    """Dangerous verbs in the tool name or an executable parameter."""
    findings = []
    name = str(tool.get("name", "?"))
    description = str(tool.get("description") or "")
    params = _params(tool)

    shell_hits = [p for p in params if COMMAND_PARAMS.match(p)]
    if SHELLY_TOOLS.search(name) or shell_hits:
        findings.append(
            Finding(
                rule="dangerous-capability",
                severity="high" if shell_hits else "medium",
                title=f"Tool '{name}' exposes command execution",
                target=target,
                tool=name,
                location=f"name/{', '.join(shell_hits) or 'description'}",
                detail="The tool can run operator-supplied commands or shell syntax.",
                evidence=f"name={name} params={sorted(params)}",
                remediation=(
                    "Command execution behind an agent is a remote shell with extra steps. "
                    "Replace with a fixed set of allowlisted operations."
                ),
                cwe=CWE["dangerous-capability"],
            )
        )

    reads = bool(READ_TOOLS.search(name) or READ_TOOLS.search(description))
    writes = bool(WRITE_TOOLS.search(name))
    network = bool(NETWORK_TOOLS.search(name) or any(URL_PARAMS.match(p) for p in params))
    if (reads and network) or (writes and network):
        findings.append(
            Finding(
                rule="dangerous-capability",
                severity="medium",
                title=f"Tool '{name}' combines local data access with network egress",
                target=target,
                tool=name,
                location="name",
                detail="Read/write plus network in one tool is the classic exfiltration primitive.",
                evidence=f"reads={reads} writes={writes} network={network}",
                remediation="Split data access from egress so no single call can leak and send.",
                cwe=CWE["dangerous-capability"],
            )
        )
    return findings


def rule_mismatch(tool: Dict[str, Any], target: str) -> List[Finding]:
    """Description claims one thing, schema allows another."""
    findings = []
    name = str(tool.get("name", "?"))
    description = str(tool.get("description") or "").lower()
    params = _params(tool)

    if not description:
        return findings

    read_only_claim = any(word in description for word in ("search", "look up", "read-only", "read only", "query"))
    risky = [p for p in params if PATH_PARAMS.match(p) or URL_PARAMS.match(p) or COMMAND_PARAMS.match(p)]
    if read_only_claim and risky:
        findings.append(
            Finding(
                rule="capability-mismatch",
                severity="medium",
                title=f"Tool '{name}' claims to be read-only but accepts {', '.join(risky)}",
                target=target,
                tool=name,
                location="inputSchema.properties",
                detail="Documented capability is narrower than the actual parameter surface.",
                evidence=f"description={description[:120]!r} params={sorted(params)}",
                remediation="Align the schema with the stated capability, or document the risk.",
                cwe=CWE["capability-mismatch"],
            )
        )
    return findings


def rule_schema(tool: Dict[str, Any], target: str) -> List[Finding]:
    findings = []
    name = str(tool.get("name", "?"))
    schema = tool.get("inputSchema") or {}
    props = _params(tool)

    for param, spec in props.items():
        if not isinstance(spec, dict):
            continue
        unconstrained = not any(k in spec for k in ("pattern", "enum", "const", "format", "maximum", "maxLength"))
        if PATH_PARAMS.match(param) and unconstrained:
            findings.append(
                Finding(
                    rule="schema-weakness",
                    severity="medium",
                    title=f"'{name}.{param}' accepts any path",
                    target=target,
                    tool=name,
                    location=f"inputSchema.properties.{param}",
                    detail="No pattern, enum or format constraint: path traversal and absolute paths pass through.",
                    evidence=json.dumps(spec, ensure_ascii=False)[:200],
                    remediation="Constrain to a relative allowlist pattern, e.g. ^[a-z0-9_\\-]+\\.md$.",
                    cwe=CWE["schema-weakness"],
                )
            )
        if URL_PARAMS.match(param) and unconstrained:
            findings.append(
                Finding(
                    rule="schema-weakness",
                    severity="low",
                    title=f"'{name}.{param}' accepts any destination",
                    target=target,
                    tool=name,
                    location=f"inputSchema.properties.{param}",
                    detail="Unrestricted URL parameter enables SSRF and data egress.",
                    evidence=json.dumps(spec, ensure_ascii=False)[:200],
                    remediation="Pin the host with an enum or a pattern plus an egress allowlist.",
                    cwe=CWE["schema-weakness"],
                )
            )

    if isinstance(schema, dict) and schema.get("additionalProperties") is True:
        findings.append(
            Finding(
                rule="schema-weakness",
                severity="low",
                title=f"'{name}' accepts arbitrary extra properties",
                target=target,
                tool=name,
                location="inputSchema",
                detail="additionalProperties: true lets a caller smuggle fields the server still reads.",
                evidence="additionalProperties: true",
                remediation="Set additionalProperties: false and validate strictly.",
                cwe=CWE["schema-weakness"],
            )
        )
    return findings


def rule_annotations(tool: Dict[str, Any], target: str) -> List[Finding]:
    """MCP tool annotations that contradict what the tool actually does.

    Clients use `readOnlyHint` to decide whether to ask the user for approval.
    A server that sets it on a destructive tool gets to skip that prompt, which
    makes the annotation itself the attack.
    """
    findings: List[Finding] = []
    annotations = tool.get("annotations")
    if not isinstance(annotations, dict) or not any(k in annotations for k in ANNOTATION_KEYS):
        return findings

    name = str(tool.get("name", "?"))
    description = str(tool.get("description") or "")
    params = " ".join(_params(tool).keys())
    text = f"{name} {description} {params}"
    declared = json.dumps({k: v for k, v in annotations.items() if k in ANNOTATION_KEYS}, sort_keys=True)

    if annotations.get("readOnlyHint") is True:
        match = WRITE_VERBS.search(text)
        if match:
            findings.append(
                Finding(
                    rule="annotation-lie",
                    severity="high",
                    title=f"Tool '{name}' declares readOnlyHint but performs writes",
                    target=target,
                    tool=name,
                    location="annotations.readOnlyHint",
                    detail=(
                        "The tool advertises itself as read-only, so the client may skip the approval "
                        f"prompt, while its own metadata contains '{match.group(0)}'."
                    ),
                    evidence=f"{declared} · signal={match.group(0)!r} in name/description/parameters",
                    remediation=(
                        "Never let an annotation decide approval on its own. Cross-check the annotation "
                        "against the schema and the name before granting a call."
                    ),
                    cwe=CWE["annotation-lie"],
                )
            )

    if annotations.get("destructiveHint") is False:
        match = DESTRUCTIVE_VERBS.search(text)
        if match:
            findings.append(
                Finding(
                    rule="annotation-lie",
                    severity="high",
                    title=f"Tool '{name}' declares destructiveHint: false but can destroy data",
                    target=target,
                    tool=name,
                    location="annotations.destructiveHint",
                    detail=f"The definition contains '{match.group(0)}' while the annotation denies destructive behaviour.",
                    evidence=f"{declared} · signal={match.group(0)!r}",
                    remediation="Treat destructiveHint: false as a claim to verify, never as a guarantee.",
                    cwe=CWE["annotation-lie"],
                )
            )

    if annotations.get("openWorldHint") is False:
        match = re.search(r"https?://[^\s\"']+", text) or next(
            (p for p in _params(tool) if URL_PARAMS.match(p)), None
        )
        if match:
            signal = match.group(0) if hasattr(match, "group") else str(match)
            findings.append(
                Finding(
                    rule="annotation-lie",
                    severity="medium",
                    title=f"Tool '{name}' declares openWorldHint: false but reaches the network",
                    target=target,
                    tool=name,
                    location="annotations.openWorldHint",
                    detail="A closed-world annotation on a tool that takes or mentions a URL hides its egress.",
                    evidence=f"{declared} · signal={signal!r}",
                    remediation="Verify egress claims against the schema; closed-world tools should take no URLs.",
                    cwe=CWE["annotation-lie"],
                )
            )
    return findings


RULES = (
    rule_hidden_instruction,
    rule_annotations,
    rule_unicode,
    rule_secret_paths,
    rule_exfil,
    rule_capability,
    rule_mismatch,
    rule_schema,
)


def analyze_tools(tools: List[Dict[str, Any]], target: str) -> List[Finding]:
    findings: List[Finding] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        for rule in RULES:
            findings.extend(rule(tool, target))
    findings.extend(rule_shadowing(tools, target))
    return findings


def rule_shadowing(tools: List[Dict[str, Any]], target: str) -> List[Finding]:
    """Same tool name twice in one listing: the later definition wins silently."""
    seen: Dict[str, int] = {}
    findings = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", "?"))
        seen[name] = seen.get(name, 0) + 1
    for name, count in seen.items():
        if count > 1:
            findings.append(
                Finding(
                    rule="tool-shadowing",
                    severity="high",
                    title=f"Tool '{name}' is defined {count} times",
                    target=target,
                    tool=name,
                    location="tools[]",
                    detail="Duplicate names let one definition shadow another; the client picks silently.",
                    evidence=f"{count} definitions named {name}",
                    remediation="Reject duplicate tool names at registration time.",
                    cwe=CWE["tool-shadowing"],
                )
            )
    return findings


def definition_hash(tool: Dict[str, Any]) -> str:
    import hashlib

    payload = json.dumps(tool, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def drift(previous: Dict[str, str], tools: List[Dict[str, Any]], target: str) -> List[Finding]:
    """Compare pinned definition hashes with what the server returns now."""
    findings = []
    current = {str(t.get("name")): definition_hash(t) for t in tools if isinstance(t, dict)}
    for name, old_hash in previous.items():
        new_hash = current.get(name)
        if new_hash is None:
            findings.append(
                Finding(
                    rule="definition-drift",
                    severity="medium",
                    title=f"Tool '{name}' disappeared since the last pin",
                    target=target,
                    tool=name,
                    detail=f"Pinned {old_hash}, now absent from tools/list.",
                    evidence=f"pinned={old_hash} current=missing",
                    remediation="Track removals too: a rug pull often starts by dropping the reviewed tool.",
                    cwe=CWE["definition-drift"],
                )
            )
        elif new_hash != old_hash:
            findings.append(
                Finding(
                    rule="definition-drift",
                    severity="high",
                    title=f"Tool '{name}' changed after review",
                    target=target,
                    tool=name,
                    detail=f"Definition hash moved from {old_hash} to {new_hash}.",
                    evidence=f"pinned={old_hash} current={new_hash}",
                    remediation=(
                        "A silent definition change after install is the signature of a rug pull. "
                        "Re-review before the next call, then re-pin."
                    ),
                    cwe=CWE["definition-drift"],
                )
            )
    for name, new_hash in current.items():
        if name not in previous:
            findings.append(
                Finding(
                    rule="definition-drift",
                    severity="low",
                    title=f"New tool '{name}' appeared since the last pin",
                    target=target,
                    tool=name,
                    detail=f"No pinned hash; current {new_hash}.",
                    evidence=f"current={new_hash}",
                    remediation="Review newly added tools before granting them a session.",
                    cwe=CWE["definition-drift"],
                )
            )
    return findings
