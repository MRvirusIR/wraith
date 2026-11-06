"""Turn a pile of captures into a dataset.

Offline and boring on purpose: Wraith never mass-scans the internet. You bring
captures you are allowed to have, this module turns them into numbers you can
publish and diffs you can trust.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from wraith import rules
from wraith.findings import RANK, SEVERITIES, Finding, dedupe, summarize, worst


def severity_rank(label: str) -> int:
    """Sort key that tolerates 'none' (a capture with no findings)."""
    return RANK.get(label, len(RANK))


@dataclass
class Capture:
    path: str
    target: str
    tool_count: int
    findings: List[Finding]

    @property
    def worst(self) -> str:
        return worst(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capture": self.path,
            "target": self.target,
            "tool_count": self.tool_count,
            "worst": self.worst,
            "summary": summarize(self.findings),
            "rules": sorted({f.rule for f in self.findings}),
        }


def load_tools(path: str) -> Optional[List[Dict[str, Any]]]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, list):
        return data if data and all(isinstance(item, dict) and "name" in item for item in data) else None
    if isinstance(data, dict):
        tools = data.get("tools")
        if isinstance(tools, list):
            return [tool for tool in tools if isinstance(tool, dict)]
    return None


def _target_for(path: str, tools: List[Dict[str, Any]]) -> str:
    sibling = os.path.join(os.path.dirname(path), "target.json")
    if os.path.exists(sibling):
        try:
            with open(sibling, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if data.get("target"):
                return str(data["target"])
        except (OSError, json.JSONDecodeError):
            pass
    return os.path.basename(os.path.dirname(path)) or os.path.basename(path)


def iter_paths(root: str) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if name.endswith(".json") and name not in ("findings.json", "target.json", "package.json"):
                yield os.path.join(dirpath, name)


def analyze(root: str) -> List[Capture]:
    captures: List[Capture] = []
    for path in iter_paths(root):
        tools = load_tools(path)
        if tools is None:
            continue
        target = _target_for(path, tools)
        captures.append(
            Capture(
                path=path,
                target=target,
                tool_count=len(tools),
                findings=dedupe(rules.analyze_tools(tools, target)),
            )
        )
    return captures


def aggregate(captures: List[Capture]) -> Dict[str, Any]:
    totals = {name: 0 for name in SEVERITIES}
    histogram: Dict[str, Dict[str, int]] = {}
    affected = 0
    for capture in captures:
        for name, count in summarize(capture.findings).items():
            totals[name] += count
        for finding in capture.findings:
            bucket = histogram.setdefault(finding.rule, {name: 0 for name in SEVERITIES})
            bucket[finding.severity] += 1
        if capture.worst in ("critical", "high"):
            affected += 1
    return {
        "captures": len(captures),
        "tools": sum(c.tool_count for c in captures),
        "findings": sum(totals.values()),
        "severity": totals,
        "affected_captures": affected,
        "rules": histogram,
    }


def render_markdown(captures: List[Capture], stats: Dict[str, Any], title: str = "Wraith corpus report") -> str:
    total = stats["captures"] or 1
    percent = round(100 * stats["affected_captures"] / total)
    lines = [
        f"# {title}",
        "",
        "## Method",
        "",
        "Every capture was analysed offline with the Wraith rule set: the raw tool definitions a "
        "server returned from `tools/list`, nothing executed, no live probing.",
        "",
        "## Numbers",
        "",
        f"- Captures analysed: **{stats['captures']}**",
        f"- Tool definitions: **{stats['tools']}**",
        f"- Findings: **{stats['findings']}**",
        f"- Captures with at least one high or critical finding: **{stats['affected_captures']} "
        f"({percent}%)**",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {stats['severity'][severity]} |")
    lines += ["", "## By rule", "", "| Rule | High | Medium | Low | Total |", "|---|---|---|---|---|"]
    for rule_id, bucket in sorted(
        stats["rules"].items(), key=lambda item: -sum(item[1].values())
    ):
        total_rule = sum(bucket.values())
        lines.append(f"| `{rule_id}` | {bucket['high']} | {bucket['medium']} | {bucket['low']} | {total_rule} |")
    lines += ["", "## Captures", "", "| Target | Tools | Worst | Findings | Rules hit |", "|---|---|---|---|---|"]
    for capture in sorted(captures, key=lambda c: (severity_rank(c.worst), -len(c.findings))):
        lines.append(
            f"| `{capture.target}` | {capture.tool_count} | {capture.worst.upper()} | "
            f"{len(capture.findings)} | {', '.join(sorted({f.rule for f in capture.findings})) or '-'} |"
        )
    lines += [
        "",
        "## Caveats",
        "",
        "- A finding means the definition matches a poisoning pattern, not that the server is malicious.",
        "- A clean capture is not a clean bill of health; the rule set is finite and documented in docs/DETECTIONS.md.",
        "- Publish only captures you are allowed to have, and disclose to maintainers before publishing anything that names them.",
        "",
    ]
    return "\n".join(lines)
