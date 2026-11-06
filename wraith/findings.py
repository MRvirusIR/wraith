"""Finding model shared by the rules engine, the CLI and the report writer."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {name: index for index, name in enumerate(SEVERITIES)}

# Conservative vectors: they describe the *category* of impact, not a per-target score.
CVSS_VECTORS = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    target: str
    detail: str
    location: str = ""
    tool: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    poc: Optional[str] = None
    cwe: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in RANK:
            raise ValueError(f"unknown severity: {self.severity}")

    @property
    def key(self) -> str:
        raw = f"{self.rule}|{self.tool or ''}|{self.location}|{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @property
    def cvss(self) -> str:
        return CVSS_VECTORS[self.severity]

    def sort_key(self) -> tuple:
        return (RANK[self.severity], self.rule, self.tool or "")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["id"] = self.key
        data["cvss"] = self.cvss
        return data


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def worst(findings: List[Finding]) -> str:
    if not findings:
        return "none"
    return sorted(findings, key=lambda f: f.sort_key())[0].severity


def dedupe(findings: List[Finding]) -> List[Finding]:
    seen, out = set(), []
    for finding in findings:
        if finding.key in seen:
            continue
        seen.add(finding.key)
        out.append(finding)
    return out


def to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False)
