"""SARIF 2.1.0 output, so findings can land in code scanning / CI dashboards."""
from __future__ import annotations

from typing import Any, Dict, List

from wraith import __version__
from wraith.findings import Finding

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def build(target: str, findings: List[Finding], rulebook: List[tuple]) -> Dict[str, Any]:
    rules = [
        {
            "id": rule_id,
            "name": rule_id.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": description},
            "helpUri": "https://github.com/MRvirusIR/wraith/blob/main/docs/DETECTIONS.md",
            "properties": {"tags": ["security", "mcp", "ai-agent"]},
        }
        for rule_id, description in rulebook
    ]
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule,
                "level": LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.title} — {finding.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target},
                            "region": {"startLine": 1, "snippet": {"text": (finding.evidence or finding.location)[:400]}},
                        },
                        "logicalLocations": [{"fullyQualifiedName": finding.location or finding.rule}],
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "security-severity": SECURITY_SEVERITY.get(finding.severity, "0.0"),
                    "cwe": finding.cwe,
                    "tool": finding.tool,
                    "remediation": finding.remediation,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wraith",
                        "version": __version__,
                        "informationUri": "https://github.com/MRvirusIR/wraith",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
