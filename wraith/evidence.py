"""Evidence bundles.

A finding nobody can reproduce is a finding nobody pays for. Every run writes
a self-contained directory with the request transcript, the exact tool
definitions, the findings, and a manifest so a triager can verify nothing was
edited after the fact.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization|api[-_]?key|token|cookie)\s*[:=]\s*\S+"),
]


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + ": [redacted]", text)
    return text


def slug(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "target").replace(".", "-")
    port = f"-{parsed.port}" if parsed.port else ""
    return f"{host}{port}"


def create_run_dir(base: str = "runs", url: str = "") -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = os.path.join(base, f"{stamp}-{slug(url)}")
    os.makedirs(path, exist_ok=True)
    return path


def _write(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def manifest(run_dir: str) -> str:
    lines = []
    for name in sorted(os.listdir(run_dir)):
        full = os.path.join(run_dir, name)
        if not os.path.isfile(full) or name == "manifest.sha256":
            continue
        with open(full, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        lines.append(f"{digest}  {name}")
    path = os.path.join(run_dir, "manifest.sha256")
    _write(path, "\n".join(lines) + "\n")
    return path


def write_bundle(
    run_dir: str,
    target: str,
    tools: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    transcript: List[Dict[str, Any]],
    meta: Optional[Dict[str, Any]] = None,
    report_markdown: Optional[str] = None,
) -> Dict[str, str]:
    paths: Dict[str, str] = {}
    paths["target"] = _write(
        os.path.join(run_dir, "target.json"),
        json.dumps({"target": target, "meta": meta or {}}, indent=2),
    )
    paths["tools"] = _write(os.path.join(run_dir, "tools.json"), json.dumps(tools, indent=2, ensure_ascii=False))
    paths["findings"] = _write(
        os.path.join(run_dir, "findings.json"), json.dumps(findings, indent=2, ensure_ascii=False)
    )
    transcript_text = "\n".join(redact(json.dumps(entry, ensure_ascii=False)) for entry in transcript)
    paths["transcript"] = _write(os.path.join(run_dir, "transcript.jsonl"), transcript_text + "\n")
    if report_markdown is not None:
        paths["report"] = _write(os.path.join(run_dir, "report.md"), report_markdown)
    paths["manifest"] = manifest(run_dir)
    return paths
