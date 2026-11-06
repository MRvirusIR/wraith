"""Pinned tool definitions.

Pinning is the daily-use loop: run `wraith pin` once, then `wraith probe`
tells you when a server quietly rewrites a tool you already reviewed.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

STORE_DIR = ".wraith"
STORE_FILE = "pins.json"


def _path(root: str = ".") -> str:
    return os.path.join(root, STORE_DIR, STORE_FILE)


def load(root: str = ".") -> Dict[str, Any]:
    path = _path(root)
    if not os.path.exists(path):
        return {"targets": {}}
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError:
            return {"targets": {}}
    data.setdefault("targets", {})
    return data


def save(data: Dict[str, Any], root: str = ".") -> str:
    path = _path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def get_target(data: Dict[str, Any], url: str) -> Optional[Dict[str, Any]]:
    return data.get("targets", {}).get(url)


def pin(data: Dict[str, Any], url: str, tools: List[Dict[str, Any]], hasher) -> Dict[str, Any]:
    hashes = {str(t.get("name")): hasher(t) for t in tools if isinstance(t, dict)}
    record = {
        "tools": hashes,
        "count": len(hashes),
        "pinned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    data.setdefault("targets", {})[url] = record
    return record


def previous_hashes(data: Dict[str, Any], url: str) -> Dict[str, str]:
    record = get_target(data, url) or {}
    tools = record.get("tools") or {}
    return {str(k): str(v) for k, v in tools.items()}
