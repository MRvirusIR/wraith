"""Scope enforcement.

Wraith refuses to touch a host that is not explicitly in scope. This is the
difference between a research tool and a liability, so it is on by default and
has no silent override: you either add the target or pass --i-own-this-target.
"""
from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

SCOPE_FILE = ".wraith-scope.json"
LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


@dataclass
class Program:
    id: str
    name: str = ""
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "notes": self.notes,
        }


@dataclass
class ScopeState:
    programs: List[Program] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"programs": [p.to_dict() for p in self.programs]}

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ScopeState":
        programs = []
        for item in data.get("programs", []) or []:  # type: ignore[union-attr]
            if not isinstance(item, dict):
                continue
            programs.append(
                Program(
                    id=str(item.get("id", "default")),
                    name=str(item.get("name", "")),
                    in_scope=list(item.get("in_scope", []) or []),
                    out_of_scope=list(item.get("out_of_scope", []) or []),
                    notes=str(item.get("notes", "")),
                )
            )
        return cls(programs=programs)


def load(path: Optional[str] = None) -> ScopeState:
    path = path or SCOPE_FILE
    if not os.path.exists(path):
        return ScopeState()
    with open(path, "r", encoding="utf-8") as handle:
        return ScopeState.from_dict(json.load(handle))


def save(state: ScopeState, path: Optional[str] = None) -> str:
    path = path or SCOPE_FILE
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state.to_dict(), handle, indent=2)
        handle.write("\n")
    return path


def _target_shape(url: str) -> str:
    parsed = urlparse(url if "//" in url else f"//{url}", scheme="https")
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    return f"{host}{port}{path}"


def _matches(pattern: str, shape: str, host: str) -> bool:
    pattern = pattern.strip().lower()
    if not pattern:
        return False
    if pattern.startswith(("http://", "https://")):
        pattern = _target_shape(pattern)
    if "/" not in pattern:
        return fnmatch.fnmatchcase(host, pattern)
    return fnmatch.fnmatchcase(shape, pattern)


def check(url: str, state: ScopeState, allow_any: bool = False) -> Tuple[bool, str, Optional[str]]:
    """Return (allowed, reason, program_id)."""
    host = (urlparse(url if "//" in url else f"//{url}", scheme="https").hostname or "").lower()
    shape = _target_shape(url)

    if host in LOOPBACK:
        return True, "loopback target (local lab)", "local"

    if allow_any:
        return True, "scope check bypassed with --i-own-this-target", None

    for program in state.programs:
        for pattern in program.out_of_scope:
            if _matches(pattern, shape, host):
                return False, f"explicitly out of scope in '{program.id}' ({pattern})", program.id

    for program in state.programs:
        for pattern in program.in_scope:
            if _matches(pattern, shape, host):
                return True, f"in scope for '{program.id}' ({pattern})", program.id

    return False, "host is not in any in-scope list", None
