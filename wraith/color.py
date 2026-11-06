"""Tiny ANSI helper. No dependencies, respects NO_COLOR and --color."""
from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
}

_MODE = "auto"


def set_mode(mode: str) -> None:
    global _MODE
    _MODE = mode


def enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if _MODE == "always":
        return True
    if _MODE == "never":
        return False
    return sys.stdout.isatty()


def paint(text: str, *styles: str) -> str:
    if not enabled():
        return text
    prefix = "".join(_CODES[s] for s in styles if s in _CODES)
    return f"{prefix}{text}{_CODES['reset']}"


SEVERITY_STYLE = {
    "critical": ("red", "bold"),
    "high": ("red",),
    "medium": ("yellow",),
    "low": ("blue",),
    "info": ("gray",),
}


def severity_badge(severity: str, width: int = 8) -> str:
    label = severity.upper().ljust(width)
    return paint(label, *SEVERITY_STYLE.get(severity, ("gray",)))
