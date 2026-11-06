"""Unicode abuse detection: invisible characters, tag-block smuggling, bidi tricks.

The interesting case is the Unicode Tag block (U+E0000..U+E007F). Each tag
character maps 1:1 onto an ASCII codepoint, so an attacker can hide a full
instruction inside a tool description that renders as an empty string.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Dict, List

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u00ad": "SOFT HYPHEN",
}

BIDI = {
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
}

TAG_BASE = 0xE0000
TAG_END = 0xE007F
VARIATION_RANGE = (0xFE00, 0xFE0F)


def decode_tags(text: str) -> str:
    """Decode Unicode tag characters back into ASCII (ASCII smuggling)."""
    out: List[str] = []
    for char in text:
        code = ord(char)
        if TAG_BASE < code <= TAG_END:
            out.append(chr(code - TAG_BASE))
    return "".join(out)


@dataclass
class UnicodeReport:
    total_chars: int
    invisible: Dict[str, int]
    bidi: Dict[str, int]
    tag_chars: int
    variation_selectors: int
    decoded: str
    suspicious: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_chars": self.total_chars,
            "invisible": self.invisible,
            "bidi": self.bidi,
            "tag_chars": self.tag_chars,
            "variation_selectors": self.variation_selectors,
            "decoded": self.decoded,
            "suspicious": self.suspicious,
        }


def scan(text: str) -> UnicodeReport:
    invisible: Dict[str, int] = {}
    bidi: Dict[str, int] = {}
    tag_chars = 0
    variation = 0

    for char in text:
        if char in ZERO_WIDTH:
            invisible[ZERO_WIDTH[char]] = invisible.get(ZERO_WIDTH[char], 0) + 1
        elif char in BIDI:
            bidi[BIDI[char]] = bidi.get(BIDI[char], 0) + 1
        elif TAG_BASE < ord(char) <= TAG_END:
            tag_chars += 1
        elif VARIATION_RANGE[0] <= ord(char) <= VARIATION_RANGE[1]:
            variation += 1

    decoded = decode_tags(text)
    suspicious = bool(invisible or bidi or tag_chars)

    return UnicodeReport(
        total_chars=len(text),
        invisible=invisible,
        bidi=bidi,
        tag_chars=tag_chars,
        variation_selectors=variation,
        decoded=decoded,
        suspicious=suspicious,
    )


def strip_invisible(text: str) -> str:
    out = []
    for char in text:
        if char in ZERO_WIDTH or char in BIDI:
            continue
        if TAG_BASE < ord(char) <= TAG_END:
            continue
        out.append(char)
    return "".join(out)


def homoglyph_ratio(text: str) -> float:
    """Share of non-ASCII letters. High values in an English tool schema are odd."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    non_ascii = sum(1 for c in letters if ord(c) > 127)
    return non_ascii / len(letters)


def describe(report: UnicodeReport) -> str:
    parts: List[str] = []
    for name, count in report.invisible.items():
        parts.append(f"{count}x {name}")
    for name, count in report.bidi.items():
        parts.append(f"{count}x bidi {name}")
    if report.tag_chars:
        parts.append(f"{report.tag_chars} tag char(s)")
    if report.decoded:
        parts.append(f'hidden text: "{report.decoded}"')
    if report.variation_selectors:
        parts.append(f"{report.variation_selectors}x variation selector")
    return ", ".join(parts) or "no invisible characters"


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", strip_invisible(text))
