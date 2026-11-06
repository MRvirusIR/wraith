"""Render the demo output to docs/demo.svg and docs/demo.png.

Runs the built-in lab, captures the coloured CLI output, then draws a static
terminal screenshot. The SVG is committed because it is text: it diffs, it
scales, and it needs no binary in the repository.
"""
from __future__ import annotations

import html
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANSI = re.compile(r"\033\[([0-9;]*)m")

FILL = {
    "1": "#e6edf7",
    "2": "#6b7688",
    "31": "#ff6b6b",
    "32": "#5ee08a",
    "33": "#ffd166",
    "34": "#6ba7ff",
    "35": "#c792ea",
    "36": "#57d1d1",
    "90": "#7b8494",
}
DEFAULT_FILL = "#dfe6f1"
CHAR_W = 8.4
LINE_H = 23.0


def tokenize(line: str):
    """Yield (text, fill, bold) segments for one ANSI-coloured line."""
    segments, buffer, fill, bold = [], [], DEFAULT_FILL, False

    def flush():
        if buffer:
            segments.append(("".join(buffer), fill, bold))
            buffer.clear()

    for chunk in ANSI.split(line):
        if chunk == "":
            continue
        if all(piece.isdigit() for piece in chunk.split(";")) and chunk.strip():
            flush()
            codes = chunk.split(";")
            if "0" in codes:
                fill, bold = DEFAULT_FILL, False
            else:
                bold = bold or "1" in codes
                for code in reversed(codes):
                    if code in FILL:
                        fill = FILL[code]
                        break
            continue
        buffer.append(chunk)
    flush()
    return segments


def ansi_to_svg(text: str, title: str = "wraith demo") -> str:
    lines = text.rstrip("\n").split("\n")
    pad_x, pad_y, width = 26, 24, 1080
    top = 70
    height = top + pad_y * 2 + LINE_H * len(lines)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height:.0f}" '
        f'viewBox="0 0 {width} {height:.0f}" xml:space="preserve" '
        'font-family="ui-monospace, SFMono-Regular, Menlo, DejaVu Sans Mono, monospace">',
        '<rect width="100%" height="100%" fill="#0b0e14"/>',
        f'<rect x="24" y="24" width="{width - 48}" height="{height - 48:.0f}" rx="12" '
        'fill="#0f131c" stroke="#1d2431"/>',
        f'<rect x="24" y="24" width="{width - 48}" height="46" rx="12" fill="#141a24"/>',
        '<circle cx="52" cy="47" r="6" fill="#ff5f57"/>'
        '<circle cx="74" cy="47" r="6" fill="#febc2e"/>'
        '<circle cx="96" cy="47" r="6" fill="#28c840"/>',
        f'<text x="122" y="52" fill="#6b7688" font-size="13">{html.escape(title)}</text>',
    ]
    y = top + pad_y
    left = 24 + pad_x
    for line in lines:
        column = 0
        for chunk, fill, bold in tokenize(line):
            # Position by column instead of trusting the renderer with whitespace.
            body = chunk.strip(" ")
            column += len(chunk) - len(chunk.lstrip(" "))
            if body:
                weight = ' font-weight="700"' if bold else ""
                x = left + column * CHAR_W
                out.append(
                    f'<text x="{x:.1f}" y="{y:.1f}" font-size="14" fill="{fill}"{weight}>'
                    f"{html.escape(body)}</text>"
                )
            column += len(body) + (len(chunk) - len(chunk.rstrip(" ")) if body else 0)
        y += LINE_H
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run(
            [sys.executable, "-m", "wraith", "demo", "--color", "always", "--evidence-dir", "runs"],
            capture_output=True, text=True, cwd=tmp, timeout=120,
            env=dict(os.environ, PYTHONPATH=ROOT),
        )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode

    svg_path = os.path.join(ROOT, "docs", "demo.svg")
    with open(svg_path, "w", encoding="utf-8") as handle:
        handle.write(ansi_to_svg(proc.stdout))
    print(svg_path)

    png_path = os.path.join(ROOT, "docs", "demo.png")
    match = re.search(r'height="([0-9.]+)"', open(svg_path, encoding="utf-8").read(400))
    height = int(float(match.group(1))) + 8 if match else 900
    try:
        subprocess.run(
            [
                "chromium", "--headless=new", "--no-sandbox", "--disable-gpu",
                "--disable-dev-shm-usage", "--hide-scrollbars", "--virtual-time-budget=3000",
                "--force-device-scale-factor=2", f"--window-size=1080,{height}",
                f"--screenshot={png_path}", f"file://{svg_path}",
            ],
            check=True, capture_output=True, timeout=180,
        )
        print(png_path)
    except (FileNotFoundError, subprocess.SubprocessError):
        print("chromium not available; svg only", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
