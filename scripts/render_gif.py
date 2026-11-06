"""Render the demo output to an animated GIF for the launch.

Line-by-line reveal with a cursor, drawn with Pillow from the real CLI output.
`python scripts/render_gif.py`
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render_demo import FILL, tokenize  # noqa: E402

FONT_REGULAR = "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf"
FONT_BOLD = "/usr/share/fonts/liberation-mono/LiberationMono-Bold.ttf"

WIDTH = 980
PAD_X = 26
TOP = 76
LINE_H = 21
FONT_SIZE = 13

BG = "#0b0e14"
PANEL = "#0f131c"
BAR = "#141a24"
BORDER = "#1d2431"
DEFAULT = "#dfe6f1"
CURSOR = "#5ee08a"


def capture() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run(
            [sys.executable, "-m", "wraith", "demo", "--color", "always", "--evidence-dir", "runs"],
            capture_output=True, text=True, cwd=tmp, timeout=120,
            env=dict(os.environ, PYTHONPATH=ROOT),
        )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr)
    return proc.stdout.rstrip("\n")


def frame(lines, upto, fonts, char_w, height, cursor: bool):
    image = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([16, 16, WIDTH - 16, height - 16], radius=12, fill=PANEL, outline=BORDER)
    draw.rounded_rectangle([16, 16, WIDTH - 16, 58], radius=12, fill=BAR)
    for index, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        cx = 42 + index * 22
        draw.ellipse([cx - 6, 31, cx + 6, 43], fill=colour)
    draw.text((116, 30), "wraith demo", font=fonts["regular"], fill="#6b7688")

    y = TOP
    for line in lines[:upto]:
        column = 0
        for chunk, fill, bold in tokenize(line):
            body = chunk.strip(" ")
            column += len(chunk) - len(chunk.lstrip(" "))
            if body:
                draw.text(
                    (PAD_X + column * char_w, y),
                    body,
                    font=fonts["bold"] if bold else fonts["regular"],
                    fill=fill,
                )
            column += len(body) + (len(chunk) - len(chunk.rstrip(" ")) if body else 0)
        y += LINE_H
    if cursor and upto < len(lines):
        draw.rectangle([PAD_X, y + 2, PAD_X + char_w, y + LINE_H - 2], fill=CURSOR)
    return image


def main() -> int:
    text = capture()
    lines = text.split("\n")
    fonts = {
        "regular": ImageFont.truetype(FONT_REGULAR, FONT_SIZE),
        "bold": ImageFont.truetype(FONT_BOLD, FONT_SIZE),
    }
    char_w = fonts["regular"].getlength("M")
    height = TOP + LINE_H * len(lines) + 34

    frames, durations = [], []
    step = 2
    for upto in range(step, len(lines) + 1, step):
        frames.append(frame(lines, upto, fonts, char_w, height, cursor=True))
        durations.append(280)
    frames.append(frame(lines, len(lines), fonts, char_w, height, cursor=False))
    durations.append(3200)

    out = os.path.join(ROOT, "docs", "demo.gif")
    frames[0].save(
        out, save_all=True, append_images=frames[1:], duration=durations,
        loop=0, optimize=True, disposal=2,
    )
    poster = os.path.join(ROOT, "docs", "demo.png")
    frames[-1].save(poster)
    print(out)
    print(poster)
    print(f"{len(frames)} frames, {os.path.getsize(out) / 1024:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
