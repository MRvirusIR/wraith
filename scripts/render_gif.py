"""Render the demo to docs/demo.gif and docs/demo.mp4.

Frames are drawn with Pillow from the real CLI output, so the animation always
matches what the tool actually prints.

    python scripts/render_gif.py          # both assets
    python scripts/render_gif.py --mp4    # only the video
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render_demo import tokenize  # noqa: E402

FONT_REGULAR = "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf"
FONT_BOLD = "/usr/share/fonts/liberation-mono/LiberationMono-Bold.ttf"

WIDTH, PAD_X, TOP, LINE_H, FONT_SIZE = 980, 26, 76, 21, 13
BG, PANEL, BAR, BORDER = "#0b0e14", "#0f131c", "#141a24", "#1d2431"
CURSOR = "#5ee08a"

VIDEO_FPS = 12
VIDEO_HOLD_FRAMES = 36
GIF_STEP = 2


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


class Canvas:
    def __init__(self, lines, scale=1):
        self.lines = lines
        self.scale = scale
        self.fonts = {
            "regular": ImageFont.truetype(FONT_REGULAR, FONT_SIZE * scale),
            "bold": ImageFont.truetype(FONT_BOLD, FONT_SIZE * scale),
        }
        self.char_w = self.fonts["regular"].getlength("M")
        self.width = WIDTH * scale
        self.height = (TOP + LINE_H * len(lines) + 34) * scale

    def frame(self, upto: int, cursor: bool = True) -> Image.Image:
        s = self.scale
        image = Image.new("RGB", (self.width, self.height), BG)
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle(
            [16 * s, 16 * s, self.width - 16 * s, self.height - 16 * s],
            radius=12 * s, fill=PANEL, outline=BORDER,
        )
        draw.rounded_rectangle([16 * s, 16 * s, self.width - 16 * s, 58 * s], radius=12 * s, fill=BAR)
        for index, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
            cx = (42 + index * 22) * s
            draw.ellipse([cx - 6 * s, 31 * s, cx + 6 * s, 43 * s], fill=colour)
        draw.text((116 * s, 30 * s), "wraith demo", font=self.fonts["regular"], fill="#6b7688")

        y = TOP * s
        for line in self.lines[:upto]:
            column = 0
            for chunk, fill, bold in tokenize(line):
                body = chunk.strip(" ")
                column += len(chunk) - len(chunk.lstrip(" "))
                if body:
                    draw.text(
                        (PAD_X * s + column * self.char_w, y),
                        body,
                        font=self.fonts["bold"] if bold else self.fonts["regular"],
                        fill=fill,
                    )
                column += len(body) + (len(chunk) - len(chunk.rstrip(" ")) if body else 0)
            y += LINE_H * s
        if cursor and upto < len(self.lines):
            draw.rectangle(
                [PAD_X * s, y + 2 * s, PAD_X * s + self.char_w, y + (LINE_H - 2) * s], fill=CURSOR
            )
        return image


def build_gif(canvas: Canvas) -> str:
    frames, durations = [], []
    for upto in range(GIF_STEP, len(canvas.lines) + 1, GIF_STEP):
        frames.append(canvas.frame(upto))
        durations.append(280)
    frames.append(canvas.frame(len(canvas.lines), cursor=False))
    durations.append(3200)
    out = os.path.join(ROOT, "docs", "demo.gif")
    frames[0].save(
        out, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True, disposal=2
    )
    frames[-1].save(os.path.join(ROOT, "docs", "demo.png"))
    print(f"{out}  ({len(frames)} frames, {os.path.getsize(out) / 1024:.0f} KB)")
    return out


def build_mp4(canvas: Canvas) -> str:
    if shutil.which("ffmpeg") is None:
        raise SystemExit("ffmpeg is required for the mp4 render")
    out = os.path.join(ROOT, "docs", "demo.mp4")
    with tempfile.TemporaryDirectory() as tmp:
        index = 0
        for upto in range(1, len(canvas.lines) + 1):
            canvas.frame(upto).save(os.path.join(tmp, f"f{index:04d}.png"))
            index += 1
        final = canvas.frame(len(canvas.lines), cursor=False)
        for _ in range(VIDEO_HOLD_FRAMES):
            final.save(os.path.join(tmp, f"f{index:04d}.png"))
            index += 1
        subprocess.run(
            [
                "ffmpeg", "-y", "-loglevel", "error", "-framerate", str(VIDEO_FPS),
                "-i", os.path.join(tmp, "f%04d.png"),
                "-c:v", "libx264", "-preset", "slow", "-crf", "20",
                "-pix_fmt", "yuv420p", "-movflags", "+faststart", out,
            ],
            check=True,
        )
    print(f"{out}  ({os.path.getsize(out) / 1024:.0f} KB)")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mp4", action="store_true", help="only render the video")
    parser.add_argument("--gif", action="store_true", help="only render the gif")
    args = parser.parse_args()

    lines = capture().split("\n")
    if not args.gif:
        build_mp4(Canvas(lines, scale=2))
    if not args.mp4:
        build_gif(Canvas(lines, scale=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
