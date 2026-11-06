"""Render docs/social.png — the 1280x640 card for GitHub, X and Telegram previews."""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANS_BOLD = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
MONO = "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf"
MONO_BOLD = "/usr/share/fonts/liberation-mono/LiberationMono-Bold.ttf"

W, H = 1280, 640
BG = (11, 14, 20)
PANEL = (15, 19, 28)
BORDER = (29, 36, 49)
TEXT = (230, 237, 247)
MUTED = (123, 132, 148)
ACCENT = (255, 107, 107)
CYAN = (87, 209, 209)
GREEN = (94, 224, 138)
YELLOW = (255, 209, 102)


def main() -> int:
    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)

    for x in range(0, W, 32):
        draw.line([(x, 0), (x, H)], fill=(15, 18, 26))
    for y in range(0, H, 32):
        draw.line([(0, y), (W, y)], fill=(15, 18, 26))

    title = ImageFont.truetype(SANS_BOLD, 96)
    tagline = ImageFont.truetype(SANS, 28)
    bullet = ImageFont.truetype(SANS, 21)
    small = ImageFont.truetype(MONO, 16)
    mono = ImageFont.truetype(MONO, 15)
    mono_bold = ImageFont.truetype(MONO_BOLD, 15)

    draw.text((72, 96), "WRAITH", font=title, fill=TEXT)
    draw.text((76, 214), "Proof of impact for AI attack surfaces.", font=tagline, fill=CYAN)

    lines = [
        ("probe MCP servers for tool poisoning", ACCENT),
        ("decode instructions hidden in unicode", YELLOW),
        ("catch annotations that lie about a tool", GREEN),
        ("ship a report a triager can reproduce", MUTED),
    ]
    y = 292
    for text, colour in lines:
        draw.ellipse([78, y + 8, 88, y + 18], fill=colour)
        draw.text((104, y), text, font=bullet, fill=(200, 208, 220))
        y += 42

    draw.text((76, 528), "github.com/MRvirusIR/wraith", font=small, fill=MUTED)
    draw.text((76, 560), "pipx install git+https://github.com/MRvirusIR/wraith", font=small, fill=(96, 106, 122))

    box = [760, 96, 1216, 544]
    draw.rounded_rectangle(box, radius=14, fill=PANEL, outline=BORDER)
    draw.rounded_rectangle([760, 96, 1216, 138], radius=14, fill=(20, 26, 36))
    for index, colour in enumerate(((255, 95, 87), (254, 188, 46), (40, 200, 64))):
        cx = 790 + index * 20
        draw.ellipse([cx - 5, 112, cx + 5, 122], fill=colour)
    draw.text((852, 110), "wraith demo", font=mono, fill=MUTED)

    rows = [
        ("$ ", MUTED, "wraith demo", TEXT, ""),
        ("", TEXT, "", TEXT, ""),
        ("HIGH", ACCENT, "  annotation-lie      delete_account", TEXT, ""),
        ("", TEXT, "  declares readOnlyHint but writes", MUTED, ""),
        ("HIGH", ACCENT, "  unicode-obfuscation  summarize", TEXT, ""),
        ("", TEXT, "  hidden tag chars decoded", MUTED, ""),
        ("HIGH", ACCENT, "  hidden-instruction   search_docs", TEXT, ""),
        ("", TEXT, "  \"ignore previous instructions\"", MUTED, ""),
        ("", TEXT, "", TEXT, ""),
        ("", TEXT, "10 findings · 7 high · 3 medium", TEXT, ""),
        ("", GREEN, "VERDICT  do not connect this server", TEXT, ""),
    ]
    y = 166
    for badge, badge_colour, body, body_colour, _ in rows:
        if badge:
            draw.text((790, y), badge.ljust(6), font=mono_bold, fill=badge_colour)
        draw.text((880, y), body, font=mono, fill=body_colour)
        y += 28

    out = os.path.join(ROOT, "docs", "social.png")
    image.save(out)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
