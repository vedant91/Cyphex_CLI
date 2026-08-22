"""mascot_remaster_qa.py
=======================

Generate the human-reviewable QA evidence for :mod:`mascot_remaster` into
``assets/qa/``.

Three kinds of sheet are produced:

``<stem>_sheet.png``
    One per remastered asset. The sprite at every width in
    ``mascot_remaster.DEFAULT_COLS``, upscaled 12x with ``Image.NEAREST``
    (so you see the actual pixel grid, not an interpolation of it) and
    composited over the same dark ``(8, 8, 10)`` ground the terminal has.
    Bottom-aligned so the sizes compare directly.

``all_assets_24.png``
    Every asset at cols=24 in one overview, for judging the set as a set.

``remaster_before_after.png``
    The proof the fix worked. For ``idle``, ``scan``, ``expr_thinking`` and
    ``expr_error``: the sprite downsampled the OLD way (straight
    ``Image.BOX`` to the same grid, no premultiply, no palette snap, no
    alpha re-hardening -- exactly what ``mascot_backend_halfblock`` does to
    a raw source PNG today) next to the remastered version.

Run: ``python mascot_remaster_qa.py``
"""

from __future__ import annotations

import os
from typing import List, Sequence, Tuple

from PIL import Image, ImageDraw, ImageFont

import mascot_remaster as MR

HERE = os.path.dirname(os.path.abspath(__file__))
QA_DIR = os.path.join(HERE, "assets", "qa")

#: The terminal ground colour the mascot is judged against.
BG = (8, 8, 10, 255)

SCALE = 12          # NEAREST upscale factor for the contact sheets
PAD = 16
LABEL_H = 20
HEADER_H = 30

BEFORE_AFTER_ASSETS = ("idle", "scan", "expr_thinking", "expr_error")
BEFORE_AFTER_COLS = 24


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

_FONT_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)


def _font(size: int):
    for path in _FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


FONT = _font(15)
FONT_SMALL = _font(13)
FONT_BIG = _font(19)


# ---------------------------------------------------------------------------
# The "old way" downsample, for the before/after comparison
# ---------------------------------------------------------------------------

def old_way(src: str, cols: int) -> Image.Image:
    """Downsample ``src`` the way the shipped renderer does today.

    Straight ``Image.BOX`` on non-premultiplied RGBA to the render grid, and
    nothing else: no premultiply (so the transparent-black surround bleeds a
    dark fringe in), no gamma, no saturation, no palette snap (so the JPEG
    noise survives as thousands of muddy near-colours), no alpha
    re-hardening (so the edge keeps a soft fractional halo).
    """
    img = Image.open(src).convert("RGBA")
    return img.resize(MR.grid_for_cols(img, cols), Image.BOX)


# ---------------------------------------------------------------------------
# Composition helpers
# ---------------------------------------------------------------------------

def _upscale(img: Image.Image, scale: int = SCALE) -> Image.Image:
    return img.resize((img.width * scale, img.height * scale), Image.NEAREST)


def _paste(canvas: Image.Image, img: Image.Image, x: int, y: int) -> None:
    """Composite ``img`` (which may carry fractional alpha) onto ``canvas``."""
    canvas.alpha_composite(img, (x, y))


def _sheet(panels: Sequence[Tuple[str, Image.Image]], title: str,
           out_path: str, sub: str = "") -> str:
    """Lay ``panels`` out in one bottom-aligned row and save."""
    ups = [(lbl, _upscale(im)) for lbl, im in panels]
    max_h = max(im.height for _, im in ups)
    total_w = sum(im.width for _, im in ups) + PAD * (len(ups) + 1)
    head = HEADER_H + (20 if sub else 0)
    total_h = head + max_h + LABEL_H + PAD * 2

    canvas = Image.new("RGBA", (total_w, total_h), BG)
    d = ImageDraw.Draw(canvas)
    d.text((PAD, 8), title, font=FONT_BIG, fill=(255, 255, 255))
    if sub:
        d.text((PAD, 8 + 22), sub, font=FONT_SMALL, fill=(150, 150, 155))

    x = PAD
    base_y = head + PAD + max_h
    for lbl, im in ups:
        _paste(canvas, im, x, base_y - im.height)
        d.text((x, base_y + 4), lbl, font=FONT, fill=(200, 200, 205))
        x += im.width + PAD

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    canvas.convert("RGB").save(out_path)
    return out_path


# ---------------------------------------------------------------------------
# Sheets
# ---------------------------------------------------------------------------

def build_asset_sheets(qa_dir: str = QA_DIR) -> List[str]:
    """One contact sheet per asset: every width, 12x NEAREST, on dark ground."""
    written = []
    for stem in MR.source_stems():
        p = MR.params_for(stem)
        panels = [(f"cols={c}", MR.load_remastered(stem, c))
                  for c in MR.DEFAULT_COLS]
        sub = (f"sat={p['sat']}  gamma={p['gamma']}  black_floor={p['black_floor']}  "
               f"despeckle={p['despeckle']}  |  {SCALE}x NEAREST on rgb(8,8,10)")
        written.append(_sheet(panels, stem, os.path.join(qa_dir, f"{stem}_sheet.png"), sub))
    return written


def build_overview(qa_dir: str = QA_DIR, cols: int = 24) -> str:
    """Every asset at one width, so the set can be judged as a set."""
    panels = [(stem, MR.load_remastered(stem, cols)) for stem in MR.source_stems()]
    # Two rows so the sheet stays a sane shape.
    half = (len(panels) + 1) // 2
    rows = [panels[:half], panels[half:]]

    ups = [[(l, _upscale(i, 8)) for l, i in r] for r in rows]
    row_h = [max(i.height for _, i in r) for r in ups]
    row_w = [sum(i.width for _, i in r) + PAD * (len(r) + 1) for r in ups]
    W = max(row_w)
    H = HEADER_H + sum(h + LABEL_H + PAD for h in row_h) + PAD

    canvas = Image.new("RGBA", (W, H), BG)
    d = ImageDraw.Draw(canvas)
    d.text((PAD, 8), f"CYPHEX mascot -- remastered set @ cols={cols} (8x NEAREST)",
           font=FONT_BIG, fill=(255, 255, 255))

    y = HEADER_H
    for r, rh in zip(ups, row_h):
        x = PAD
        base = y + rh
        for lbl, im in r:
            _paste(canvas, im, x, base - im.height)
            d.text((x, base + 4), lbl, font=FONT_SMALL, fill=(200, 200, 205))
            x += im.width + PAD
        y += rh + LABEL_H + PAD

    out = os.path.join(qa_dir, f"all_assets_{cols}.png")
    os.makedirs(qa_dir, exist_ok=True)
    canvas.convert("RGB").save(out)
    return out


def build_before_after(qa_dir: str = QA_DIR) -> str:
    """The evidence sheet: old downsample vs remaster, side by side."""
    cols = BEFORE_AFTER_COLS
    pairs = []
    for stem in BEFORE_AFTER_ASSETS:
        src = os.path.join(MR.ASSET_DIR, stem + ".png")
        pairs.append((stem, _upscale(old_way(src, cols)),
                      _upscale(MR.load_remastered(stem, cols))))

    gap, group_gap = 10, 46
    max_h = max(max(b.height, a.height) for _, b, a in pairs)
    W = sum(b.width + gap + a.width for _, b, a in pairs) \
        + group_gap * (len(pairs) - 1) + PAD * 2
    head = 78
    H = head + max_h + LABEL_H * 2 + PAD * 2

    canvas = Image.new("RGBA", (W, H), BG)
    d = ImageDraw.Draw(canvas)
    d.text((PAD, 10), "CYPHEX mascot remaster -- BEFORE vs AFTER",
           font=FONT_BIG, fill=(255, 255, 255))
    d.text((PAD, 34),
           f"BEFORE = the shipped path: PIL BOX downsample to cols={cols}, no palette snap, "
           f"soft alpha  (idle.png source = 6263 unique colours)",
           font=FONT_SMALL, fill=(150, 150, 155))
    d.text((PAD, 52),
           "AFTER = mascot_remaster: BOX-first (premultiplied) -> saturation -> 6-colour "
           "palette snap -> despeckle -> binary alpha",
           font=FONT_SMALL, fill=(150, 150, 155))

    x = PAD
    base = head + PAD + max_h
    for stem, before, after in pairs:
        d.text((x, head - 4), stem, font=FONT, fill=(235, 235, 240))
        _paste(canvas, before, x, base - before.height)
        d.text((x, base + 4), "BEFORE", font=FONT, fill=(210, 130, 130))
        d.text((x, base + 22), "muddy / soft", font=FONT_SMALL, fill=(130, 130, 135))
        x += before.width + gap
        _paste(canvas, after, x, base - after.height)
        d.text((x, base + 4), "AFTER", font=FONT, fill=(120, 220, 130))
        d.text((x, base + 22), "6 colours / hard", font=FONT_SMALL, fill=(130, 130, 135))
        x += after.width + group_gap

        # divider between asset groups
        if stem != pairs[-1][0]:
            dx = x - group_gap // 2
            d.line([(dx, head - 8), (dx, base + 34)], fill=(46, 46, 52), width=2)

    out = os.path.join(qa_dir, "remaster_before_after.png")
    os.makedirs(qa_dir, exist_ok=True)
    canvas.convert("RGB").save(out)
    return out


if __name__ == "__main__":
    os.makedirs(QA_DIR, exist_ok=True)
    sheets = build_asset_sheets()
    overview = build_overview()
    ba = build_before_after()
    print(f"{len(sheets)} per-asset sheets -> {QA_DIR}")
    print(f"overview       -> {overview}")
    print(f"before/after   -> {ba}")
