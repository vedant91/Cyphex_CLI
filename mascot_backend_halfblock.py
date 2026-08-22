"""mascot_backend_halfblock.py
================================

Universal truecolor Unicode half-block renderer for the CYPHEX CLI pixel-art
robot mascot.

Target environment: terminals that support 24-bit ("truecolor") ANSI color
codes but do NOT support an inline-image protocol (Kitty graphics, iTerm2
inline images, Sixel, ...). This is the overwhelmingly common case across
real-world terminal emulators, so this backend is the safe universal
fallback every CLI mascot renderer should have.

Technique
---------
Each terminal cell is (roughly) twice as tall as it is wide. We exploit the
Unicode "upper half block" glyph (U+2580, ``▀``) together with independently
settable ANSI foreground/background colors to pack TWO vertically stacked
source pixels into ONE terminal cell:

    * the glyph's own (foreground) half is colored with the TOP source pixel
    * the cell's background is colored with the BOTTOM source pixel

This doubles the effective vertical resolution we can render at a given
character-cell budget, which is exactly what pixel-art mascots need since
terminal cells are not square.

Resampling filter
------------------
The mascot art is small (roughly 100-180px on a side) hand-authored pixel
art, and target widths are also small (18-40 columns), so every resize here
is a HEAVY, non-integer-ratio downsample (e.g. 109px -> 28px is a ~3.9x
reduction). We empirically compared ``Image.NEAREST`` against ``Image.BOX``
by rendering idle.png and success.png at target_cols = 18, 28, and 40 and
visually inspecting the results (see the QA PNGs this module can produce via
``dump_preview_png``):

    * ``Image.NEAREST`` picks one arbitrary source pixel per output pixel.
      Because the resize ratio is not an integer, this produces visible
      aliasing/moire speckle noise -- thin details (like the "CYPHEX" chest
      text) come out jagged and harder to read.
    * ``Image.BOX`` averages every source pixel that falls under each output
      pixel's footprint. At these ratios it reads distinctly crisper and
      cleaner than NEAREST -- edges stay sharp (it is still a hard box
      average, not a smooth/ringing filter like LANCZOS) while removing the
      speckle, and small text elements stay legible.

``Image.BOX`` was the clear winner at all three tested widths for both test
images, so it is used as the resize filter (``_RESAMPLE_FILTER`` below).
LANCZOS/BICUBIC are avoided entirely per the spec, since their ringing/blur
is wrong for hard-edged pixel art.

Public API
----------
    render_frame(img, target_cols, truecolor=True) -> str
    row_count(target_cols, img) -> int
    dump_preview_png(img, target_cols, out_path) -> str
"""

from __future__ import annotations

import os
from typing import Tuple

from PIL import Image, ImageDraw

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RESET = "\x1b[0m"

# Fully transparent threshold: an alpha value below this is treated as "not
# there" for the purposes of half-block compositing (see module docstring
# for the empirical rationale on filter choice; this threshold is per spec).
ALPHA_TRANSPARENT = 20

# Chosen after visually comparing NEAREST vs BOX at target_cols 18/28/40 on
# idle.png and success.png -- BOX reads crisper and less noisy for this
# heavy, non-integer-ratio pixel-art downsample. See module docstring.
_RESAMPLE_FILTER = Image.BOX

UPPER_HALF_BLOCK = "▀"  # ▀  fg = top pixel, bg = bottom pixel
LOWER_HALF_BLOCK = "▄"  # ▄  fg = bottom pixel (used when only the top
                             #    pixel of a pair is transparent, so we
                             #    still paint the opaque bottom pixel without
                             #    forcing a background color)


# ---------------------------------------------------------------------------
# Sizing helpers
# ---------------------------------------------------------------------------

def _resize_dims(img: Image.Image, target_cols: int) -> Tuple[int, int]:
    """Compute the (source_width, source_height) to resize ``img`` to for a
    render at ``target_cols`` terminal columns wide.

    Aspect ratio is preserved in *source pixel* space: each terminal row
    consumes exactly two source pixel rows (the half-block trick), so the
    resized height is simply ``target_cols * (orig_h / orig_w)`` rounded to
    the nearest even integer (so pixel rows pair up cleanly with no leftover
    unpaired row).
    """
    target_cols = max(1, int(target_cols))
    orig_w, orig_h = img.size
    if orig_w <= 0 or orig_h <= 0:
        return target_cols, 2

    aspect = orig_h / orig_w
    new_h = int(round(target_cols * aspect))
    if new_h < 2:
        new_h = 2
    if new_h % 2:
        new_h += 1
    return target_cols, new_h


def row_count(target_cols: int, img: Image.Image) -> int:
    """Return how many terminal rows a render of ``img`` at ``target_cols``
    will occupy. Callers use this to know how far to cursor-up before
    redrawing the next frame in place.
    """
    _, new_h = _resize_dims(img, target_cols)
    return new_h // 2


# ---------------------------------------------------------------------------
# Color quantization (256-color fallback)
# ---------------------------------------------------------------------------

def _rgb_to_xterm256(r: int, g: int, b: int) -> int:
    """Quantize an 8-bit RGB triple to the nearest xterm-256 color index
    using the standard 6x6x6 color-cube + 24-step greyscale-ramp formula.
    """
    if r == g == b:
        if r < 8:
            return 16
        if r > 248:
            return 231
        return 232 + round((r - 8) / 247 * 24)

    def cube(v: int) -> int:
        return round(v / 255 * 5)

    return 16 + 36 * cube(r) + 6 * cube(g) + cube(b)


def _fg_code(r: int, g: int, b: int, truecolor: bool) -> str:
    if truecolor:
        return f"38;2;{r};{g};{b}"
    return f"38;5;{_rgb_to_xterm256(r, g, b)}"


def _bg_code(r: int, g: int, b: int, truecolor: bool) -> str:
    if truecolor:
        return f"48;2;{r};{g};{b}"
    return f"48;5;{_rgb_to_xterm256(r, g, b)}"


# ---------------------------------------------------------------------------
# Core resize
# ---------------------------------------------------------------------------

def _prepare_pixels(img: Image.Image, target_cols: int):
    """Downsample ``img`` to the render resolution and return
    (target_cols, rows, pixel_access) where pixel_access[x, y] -> (r,g,b,a).
    """
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    cols, new_h = _resize_dims(img, target_cols)
    resized = img.resize((cols, new_h), resample=_RESAMPLE_FILTER)
    rows = new_h // 2
    return cols, rows, resized.load()


def _cell_codes(top, bot, truecolor: bool):
    """Given a (r,g,b,a) pair for the top and bottom source pixel of one
    terminal cell, return the text to emit for that cell (color codes +
    glyph, or a plain space). No reset is included here; the caller resets
    once per cell to guarantee no color state leaks into an adjacent
    transparent cell.
    """
    tr, tg, tb, ta = top
    br, bg, bb, ba = bot
    top_transparent = ta < ALPHA_TRANSPARENT
    bot_transparent = ba < ALPHA_TRANSPARENT

    if top_transparent and bot_transparent:
        return " "

    if top_transparent and not bot_transparent:
        # Only the bottom pixel is real -> paint just the lower half with
        # its own color and leave no background set, so the real terminal
        # background shows through the top half cleanly (no hard seam from
        # guessing a fill color for the missing pixel).
        code = _fg_code(br, bg, bb, truecolor)
        return f"\x1b[{code}m{LOWER_HALF_BLOCK}"

    if bot_transparent and not top_transparent:
        # Mirror case: only the top pixel is real.
        code = _fg_code(tr, tg, tb, truecolor)
        return f"\x1b[{code}m{UPPER_HALF_BLOCK}"

    # Both pixels opaque: classic half-block packing.
    fg = _fg_code(tr, tg, tb, truecolor)
    bg_ = _bg_code(br, bg, bb, truecolor)
    return f"\x1b[{fg};{bg_}m{UPPER_HALF_BLOCK}"


def render_frame(img: Image.Image, target_cols: int, truecolor: bool = True) -> str:
    """Render ``img`` as a block of ANSI text ``target_cols`` columns wide.

    Each terminal row encodes two vertically-stacked source pixel rows via
    the U+2580 upper-half-block trick (ANSI truecolor/256-color foreground =
    top pixel, background = bottom pixel). Fully-transparent pixel pairs
    (both alpha < 20) become a plain space with no color codes at all, so
    the real terminal background shows through. Mixed pairs (one pixel
    transparent, one opaque) render with only a foreground color set and the
    matching half-block glyph, so the opaque pixel is still shown accurately
    without forcing a background fill color for its transparent partner.

    The returned string has no leading/trailing blank lines, each line ends
    with the ANSI reset code, and (since the layout depends only on
    ``img.size`` and ``target_cols``, never on pixel content) the total
    line count is always exactly ``row_count(target_cols, img)`` -- stable
    across repeated calls, so a caller's in-place redraw loop can rely on a
    fixed cursor-up distance.

    Args:
        img: a PIL Image (any mode; converted to RGBA internally).
        target_cols: desired render width in terminal columns.
        truecolor: if True, emit 24-bit ANSI truecolor codes (``38;2;..``/
            ``48;2;..``). If False, quantize to the nearest xterm-256 color
            cube index and emit 256-color codes (``38;5;..``/``48;5;..``)
            for terminals whose TERM contains '256color' but which lack
            COLORTERM=truecolor.

    Returns:
        The rendered frame as a single string with '\\n'-joined rows.
    """
    cols, rows, px = _prepare_pixels(img, target_cols)

    lines = []
    for row in range(rows):
        y_top = row * 2
        y_bot = y_top + 1
        parts = []
        for x in range(cols):
            cell = _cell_codes(px[x, y_top], px[x, y_bot], truecolor)
            # Reset immediately after any colored cell so color state can
            # never leak into a following transparent (plain-space) cell.
            if cell != " ":
                cell += RESET
            parts.append(cell)
        lines.append("".join(parts) + RESET)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# QA helper: rasterize what the half-block render would look like
# ---------------------------------------------------------------------------

def dump_preview_png(img: Image.Image, target_cols: int, out_path: str,
                      cell_w: int = 10, cell_h: int = 20) -> str:
    """Debugging/QA aid: re-rasterize what ``render_frame`` would produce
    into an actual flat PNG, so a human can judge downsample quality without
    a real terminal.

    Each terminal cell becomes a ``cell_w`` x ``cell_h`` block in the output
    image, drawn as two stacked ``cell_w`` x ``cell_h/2`` rectangles: the top
    rectangle filled with the top source pixel's color, the bottom rectangle
    filled with the bottom source pixel's color -- exactly mirroring the
    fg/bg colors the real ANSI renderer computes for that cell. Cells where
    a half is fully transparent are left transparent (alpha 0) in that half
    of the output PNG, rather than guessing a fill color, so the "real
    terminal background would show through" behavior is visible when the
    PNG is viewed over a checkered/transparent backdrop.

    Args:
        img: source PIL Image.
        target_cols: render width in terminal columns (same value you'd
            pass to render_frame / row_count).
        out_path: file path to save the PNG to.
        cell_w: pixel width per terminal cell in the output raster.
        cell_h: pixel height per terminal cell in the output raster (split
            evenly between the top and bottom half-pixel rectangles).

    Returns:
        The ``out_path`` it wrote to (for convenience).
    """
    cols, rows, px = _prepare_pixels(img, target_cols)
    half_h = cell_h // 2

    canvas = Image.new("RGBA", (cols * cell_w, rows * cell_h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)

    for row in range(rows):
        y_top = row * 2
        y_bot = y_top + 1
        for x in range(cols):
            tr, tg, tb, ta = px[x, y_top]
            br, bg, bb, ba = px[x, y_bot]

            px0 = x * cell_w
            py0 = row * cell_h

            if ta >= ALPHA_TRANSPARENT:
                draw.rectangle(
                    [px0, py0, px0 + cell_w - 1, py0 + half_h - 1],
                    fill=(tr, tg, tb, 255),
                )
            if ba >= ALPHA_TRANSPARENT:
                draw.rectangle(
                    [px0, py0 + half_h, px0 + cell_w - 1, py0 + cell_h - 1],
                    fill=(br, bg, bb, 255),
                )

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    canvas.save(out_path)
    return out_path


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    HERE = os.path.dirname(os.path.abspath(__file__))
    ASSETS = os.path.join(HERE, "assets", "mascot")

    idle_path = os.path.join(ASSETS, "idle.png")
    success_path = os.path.join(ASSETS, "success.png")

    idle_img = Image.open(idle_path)
    success_img = Image.open(success_path)

    TARGET_COLS = 28

    print("=== idle.png (target_cols=28, truecolor) ===")
    idle_frame = render_frame(idle_img, TARGET_COLS, truecolor=True)
    print(idle_frame)
    print()

    print("=== success.png (target_cols=28, truecolor) ===")
    success_frame = render_frame(success_img, TARGET_COLS, truecolor=True)
    print(success_frame)
    print()

    idle_ansi_path = os.path.join(HERE, "halfblock_preview_idle.ansi")
    success_ansi_path = os.path.join(HERE, "halfblock_preview_success.ansi")

    with open(idle_ansi_path, "w", encoding="utf-8") as f:
        f.write(idle_frame)
    with open(success_ansi_path, "w", encoding="utf-8") as f:
        f.write(success_frame)

    idle_rows = row_count(TARGET_COLS, idle_img)
    success_rows = row_count(TARGET_COLS, success_img)

    idle_bytes = len(idle_frame.encode("utf-8"))
    success_bytes = len(success_frame.encode("utf-8"))

    print("--- self-test report ---")
    print(f"idle.png:    {idle_bytes} bytes, {idle_rows} rows -> {idle_ansi_path}")
    print(f"success.png: {success_bytes} bytes, {success_rows} rows -> {success_ansi_path}")

    # QA rasterization (debugging aid, not part of the ANSI pipeline).
    qa_idle_path = os.path.join(ASSETS, "..", "mascot_qa_halfblock_idle.png")
    qa_success_path = os.path.join(ASSETS, "..", "mascot_qa_halfblock_success.png")

    dump_preview_png(idle_img, TARGET_COLS, qa_idle_path)
    dump_preview_png(success_img, TARGET_COLS, qa_success_path)

    print(f"QA PNG (idle):    {os.path.abspath(qa_idle_path)}")
    print(f"QA PNG (success): {os.path.abspath(qa_success_path)}")
