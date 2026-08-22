"""mascot_backend_subcell.py
============================

Higher-density truecolor sub-cell renderers for the CYPHEX CLI pixel-art
mascot -- a drop-in sibling of :mod:`mascot_backend_halfblock` that packs
FOUR (quadrant) or SIX (sextant) source pixels into every terminal cell
instead of two.

Why
---
The half-block backend (U+2580 ``▀``, fg = top pixel, bg = bottom pixel)
packs 1 x 2 subpixels per cell. That is universal and safe, but it is also
the *lowest* density option available: horizontally it is stuck at one
sample per column, which is why the mascot's pixels read chunky and
blown-out at the small column counts the CLI actually uses. This module
adds the two denser Unicode block families:

===========  ============  =====================  ==============  ===========
mode         subpixels     glyph family           horiz. detail   font risk
===========  ============  =====================  ==============  ===========
halfblock    1 x 2         U+2580/U+2584/U+2588   1x (baseline)   none
quadrant     2 x 2         U+2596..U+259F + half  **2x**          very low
sextant      2 x 3         U+1FB00..U+1FB3B       **2x**          HIGH
===========  ============  =====================  ==============  ===========

Note that quadrant and sextant give the same *horizontal* gain (2x); what
sextant adds is finer vertical sampling (3 rows per cell instead of 2),
which yields near-square subpixels and therefore the smoothest diagonals.
It is also the only mode whose glyphs are from Unicode 13 (2020) and are
missing from most stock macOS terminal fonts -- see "Font support" below.

**Recommended default: quadrant.** Sextant is opt-in.

More subpixels is not monotonically better
-------------------------------------------
Density buys spatial detail but *spends* color fidelity, because a cell
still gets only two colors no matter how finely it is subdivided. Measured
on a remastered ``idle.png``, mean per-cell quantization error (squared RGB,
opaque cells)::

    cols=20   halfblock    0.0     quadrant   510.1     sextant  2440.0
    cols=28   halfblock    0.0     quadrant   385.8     sextant  1030.1

Half-block is exactly zero by construction -- two subpixels, two colors, no
approximation is ever needed. Quadrant pays a modest price for doubling the
horizontal detail. Sextant pays 2.7x-4.8x more than quadrant for the same
horizontal detail, because it crams six subpixels into the same two-color
budget.

That trade shows up visually exactly where theory says it should. Sextant
wins on *silhouette geometry* -- bezel corners, antenna, diagonals -- where a
cell is naturally two-toned anyway. Sextant loses on *multi-color texture*:
on the mascot's "CYPHEX" screen wordmark, whose letterforms alternate at
close to the cell frequency, sextant merges the letters back into a notched
bar while quadrant keeps them separated. Quadrant is the better default not
merely because its glyphs are safer, but because it sits at the actual
optimum of this trade for this art.

The two-colors-per-cell problem
-------------------------------
ANSI gives each cell exactly two colors -- one foreground, one background --
no matter how many subpixels the glyph subdivides it into. Half-blocks are
the only family where that is not a constraint (2 subpixels, 2 colors, exact).
Quadrant needs 4 subpixels in 2 colors; sextant needs 6.

So every cell is a tiny 2-means clustering problem: partition the cell's
subpixel colors into two groups minimising total squared RGB error, then
pick the glyph whose "which corners are foreground" bitmask matches that
partition. With only 4 or 6 points this is solved **exactly by brute force**
-- 2^(n-1) candidate partitions, i.e. 8 for quadrant and 32 for sextant --
so there is no heuristic and no local minimum to worry about. Results are
memoised on the cell's color tuple (:func:`_solve_cell`), and since
palette-snapped mascot art has at most ~6 distinct colors the cache hit rate
during an animation loop is effectively 100%.

Group representative colors are chosen as the **weighted medoid** (the group
member that minimises within-group error), not the arithmetic mean. On
palette-snapped art the mean of two palette entries is a color that exists
nowhere in the design and reads as a blur; the medoid can only ever emit
colors the artist actually used, which is what keeps hard edges hard. Pass
``blend=True`` to switch to means for photographic (non-palettised) input.

Transparency
------------
A subpixel with alpha below :data:`ALPHA_TRANSPARENT` is not a color, it is
a hole. Holes are never averaged into a group and never get a background
color assigned; instead the glyph is chosen so that the *opaque* subpixels
are the foreground and no background is set at all, letting the real
terminal background show through. This is the same rule the half-block
backend uses for its mixed pairs, and it is what prevents the dark halo /
fringe you get from guessing a fill color for the missing pixels.

Aspect correctness (the easy thing to get subtly wrong)
--------------------------------------------------------
A terminal cell is about **1 wide x 2 tall** in pixel-aspect terms. That
makes the *subpixel* shapes differ per mode::

    halfblock  1 x 2 grid  ->  subpixel is 1.0 w x 1.0 h   (square)
    quadrant   2 x 2 grid  ->  subpixel is 0.5 w x 1.0 h   (tall)
    sextant    2 x 3 grid  ->  subpixel is 0.5 w x 0.667 h (nearly square)

Therefore the resample target is **not** the naive aspect-preserving box.
For ``C`` columns and ``R`` rows the source must be resized to::

    halfblock -> (C,     2R)
    quadrant  -> (2C,    2R)
    sextant   -> (2C,    3R)

i.e. ``(C * subcols_per_cell, R * subrows_per_cell)`` -- see
:func:`subpixel_grid`. The quadrant grid being twice as wide as the
half-block grid for the *same physical size* looks wrong at a glance; it is
exactly right, because each of those columns is only half a cell wide. Skip
the compensation and the mascot comes out horizontally squashed to 50%.

``R`` is derived identically to ``mascot_backend_halfblock._resize_dims``,
so :func:`row_count` returns **the same number of terminal rows for all
three modes** and for the sibling module. Switching density can therefore
never change a frame's height -- which matters, because the in-place redraw
loop cursor-ups by an assumed row count and drifts (leaving half a robot on
screen) the moment a frame's real height disagrees with it.

Font support
------------
Quadrant glyphs (U+2596..U+259F, Unicode 1.1) are present in essentially
every monospace font shipped on a developer machine -- Menlo, SF Mono,
Consolas, Cascadia, DejaVu Sans Mono all have them -- and most modern
terminals draw them from built-in geometry anyway. Sextant glyphs
(U+1FB00..U+1FB3B, "Symbols for Legacy Computing", Unicode 13 / 2020) are
NOT in Menlo or SF Mono, so on stock macOS Terminal.app they render as tofu
boxes and the mascot becomes an unreadable grid of rectangles.

:func:`probe_glyph_support` therefore does conservative **environment
sniffing only**. It deliberately does NOT do the DECRQCPR / cursor-position-
report trick (print the glyph, ask where the cursor ended up, infer the
advance width): that requires reading from the tty, and on any terminal that
does not answer -- pipes, CI, tmux passthrough, editors' embedded terminals
-- it blocks until timeout or forever. This function performs no terminal
I/O whatsoever, cannot hang, and falls back to the *safe* mode when it does
not recognise the environment.

Public API
----------
    MODES / MODE_HALFBLOCK / MODE_QUADRANT / MODE_SEXTANT / DEFAULT_MODE
    render_frame(img, target_cols, truecolor=True, mode=..., blend=False) -> str
    row_count(target_cols, img, mode=...) -> int
    subpixel_grid(img, target_cols, mode=...) -> (w, h)
    prepare_source(src, target_cols, mode=..., **remaster_kw) -> Image
    probe_glyph_support(env=None, stream=None) -> dict
    best_mode(env=None, stream=None) -> str
    dump_preview_png(img, target_cols, out_path, mode=..., ...) -> str
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import Dict, Optional, Sequence, Tuple

from PIL import Image, ImageDraw

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RESET = "\x1b[0m"

#: Alpha at or below this is a hole, not a color. Matches the half-block
#: backend so the two agree on where the silhouette ends.
ALPHA_TRANSPARENT = 20

#: BOX (area average) for the same reason the half-block backend uses it:
#: these are heavy non-integer-ratio downsamples of hard-edged pixel art, and
#: BOX removes resampling speckle without the ringing/blur of LANCZOS.
_RESAMPLE_FILTER = Image.BOX

MODE_HALFBLOCK = "halfblock"
MODE_QUADRANT = "quadrant"
MODE_SEXTANT = "sextant"

MODES: Tuple[str, ...] = (MODE_HALFBLOCK, MODE_QUADRANT, MODE_SEXTANT)

#: Quadrant is the recommended default: 2x the horizontal detail of
#: half-blocks at effectively zero font risk. Sextant is opt-in.
DEFAULT_MODE = MODE_QUADRANT

#: (sub-columns, sub-rows) each terminal cell is divided into, per mode.
SUBGRID: Dict[str, Tuple[int, int]] = {
    MODE_HALFBLOCK: (1, 2),
    MODE_QUADRANT: (2, 2),
    MODE_SEXTANT: (2, 3),
}

#: Subpixels per cell, per mode (1x2 = 2, 2x2 = 4, 2x3 = 6).
SUBPIXELS_PER_CELL: Dict[str, int] = {
    m: c * r for m, (c, r) in SUBGRID.items()
}

#: Environment variable that overrides mode selection entirely.
#: ``halfblock`` / ``quadrant`` / ``sextant`` force a mode; ``auto`` allows
#: sextant to be auto-selected on terminals known to render it.
ENV_OVERRIDE = "CYPHEX_MASCOT_SUBCELL"


# ---------------------------------------------------------------------------
# Glyph tables
# ---------------------------------------------------------------------------
#
# In every table below, subpixels are numbered in reading order (left to
# right, then top to bottom) and bit ``i`` of the mask means "subpixel i is
# foreground". A mask of 0 is an empty cell, a mask of all-ones is a full
# block. Every mask in 0..2**n-1 is representable for all three modes, so the
# partition search never has to reject a candidate.

#: 1 x 2. bit0 = top, bit1 = bottom.
_GLYPHS_HALFBLOCK: Tuple[str, ...] = (
    " ",  # 0000 -- empty
    "▀",  # U+2580 UPPER HALF BLOCK
    "▄",  # U+2584 LOWER HALF BLOCK
    "█",  # U+2588 FULL BLOCK
)

#: 2 x 2. bit0 = top-left, bit1 = top-right, bit2 = bottom-left,
#: bit3 = bottom-right. Ten of the sixteen come from the QUADRANT block
#: (U+2596..U+259F); the other six are the empty cell, the full block and the
#: four half blocks, which Unicode does not duplicate in the quadrant range.
_GLYPHS_QUADRANT: Tuple[str, ...] = (
    " ",  # 0  ....  empty
    "▘",  # 1  TL    U+2598 QUADRANT UPPER LEFT
    "▝",  # 2  TR    U+259D QUADRANT UPPER RIGHT
    "▀",  # 3  TL TR U+2580 UPPER HALF BLOCK
    "▖",  # 4  BL    U+2596 QUADRANT LOWER LEFT
    "▌",  # 5  TL BL U+258C LEFT HALF BLOCK
    "▞",  # 6  TR BL U+259E QUADRANT UPPER RIGHT AND LOWER LEFT
    "▛",  # 7        U+259B QUADRANT UL AND UR AND LL
    "▗",  # 8  BR    U+2597 QUADRANT LOWER RIGHT
    "▚",  # 9  TL BR U+259A QUADRANT UPPER LEFT AND LOWER RIGHT
    "▐",  # 10 TR BR U+2590 RIGHT HALF BLOCK
    "▜",  # 11       U+259C QUADRANT UL AND UR AND LR
    "▄",  # 12 BL BR U+2584 LOWER HALF BLOCK
    "▙",  # 13       U+2599 QUADRANT UL AND LL AND LR
    "▟",  # 14       U+259F QUADRANT UR AND LL AND LR
    "█",  # 15       U+2588 FULL BLOCK
)


def _build_sextant_glyphs() -> Tuple[str, ...]:
    """Build the 64-entry 2x3 sextant table.

    bit0 = top-left, bit1 = top-right, bit2 = middle-left,
    bit3 = middle-right, bit4 = bottom-left, bit5 = bottom-right.

    U+1FB00..U+1FB3B is exactly 60 codepoints, not 64: Unicode deliberately
    omits the four sextant combinations that already had a character --
    empty (space), 1+3+5 = left half block, 2+4+6 = right half block, and
    all six = full block. The range is otherwise in strict ascending mask
    order, so the codepoint for mask ``m`` is ``0x1FB00 + m - 1`` minus one
    for each omitted mask below ``m``.
    """
    left_col = 0b010101   # 21: subpixels 1,3,5 -> U+258C
    right_col = 0b101010  # 42: subpixels 2,4,6 -> U+2590
    full = 0b111111       # 63: -> U+2588
    special = {0: " ", left_col: "▌", right_col: "▐", full: "█"}

    table = []
    for mask in range(64):
        if mask in special:
            table.append(special[mask])
            continue
        skipped = (mask > left_col) + (mask > right_col)  # 0 is always below
        table.append(chr(0x1FB00 + mask - 1 - skipped))
    return tuple(table)


#: 2 x 3, 64 entries. See :func:`_build_sextant_glyphs`.
_GLYPHS_SEXTANT: Tuple[str, ...] = _build_sextant_glyphs()

_GLYPH_TABLES: Dict[str, Tuple[str, ...]] = {
    MODE_HALFBLOCK: _GLYPHS_HALFBLOCK,
    MODE_QUADRANT: _GLYPHS_QUADRANT,
    MODE_SEXTANT: _GLYPHS_SEXTANT,
}


def glyph_table(mode: str = DEFAULT_MODE) -> Tuple[str, ...]:
    """Return the mask -> glyph table for ``mode`` (index = subpixel bitmask)."""
    return _GLYPH_TABLES[_check_mode(mode)]


def _check_mode(mode: str) -> str:
    if mode not in SUBGRID:
        raise ValueError(
            f"unknown mode {mode!r}; expected one of {', '.join(MODES)}"
        )
    return mode


# ---------------------------------------------------------------------------
# Sizing
# ---------------------------------------------------------------------------

def _cell_rows(img: Image.Image, target_cols: int, mode: str) -> int:
    """Terminal rows a render of ``img`` at ``target_cols`` occupies.

    Two cases, and conflating them is a trap worth spelling out:

    * ``img`` is **already on this mode's subpixel grid** (what
      :func:`prepare_source` returns): its width is ``cols * subcols`` and
      its pixels are non-square by construction, so its raw aspect ratio is
      meaningless. Read the row count straight back off the grid.
    * ``img`` is a **square-pixel source sprite**: derive the height exactly
      the way ``mascot_backend_halfblock._resize_dims`` does -- round the
      aspect-preserving height, floor at 2, round up to even, halve.

    Deriving from the aspect in the first case is what makes a quadrant frame
    come out half as tall as the half-block frame of the same sprite, and
    also forces a second resample that blends the palette back into mush.

    Either way the answer agrees with the half-block sibling for the same
    sprite, which is load-bearing: the animation loop cursor-ups by a fixed
    row count, and any disagreement between what it assumed and what was
    drawn leaves orphaned rows on screen -- the "half a robot with another
    robot appended below it" failure.
    """
    target_cols = max(1, int(target_cols))
    sub_cols, sub_rows = SUBGRID[mode]
    orig_w, orig_h = img.size
    if orig_w <= 0 or orig_h <= 0:
        return 1

    if orig_w == target_cols * sub_cols and orig_h % sub_rows == 0:
        return max(1, orig_h // sub_rows)

    new_h = int(round(target_cols * (orig_h / orig_w)))
    if new_h < 2:
        new_h = 2
    if new_h % 2:
        new_h += 1
    return new_h // 2


def row_count(target_cols: int, img: Image.Image,
              mode: str = DEFAULT_MODE) -> int:
    """Return how many terminal rows a render of ``img`` at ``target_cols``
    will occupy.

    All three modes are deliberately height-identical (and identical to
    ``mascot_backend_halfblock.row_count``) for a given sprite, so density
    can be switched without invalidating a redraw loop's cursor-up distance.
    Pass either the original square-pixel sprite or the image
    :func:`prepare_source` produced for this same ``mode``; both round-trip
    to the same row count.
    """
    return _cell_rows(img, target_cols, _check_mode(mode))


def subpixel_grid(img: Image.Image, target_cols: int,
                  mode: str = DEFAULT_MODE) -> Tuple[int, int]:
    """Return the ``(width, height)`` in *source pixels* that ``img`` must be
    resampled to for a ``target_cols``-wide render in ``mode``.

    This is ``(cols * subcols_per_cell, rows * subrows_per_cell)``. It is NOT
    an aspect-preserving box in square-pixel space, and it must not be: a
    terminal cell is 1 wide x 2 tall, so a 2x2 quadrant subpixel is half as
    wide as it is tall and needs twice as many horizontal samples to cover
    the same physical width. Resizing to the naive aspect box instead
    squashes the mascot to half width.

    Feed the result to a remaster/resize step (see :func:`prepare_source`)
    and hand the result to :func:`render_frame`, which will then do no
    resampling at all.
    """
    _check_mode(mode)
    sub_cols, sub_rows = SUBGRID[mode]
    cols = max(1, int(target_cols))
    rows = _cell_rows(img, cols, mode)
    return cols * sub_cols, rows * sub_rows


# ---------------------------------------------------------------------------
# Color coding (256-color fallback identical to the half-block backend)
# ---------------------------------------------------------------------------

def _rgb_to_xterm256(r: int, g: int, b: int) -> int:
    if r == g == b:
        if r < 8:
            return 16
        if r > 248:
            return 231
        return 232 + round((r - 8) / 247 * 24)

    def cube(v: int) -> int:
        return round(v / 255 * 5)

    return 16 + 36 * cube(r) + 6 * cube(g) + cube(b)


def _fg_code(rgb, truecolor: bool) -> str:
    r, g, b = rgb
    if truecolor:
        return f"38;2;{r};{g};{b}"
    return f"38;5;{_rgb_to_xterm256(r, g, b)}"


def _bg_code(rgb, truecolor: bool) -> str:
    r, g, b = rgb
    if truecolor:
        return f"48;2;{r};{g};{b}"
    return f"48;5;{_rgb_to_xterm256(r, g, b)}"


# ---------------------------------------------------------------------------
# The per-cell 2-means solve
# ---------------------------------------------------------------------------

def _sqdist(a, b) -> int:
    dr = a[0] - b[0]
    dg = a[1] - b[1]
    db = a[2] - b[2]
    return dr * dr + dg * dg + db * db


def _rep_and_cost(colors: Sequence, blend: bool):
    """Best single color for ``colors`` plus the squared error it incurs.

    ``blend=False`` (default) returns the weighted **medoid** -- the member
    color minimising within-group error -- which can only emit colors that
    already exist in the art, keeping a palette-snapped sprite palette-pure
    and its edges hard. ``blend=True`` returns the arithmetic mean, which is
    the true squared-error optimum and is the right choice for photographic
    input, at the cost of inventing in-between colors.
    """
    n = len(colors)
    if n == 0:
        return None, 0
    if n == 1:
        return colors[0], 0

    if blend:
        rep = (
            round(sum(c[0] for c in colors) / n),
            round(sum(c[1] for c in colors) / n),
            round(sum(c[2] for c in colors) / n),
        )
        return rep, sum(_sqdist(c, rep) for c in colors)

    best_rep = None
    best_cost = None
    for cand in set(colors):
        cost = 0
        for c in colors:
            cost += _sqdist(c, cand)
        if best_cost is None or cost < best_cost:
            best_cost = cost
            best_rep = cand
    return best_rep, best_cost


@lru_cache(maxsize=16384)
def _solve_cell(colors: Tuple, blend: bool):
    """Solve one terminal cell.

    ``colors`` is a tuple of length ``n`` (2, 4 or 6) in subpixel reading
    order, where each entry is an ``(r, g, b)`` tuple or ``None`` for a
    transparent subpixel.

    Returns ``(mask, fg_rgb, bg_rgb)`` where ``mask`` indexes the mode's
    glyph table, ``fg_rgb`` is the foreground color and ``bg_rgb`` is the
    background color or ``None`` meaning "do not set a background, let the
    terminal's own background show through".

    The partition search is exact: every unordered 2-way split of the cell's
    subpixels is enumerated (``2**(n-1)`` of them -- 2, 8 or 32) and scored
    by total squared RGB error. Memoised, because palette-snapped art
    produces only a handful of distinct cell patterns.
    """
    n = len(colors)
    full = (1 << n) - 1

    opaque_mask = 0
    for i, c in enumerate(colors):
        if c is not None:
            opaque_mask |= 1 << i

    # --- fully transparent: emit nothing at all -------------------------
    if opaque_mask == 0:
        return 0, None, None

    # --- partially transparent -------------------------------------------
    # The holes must stay holes, which means the background must stay unset,
    # which means the glyph mask is forced to the opaque set and every opaque
    # subpixel has to share the single foreground color. This is the same
    # trade the half-block backend makes for its mixed pairs: a slightly
    # coarser edge cell in exchange for never painting a halo into the
    # transparent region.
    if opaque_mask != full:
        opaque = tuple(c for c in colors if c is not None)
        rep, _ = _rep_and_cost(opaque, blend)
        return opaque_mask, rep, None

    # --- fully opaque: exact 2-means over the subpixels --------------------
    # Iterating m over [0, 2**(n-1)) visits each unordered partition
    # {m, full ^ m} exactly once, since the complement always has the top bit
    # set and so never appears in the range. m == 0 is the degenerate
    # "one group" case and is visited first, so a flat cell wins on the very
    # first candidate.
    best_mask = 0
    best_cost = None
    best_a = best_b = None
    for m in range(1 << (n - 1)):
        group_a = tuple(colors[i] for i in range(n) if m & (1 << i))
        group_b = tuple(colors[i] for i in range(n) if not m & (1 << i))
        rep_a, cost_a = _rep_and_cost(group_a, blend)
        rep_b, cost_b = _rep_and_cost(group_b, blend)
        cost = cost_a + cost_b
        if best_cost is None or cost < best_cost:
            best_cost = cost
            best_mask = m
            best_a, best_b = rep_a, rep_b
            if cost == 0:
                break  # cannot do better than exact

    if best_mask == 0:
        # Single color for the whole cell: a full block with only a
        # foreground set. Equivalent to a space with a background, but it
        # needs no background at all, which is both shorter and immune to
        # terminals that treat the background specially (transparency,
        # dimming, selection highlight).
        return full, best_b, None

    count_a = bin(best_mask).count("1")
    if count_a <= n - count_a:
        # Foreground gets the smaller group so the background -- painted
        # across the whole cell rectangle including any inter-cell gap the
        # font leaves -- is the dominant color. Ties keep the low mask, which
        # for half-blocks means the classic "fg = top pixel, U+2580" form.
        return best_mask, best_a, best_b
    return full ^ best_mask, best_b, best_a


# ---------------------------------------------------------------------------
# Pixel access
# ---------------------------------------------------------------------------

def _prepare_pixels(img: Image.Image, target_cols: int, mode: str):
    """Resample ``img`` onto the mode's subpixel grid.

    Returns ``(cols, rows, sub_cols, sub_rows, pixel_access)``. If ``img`` is
    already exactly the right size -- which is what :func:`prepare_source`
    and ``mascot_remaster`` produce -- no resampling happens at all, so a
    palette-snapped sprite is never re-muddied on its way to the terminal.
    """
    _check_mode(mode)
    if img.mode != "RGBA":
        img = img.convert("RGBA")

    cols = max(1, int(target_cols))
    rows = _cell_rows(img, cols, mode)
    sub_cols, sub_rows = SUBGRID[mode]
    grid = (cols * sub_cols, rows * sub_rows)

    if img.size != grid:
        img = img.resize(grid, resample=_RESAMPLE_FILTER)

    return cols, rows, sub_cols, sub_rows, img.load()


def _cell_colors(px, x0: int, y0: int, sub_cols: int, sub_rows: int) -> Tuple:
    """Read one cell's subpixels in reading order as a hashable tuple of
    ``(r, g, b)`` / ``None`` (transparent)."""
    out = []
    for sy in range(sub_rows):
        yy = y0 + sy
        for sx in range(sub_cols):
            r, g, b, a = px[x0 + sx, yy]
            out.append(None if a < ALPHA_TRANSPARENT else (r, g, b))
    return tuple(out)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_frame(img: Image.Image, target_cols: int, truecolor: bool = True,
                 mode: str = DEFAULT_MODE, blend: bool = False) -> str:
    """Render ``img`` as a block of ANSI text ``target_cols`` columns wide.

    Drop-in replacement for ``mascot_backend_halfblock.render_frame`` with a
    ``mode`` knob: ``"quadrant"`` (default, 2x2 subpixels per cell),
    ``"sextant"`` (2x3, highest quality but needs Unicode 13 glyph coverage
    -- gate it on :func:`probe_glyph_support`), or ``"halfblock"`` (1x2,
    universal, behaviourally equivalent to the sibling module).

    Each cell's subpixels are clustered exactly into the two colors ANSI
    allows and rendered with the block glyph matching that partition.
    Fully-transparent cells become a bare space with no color codes; cells
    that straddle the silhouette render with a foreground color only, so the
    terminal background shows through the holes without any fill halo.

    The line count is exactly ``row_count(target_cols, img)`` and depends
    only on ``img.size`` and ``target_cols`` -- never on pixel content or on
    ``mode`` -- so a caller's in-place redraw loop can rely on a fixed
    cursor-up distance even across a mode switch.

    Args:
        img: a PIL Image (any mode; converted to RGBA internally). For best
            results pass one already sized to ``subpixel_grid(img, cols,
            mode)`` -- see :func:`prepare_source` -- so no resampling is
            needed here.
        target_cols: desired render width in terminal columns.
        truecolor: emit 24-bit ``38;2;`` / ``48;2;`` codes when True, else
            quantize to the xterm-256 cube and emit ``38;5;`` / ``48;5;``.
        mode: one of :data:`MODES`.
        blend: use mean colors instead of medoids (see :func:`_rep_and_cost`).

    Returns:
        The rendered frame as a single ``'\\n'``-joined string.
    """
    cols, rows, sub_cols, sub_rows, px = _prepare_pixels(img, target_cols, mode)
    glyphs = _GLYPH_TABLES[mode]

    lines = []
    for row in range(rows):
        y0 = row * sub_rows
        parts = []
        for col in range(cols):
            cell = _cell_colors(px, col * sub_cols, y0, sub_cols, sub_rows)
            mask, fg, bg = _solve_cell(cell, blend)
            if mask == 0 or fg is None:
                parts.append(" ")
            elif bg is None:
                parts.append(f"\x1b[{_fg_code(fg, truecolor)}m{glyphs[mask]}{RESET}")
            else:
                parts.append(
                    f"\x1b[{_fg_code(fg, truecolor)};{_bg_code(bg, truecolor)}m"
                    f"{glyphs[mask]}{RESET}"
                )
        lines.append("".join(parts) + RESET)

    return "\n".join(lines)


def render_quadrant(img: Image.Image, target_cols: int,
                    truecolor: bool = True, blend: bool = False) -> str:
    """:func:`render_frame` pinned to the 2x2 quadrant mode."""
    return render_frame(img, target_cols, truecolor, MODE_QUADRANT, blend)


def render_sextant(img: Image.Image, target_cols: int,
                   truecolor: bool = True, blend: bool = False) -> str:
    """:func:`render_frame` pinned to the 2x3 sextant mode.

    Only call this when :func:`probe_glyph_support` reports ``sextant``
    support; on a font without U+1FB00..U+1FB3B the whole mascot renders as
    tofu boxes.
    """
    return render_frame(img, target_cols, truecolor, MODE_SEXTANT, blend)


# ---------------------------------------------------------------------------
# Source preparation (remaster onto the mode's subpixel grid)
# ---------------------------------------------------------------------------

#: The six colors the mascot is actually designed in; everything else in the
#: source PNGs is JPEG damage. Mirrors ``mascot_remaster.PALETTE`` so the
#: fallback path produces the same art as the real one.
_FALLBACK_PALETTE: Tuple[Tuple[int, int, int], ...] = (
    (10, 10, 12),      # near-black chassis
    (60, 14, 16),      # deep red shadow
    (120, 26, 28),     # mid red
    (200, 40, 42),     # bright red outline
    (255, 72, 68),     # hot red highlight
    (225, 215, 215),   # off-white specular
)


def _fallback_remaster(img: Image.Image, grid: Tuple[int, int],
                       sat: float = 2.3, gamma: float = 1.0,
                       black_floor: int = 0,
                       palette: Sequence[Sequence[int]] = _FALLBACK_PALETTE,
                       alpha_threshold: int = 110,
                       despeckle: bool = False) -> Image.Image:
    """Minimal local copy of the sprite-repair pipeline, used only when
    :mod:`mascot_remaster` is not importable.

    The mascot PNGs were sliced out of WhatsApp-compressed JPEG screenshots,
    so their pixels carry ringing and block noise (idle.png holds ~6200
    distinct colors for what is designed in six). The order below matters:
    the BOX downsample runs FIRST because area-averaging to the small target
    is what low-pass-filters the JPEG noise away -- correcting color before
    shrinking just amplifies the noise. Only then is it safe to lift gamma,
    push saturation about each pixel's own grey mean, and snap to the
    designed palette, which is what restores hard edges and flat fills.
    Partial alpha is JPEG halo, so alpha is binarised hard.

    ``despeckle`` is accepted and ignored: the isolated-speck absorption pass
    is :mod:`mascot_remaster`'s, and silently dropping it here is better than
    raising on a keyword the real implementation understands.
    """
    palette = tuple(tuple(c) for c in palette)
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    small = img.resize(grid, resample=Image.BOX)
    px = small.load()
    out = Image.new("RGBA", grid, (0, 0, 0, 0))
    opx = out.load()
    for y in range(grid[1]):
        for x in range(grid[0]):
            r, g, b, a = px[x, y]
            if a <= alpha_threshold:
                continue
            if gamma and gamma != 1.0:
                r, g, b = (255.0 * (v / 255.0) ** gamma for v in (r, g, b))
            mean = (r + g + b) / 3.0
            r, g, b = (
                min(255.0, max(0.0, mean + (v - mean) * sat)) for v in (r, g, b)
            )
            if black_floor and (r + g + b) / 3.0 < black_floor:
                r = g = b = 0.0
            best = min(palette, key=lambda p: _sqdist((r, g, b), p))
            opx[x, y] = (best[0], best[1], best[2], 255)
    return out


#: Saturation bump per extra subpixel row/column of density, applied by
#: ``prepare_source(..., density_compensate=True)``.
#:
#: A denser grid samples the art more finely, so the soft outer half of every
#: outline gradient -- which a coarse BOX average would have folded into the
#: bright core -- survives as its own pixels and snaps to the deep-red shadow
#: entry instead. Measured mean luminance over the opaque area of a
#: remastered ``idle.png``, and the share of pixels landing on the bright-red
#: palette entry::
#:
#:     cols=20  halfblock  65.5  (bright 38.1%)
#:              quadrant   62.2  (bright 35.2%)
#:              sextant    58.6  (bright 32.4%)
#:
#: i.e. the denser modes render the same sprite progressively duller. The
#: remaster module's saturation is tuned against the half-block grid, so the
#: dense modes want a little more of it to hold the same vividness. A sweep at
#: 20 columns over sat 2.3 / 2.6 / 2.9 put quadrant's sweet spot at 2.6: more
#: vivid than 2.3 with the wordmark letterforms still cleanly separated,
#: whereas 2.9 starts thickening them back together. Hence one step = 0.3.
#:
#: Only the quadrant (one-step) case was validated that way. Sextant takes
#: two steps by extrapolation, which is *not* separately verified -- and
#: sextant is the mode whose wordmark is already fragile, so if you enable
#: this for a full-body sprite in sextant mode, look at the wordmark before
#: shipping it.
_DENSITY_SAT_STEP = 0.3


def prepare_source(src, target_cols: int, mode: str = DEFAULT_MODE,
                   density_compensate: bool = False,
                   **remaster_kwargs) -> Image.Image:
    """Produce a clean sprite sized exactly to this mode's subpixel grid.

    Density comparisons made on the raw JPEG-damaged PNGs are meaningless --
    all you measure is which renderer smears the noise more evenly -- so the
    art must be repaired at the *target* resolution before any density
    judgement. This routes through :mod:`mascot_remaster` (which carries the
    per-asset tuned parameters) when it is importable, and falls back to
    :func:`_fallback_remaster` otherwise.

    Args:
        src: path to a source PNG, or a PIL Image.
        target_cols: render width in terminal columns.
        mode: one of :data:`MODES`; determines the subpixel grid.
        density_compensate: nudge saturation up for the denser modes to undo
            the dulling documented at :data:`_DENSITY_SAT_STEP`. Off by
            default, because the saturation tuning lives in
            :mod:`mascot_remaster` and should not be silently overridden --
            turn it on (or pass an explicit ``sat``) once you have looked at
            the result for your asset.
        **remaster_kwargs: forwarded to ``mascot_remaster.remaster_to_grid``
            (``sat``, ``gamma``, ``black_floor``, ``palette``,
            ``alpha_threshold``, ``despeckle``), overriding the per-asset
            table.

    Returns:
        An RGBA image of size ``subpixel_grid(src, target_cols, mode)`` with
        binary alpha and a handful of flat colors -- feed it straight to
        :func:`render_frame`, whose internal resize is then a no-op.
    """
    img = Image.open(src) if isinstance(src, (str, os.PathLike)) else src
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    grid = subpixel_grid(img, target_cols, mode)

    try:
        import mascot_remaster  # local sibling module
    except Exception:
        mascot_remaster = None

    params = {}
    if mascot_remaster is not None and isinstance(src, (str, os.PathLike)):
        params = mascot_remaster.params_for(src)

    if density_compensate and "sat" not in remaster_kwargs:
        # Steps of density over the half-block baseline: quadrant is +1
        # (double the horizontal samples), sextant +2 (double horizontal and
        # half again vertical).
        sub_cols, sub_rows = SUBGRID[mode]
        base_cols, base_rows = SUBGRID[MODE_HALFBLOCK]
        steps = (sub_cols // base_cols - 1) + (sub_rows - base_rows)
        base_sat = params.get("sat", 2.3)
        params["sat"] = base_sat + steps * _DENSITY_SAT_STEP

    params.update(remaster_kwargs)

    if mascot_remaster is None:
        return _fallback_remaster(img, grid, **params)
    return mascot_remaster.remaster_to_grid(img, grid[0], grid[1], **params)


# ---------------------------------------------------------------------------
# Glyph support probing
# ---------------------------------------------------------------------------
#
# Everything below is pure environment inspection. No bytes are written to
# the terminal and none are read back, so this cannot block, cannot corrupt
# the display, and behaves identically under a pipe, in CI, inside tmux, or
# in an editor's embedded terminal. That rules out the DECRQCPR width probe
# (print glyph, request cursor position, compare advance) which is more
# accurate but hangs on every terminal that declines to answer.

#: Terminals that draw the Legacy Computing block from built-in geometry, so
#: sextants are correct regardless of which font the user picked.
_SEXTANT_TERMINALS = frozenset({
    "kitty", "wezterm", "ghostty", "foot", "contour", "rio",
    "mintty", "windows-terminal",
})

#: Recognised but known/assumed NOT to have sextant coverage: the glyphs are
#: Unicode 13 (2020) and absent from Menlo and SF Mono, so anything relying
#: on the system font on macOS shows tofu.
_NO_SEXTANT_TERMINALS = frozenset({
    "apple-terminal", "iterm2", "vscode", "hyper", "tabby", "warp",
    "alacritty",  # built-in box drawing, but legacy-computing coverage varies
})

#: TERM values where quadrants are genuinely unavailable rather than merely
#: unverified: the Linux console's 512-glyph font and the DEC/dumb terminals
#: cannot draw them at all. An *unset* TERM is not on this list -- it means
#: "no terminal information", not "no terminal capability", and quadrants are
#: near-universal enough that unknown should still get the good default.
_NO_QUADRANT_TERMS = frozenset({"dumb", "linux", "vt100", "vt102", "vt220"})


def _identify_terminal(env) -> str:
    """Best-effort terminal identity from environment variables alone."""
    term = (env.get("TERM") or "").lower()
    prog = (env.get("TERM_PROGRAM") or "").lower()

    # Process-injected markers are the most reliable signal -- a terminal
    # sets these for its own children, and unlike TERM they survive a user
    # who has overridden TERM to something generic.
    if env.get("KITTY_WINDOW_ID") or "kitty" in term:
        return "kitty"
    if env.get("WEZTERM_PANE") or env.get("WEZTERM_EXECUTABLE") or "wezterm" in prog:
        return "wezterm"
    if env.get("GHOSTTY_RESOURCES_DIR") or "ghostty" in term or "ghostty" in prog:
        return "ghostty"
    if env.get("WT_SESSION"):
        return "windows-terminal"
    if env.get("ALACRITTY_WINDOW_ID") or env.get("ALACRITTY_SOCKET") or "alacritty" in term:
        return "alacritty"
    if env.get("CONTOUR_PROFILE") or "contour" in term:
        return "contour"
    if term.startswith("foot"):
        return "foot"
    if "rio" in prog:
        return "rio"
    if "mintty" in term or "mintty" in prog:
        return "mintty"
    if prog == "apple_terminal":
        return "apple-terminal"
    if prog == "iterm.app":
        return "iterm2"
    if prog == "vscode":
        return "vscode"
    if prog == "hyper":
        return "hyper"
    if prog == "tabby":
        return "tabby"
    if prog == "warpterminal":
        return "warp"
    if env.get("VTE_VERSION"):
        return "vte"
    if term in _NO_QUADRANT_TERMS:
        return term or "unknown"
    return "unknown"


def _vte_draws_sextants(env) -> bool:
    """VTE (GNOME Terminal, Tilix, Terminator) started drawing the Legacy
    Computing block from geometry in 0.62; VTE_VERSION is ``MMmmpp``."""
    try:
        return int(env.get("VTE_VERSION", "0")) >= 6200
    except ValueError:
        return False


def probe_glyph_support(env: Optional[Dict[str, str]] = None,
                        stream=None) -> dict:
    """Best-effort, non-blocking report on what this terminal can render.

    Performs **no terminal I/O** -- it only reads environment variables and
    the output stream's encoding, so it always returns immediately and is
    safe to call from a non-tty, a pipe, CI, or inside tmux. Where the
    environment is unrecognised it reports the *safe* answer rather than the
    optimistic one.

    Args:
        env: mapping to inspect instead of ``os.environ`` (for testing).
        stream: output stream whose encoding decides whether the glyphs can
            even be written; defaults to ``sys.stdout``.

    Returns:
        A dict with keys:

        ``terminal``    best-guess identity string, or ``"unknown"``.
        ``unicode``     the stream's encoding can carry the glyphs.
        ``halfblock``   U+2580 family available (essentially always).
        ``quadrant``    U+2596..U+259F available.
        ``sextant``     U+1FB00..U+1FB3B available (conservative).
        ``truecolor``   24-bit color codes are honoured.
        ``recommended`` the mode to actually use -- see below.
        ``reason``      one-line human-readable justification.

        ``recommended`` never auto-selects sextant even on a terminal known
        to support it, because a wrong guess turns the mascot into a grid of
        tofu boxes while a wrong guess about quadrant costs nothing. Sextant
        is opt-in: set ``CYPHEX_MASCOT_SUBCELL=sextant`` to force it, or
        ``=auto`` to allow this function to choose it when detection is
        positive.
    """
    env = os.environ if env is None else env
    stream = sys.stdout if stream is None else stream

    encoding = (getattr(stream, "encoding", None) or "").lower()
    # An unknown encoding is treated as capable: many wrapped streams report
    # nothing, and refusing to draw at all is worse than a mojibake risk that
    # in practice does not materialise on modern Pythons (UTF-8 default).
    unicode_ok = (not encoding) or "utf" in encoding

    term = (env.get("TERM") or "").lower()
    name = _identify_terminal(env)

    quadrant = unicode_ok and term not in _NO_QUADRANT_TERMS
    halfblock = quadrant  # same font requirement, one Unicode version older

    if name in _SEXTANT_TERMINALS:
        sextant = quadrant
        why = f"{name} draws Legacy Computing glyphs from built-in geometry"
    elif name == "vte" and _vte_draws_sextants(env):
        sextant = quadrant
        why = f"VTE {env.get('VTE_VERSION')} draws sextants natively"
    elif name in _NO_SEXTANT_TERMINALS:
        sextant = False
        why = f"{name} depends on the user font for U+1FB00, which usually lacks it"
    else:
        sextant = False
        why = "unrecognised terminal; assuming no Unicode 13 glyph coverage"

    colorterm = (env.get("COLORTERM") or "").lower()
    truecolor = colorterm in ("truecolor", "24bit") or name in (
        "kitty", "wezterm", "ghostty", "iterm2", "vscode", "windows-terminal",
        "alacritty", "contour", "foot", "rio", "warp",
    )

    # --- resolve the recommendation --------------------------------------
    override = (env.get(ENV_OVERRIDE) or "").strip().lower()
    if override in SUBGRID:
        recommended = override
        why = f"{ENV_OVERRIDE}={override} forces this mode"
        if override == MODE_SEXTANT:
            sextant = True  # user asserted it; trust them
    elif override == "auto" and sextant:
        recommended = MODE_SEXTANT
        why = f"{ENV_OVERRIDE}=auto and {why}"
    elif quadrant:
        recommended = MODE_QUADRANT
        if not override:
            why = (f"quadrant is the safe high-density default; "
                   f"sextant is opt-in ({why})")
    else:
        recommended = MODE_HALFBLOCK
        why = f"no quadrant coverage on TERM={term!r}; falling back to half-blocks"

    return {
        "terminal": name,
        "unicode": unicode_ok,
        "halfblock": halfblock,
        "quadrant": quadrant,
        "sextant": sextant,
        "truecolor": truecolor,
        "recommended": recommended,
        "reason": why,
    }


def best_mode(env: Optional[Dict[str, str]] = None, stream=None) -> str:
    """Shorthand for ``probe_glyph_support(...)["recommended"]``."""
    return probe_glyph_support(env, stream)["recommended"]


# ---------------------------------------------------------------------------
# QA helper: rasterize what the sub-cell render would look like
# ---------------------------------------------------------------------------

def dump_preview_png(img: Image.Image, target_cols: int, out_path: str,
                     mode: str = DEFAULT_MODE, cell_w: int = 12,
                     cell_h: int = 24, blend: bool = False,
                     background: Optional[Sequence[int]] = None) -> str:
    """Debugging/QA aid: rasterize what :func:`render_frame` would produce
    into a flat PNG so a human can judge density and crispness without a
    terminal that has the right font.

    Every terminal cell becomes a ``cell_w`` x ``cell_h`` block subdivided
    into the mode's sub-rectangles, each filled with the **post-quantization**
    color the ANSI renderer actually chose for it -- foreground color inside
    the glyph's mask, background color outside it. So this shows the real
    two-colors-per-cell loss, not the pre-render source pixels. Subpixels the
    renderer leaves as holes (no background set) stay at alpha 0.

    The default ``cell_w`` x ``cell_h`` of 12 x 24 is deliberately 1:2 -- the
    real aspect of a terminal cell -- so proportions in the PNG match
    proportions on screen and a squashed render is visible as squashed. 24 is
    divisible by both 2 and 3, so the same cell size is exact for all three
    modes and the resulting PNGs are directly comparable.

    Args:
        img: source PIL image (ideally already at :func:`subpixel_grid` size).
        target_cols: render width in terminal columns.
        out_path: file path to save the PNG to.
        mode: one of :data:`MODES`.
        cell_w: output pixels per terminal cell, horizontally.
        cell_h: output pixels per terminal cell, vertically.
        blend: passed through to the cell solver.
        background: RGB to paint behind the render, standing in for the
            terminal's own background. ``None`` (default) leaves it
            transparent, matching the half-block backend. Supplying a dark
            value is what makes the near-black chassis of this particular
            mascot readable in an image viewer.

    Returns:
        The ``out_path`` it wrote to.
    """
    cols, rows, sub_cols, sub_rows, px = _prepare_pixels(img, target_cols, mode)

    fill = (0, 0, 0, 0)
    if background is not None:
        fill = (background[0], background[1], background[2], 255)
    canvas = Image.new("RGBA", (cols * cell_w, rows * cell_h), fill)
    draw = ImageDraw.Draw(canvas)

    for row in range(rows):
        y0 = row * sub_rows
        for col in range(cols):
            cell = _cell_colors(px, col * sub_cols, y0, sub_cols, sub_rows)
            mask, fg, bg = _solve_cell(cell, blend)
            if mask == 0 or fg is None:
                continue
            ox = col * cell_w
            oy = row * cell_h
            for idx in range(sub_cols * sub_rows):
                color = fg if mask & (1 << idx) else bg
                if color is None:
                    continue  # hole: terminal background shows through
                sx = idx % sub_cols
                sy = idx // sub_cols
                x0 = ox + (sx * cell_w) // sub_cols
                x1 = ox + ((sx + 1) * cell_w) // sub_cols - 1
                yy0 = oy + (sy * cell_h) // sub_rows
                yy1 = oy + ((sy + 1) * cell_h) // sub_rows - 1
                draw.rectangle([x0, yy0, x1, yy1],
                               fill=(color[0], color[1], color[2], 255))

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    canvas.save(out_path)
    return out_path


# ---------------------------------------------------------------------------
# Self-test / QA generation
# ---------------------------------------------------------------------------

def _verify_glyph_tables() -> None:
    """Cross-check the generated tables against the Unicode character
    database, so a transposed bit can never silently ship."""
    import unicodedata

    # Quadrant: position names, in bit order.
    quad_names = ("UPPER LEFT", "UPPER RIGHT", "LOWER LEFT", "LOWER RIGHT")
    for mask, glyph in enumerate(_GLYPHS_QUADRANT):
        if mask in (0, 3, 5, 10, 12, 15):
            continue  # space / half blocks / full block: not QUADRANT-named
        name = unicodedata.name(glyph)
        assert name.startswith("QUADRANT "), (mask, name)
        for bit in range(4):
            present = quad_names[bit] in name
            # "UPPER LEFT" is a substring of nothing else; "LOWER RIGHT" etc.
            # are unambiguous in these names.
            assert present == bool(mask & (1 << bit)), (mask, name, bit)

    # Sextant: names are BLOCK SEXTANT-<digits>, digits = 1-based positions.
    for mask, glyph in enumerate(_GLYPHS_SEXTANT):
        if mask in (0, 0b010101, 0b101010, 0b111111):
            continue
        name = unicodedata.name(glyph)
        assert name.startswith("BLOCK SEXTANT-"), (mask, name)
        digits = name.rsplit("-", 1)[1]
        expected = "".join(str(b + 1) for b in range(6) if mask & (1 << b))
        assert digits == expected, (mask, name, expected)

    print("glyph tables verified against the Unicode character database")


if __name__ == "__main__":
    HERE = os.path.dirname(os.path.abspath(__file__))
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    ASSETS = os.path.join(HERE, "assets", "mascot")
    QA_DIR = os.path.join(HERE, "assets", "qa")

    _verify_glyph_tables()

    print("\nprobe_glyph_support():")
    for k, v in probe_glyph_support().items():
        print(f"  {k:12s} {v}")

    src = os.path.join(ASSETS, "idle.png")
    source = Image.open(src)

    print("\n--- density QA ---")
    for cols in (20, 28):
        for mode in MODES:
            clean = prepare_source(src, cols, mode)
            frame = render_frame(clean, cols, truecolor=True, mode=mode)
            out = os.path.join(QA_DIR, f"density_{mode}_{cols}.png")
            # Dark backdrop: this mascot's chassis is near-black, so on a
            # transparent PNG most of it is invisible in an image viewer.
            dump_preview_png(clean, cols, out, mode=mode, background=(18, 18, 20))
            n_sub = SUBPIXELS_PER_CELL[mode]
            rows = row_count(cols, clean, mode)
            print(f"cols={cols:2d} {mode:10s} grid={clean.size} "
                  f"rows={rows:2d} subpixels={clean.size[0] * clean.size[1]:5d} "
                  f"({n_sub}/cell)  {len(frame.encode('utf-8')):6d} bytes  -> {out}")

    print("\n=== idle.png, quadrant, 24 cols ===")
    print(render_frame(prepare_source(src, 24, MODE_QUADRANT), 24,
                       mode=MODE_QUADRANT))
