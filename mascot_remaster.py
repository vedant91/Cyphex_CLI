"""mascot_remaster.py
====================

Re-master the CYPHEX pixel-art mascot sprites so they render CRISP in the
terminal instead of as muddy mush.

Why this module exists
----------------------
The shipped sprites in ``assets/mascot/*.png`` were sliced out of
WhatsApp-compressed JPEG screenshots. The art is *designed* as roughly
six-colour pixel art (near-black chassis, three reds, a hot-red highlight,
an off-white specular) but the PNGs actually contain thousands of distinct
colours -- 6263 unique RGBA values in ``idle.png`` alone. Those extra
colours are not art, they are JPEG ringing and 8x8 block noise baked into
the pixels, plus a washed-out gamut (the brightest "red" in ``idle.png`` is
only ``rgb(193, 74, 71)``, and a large mass of the torso is a dead
grey-brown ``rgb(45, 32, 30)``).

Downsampling *that* to 20-36 terminal columns averages the noise together
with the art, which is the "bursted pixels" the user complained about.

The repair pipeline (order matters)
-----------------------------------
1. **Resize to the small target FIRST**, with ``Image.BOX``. BOX is an
   area-average, i.e. a box low-pass filter. Running it before any colour
   work is what actually *removes* the JPEG ringing rather than amplifying
   it: each output pixel is the mean of a ~4x5 source neighbourhood, and
   zero-mean compression noise averages away. Doing colour work first and
   resizing second amplifies the noise instead -- that is the old, broken
   order.
   The resize runs in **premultiplied-alpha space** so the fully transparent
   surround (which is transparent *black*) cannot bleed a dark fringe into
   the sprite's edge pixels.
2. **Gamma** (``(v/255) ** gamma``). Below 1.0 lifts midtones, above 1.0
   adds contrast. See the calibration note below -- for this art the useful
   value turned out to be 1.0.
3. **Saturation boost around the per-pixel grey mean**: ``v' = mean +
   (v - mean) * sat``. This re-vivifies the desaturated JPEG reds so they
   land on the *red* side of the palette instead of collapsing to grey.
   This is the single most load-bearing knob in the pipeline.
4. **Black floor** (optional): pixels whose channel mean falls below
   ``black_floor`` are crushed to pure black. A scalpel, not a hammer --
   see the calibration note.
5. **Snap every pixel to the designed palette** by nearest euclidean RGB
   distance. This is what makes the result *pixel art* again: afterwards
   the image holds at most ``len(palette)`` colours, so every edge is a
   hard edge between two flat colours.
6. **Despeckle** (optional, on by default): replace any pixel whose colour
   differs from *every* one of its orthogonal opaque neighbours when those
   neighbours all agree on one colour. Deliberately conservative -- a pixel
   that is part of a one-pixel-wide line always has at least one neighbour
   of its own colour, so lines, the antenna, and glyph strokes are never
   touched. Only genuinely isolated specks are absorbed.
7. **Binarise alpha** at ``alpha_threshold``. The source alpha is already
   hard 0/255; it only turns fractional *because* of the BOX resize, and
   those fractional pixels are exactly the halo that makes the sprite look
   fuzzy. Re-hardening them removes the fringe. Fully transparent pixels
   are zeroed to ``(0, 0, 0, 0)`` so no ghost colour survives.

Calibration note -- why gamma is 1.0 and black_floor is 0
---------------------------------------------------------
The prototype these numbers came from suggested ``gamma=0.85`` (a midtone
*lift*) with ``black_floor=42``. Sweeping ``sat`` x ``gamma`` x
``black_floor`` and inspecting 8x-NEAREST QA renders of every combination
showed both of those are wrong at the column widths the CLI actually uses
(16-36), for a reason specific to this art:

  * The head is a bright red bezel around a **black screen**, and the JPEG
    left a dim red glow haze spilling across that screen. A gamma lift
    raises the haze past the palette's mid-red boundary, so the snap paints
    the entire screen interior bright red -- the head stops being a screen
    with a face on it and becomes a solid red brick. Every gamma below 1.0
    did this; 0.75 did it worst. Gamma 1.0 keeps the screen black.
  * Pushing the other way (gamma > 1.0, i.e. contrast) is safe up to about
    1.15, but by 1.3 the head's *bottom* bezel disappears entirely. That
    edge is drawn darker than the top and sides (the art is lit from
    above), so it is the first thing a contrast curve eats, and the head
    then reads as an open-topped box. Gamma 1.0 is the widest safe setting.
  * ``black_floor`` at 42 or 55 does not clean the torso, it *deletes half
    of it*. The torso is low-contrast dark plating whose contrast JPEG
    already destroyed; crushing it leaves disconnected survivors, so the
    body stops reading as a body and starts reading as noise. 0 keeps the
    plating as a continuous deep-red mass, which is both quieter and more
    legible. On the head cameos a floor of 42 fragments the bezel ring's
    bottom and corners the same way.

The knobs are still exposed with their full range -- the defaults are just
what the QA sheets in ``assets/qa/`` actually support.

Output contract
---------------
``remaster(src, cols)`` returns an RGBA image whose width is exactly
``cols`` and whose height is an **even** number ``2 * rows``. That grid is a
fixed point for ``mascot_backend_halfblock``: feeding the result to
``render_frame(img, cols)`` triggers a no-op resize (verified pixel-identical
for every asset at every width in ``DEFAULT_COLS``), so the palette-snapped
pixels reach the terminal untouched with no second resampling to re-muddy
them.

Public API
----------
    PALETTE, PALETTE_NO_WHITE          -- designed palettes
    ASSET_OVERRIDES                    -- per-asset tuned parameters
    params_for(name)                   -- resolve overrides for an asset
    remaster(src, cols, ...)           -- remaster to a column width
    remaster_to_grid(src, w, h, ...)   -- remaster to an explicit pixel grid
    remaster_asset(path, cols)         -- remaster with the tuned overrides
    grid_for_cols(src, cols)           -- the (w, h) `remaster` would use
    build_all(...)                     -- pre-render the whole asset set
    load_remastered(stem, cols)        -- load a pre-rendered sprite
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, Sequence, Tuple, Union

import numpy as np
from PIL import Image

# ---------------------------------------------------------------------------
# Designed palette
# ---------------------------------------------------------------------------

#: The six colours the mascot is *designed* in. Everything else in the source
#: PNGs is JPEG damage. Order is documentary only -- the snap is a nearest
#: euclidean search, not an index lookup.
PALETTE: Tuple[Tuple[int, int, int], ...] = (
    (10, 10, 12),      # near-black chassis fill / screen interior
    (60, 14, 16),      # deep red shadow (torso plating, outer glow falloff)
    (120, 26, 28),     # mid red (bezel shadow side, dimmer outline runs)
    (200, 40, 42),     # bright red outline -- the shape-defining colour
    (255, 72, 68),     # hot red highlight (antenna bulb, lit bezel edge)
    (225, 215, 215),   # off-white specular
)

#: Same palette minus the off-white. The off-white only ever wins on a handful
#: of blown-out JPEG highlight pixels; on most assets those land on the
#: antenna bulb and read as a deliberate specular hit (kept), but if an asset
#: ever scatters them as dirt this palette is the fix.
PALETTE_NO_WHITE: Tuple[Tuple[int, int, int], ...] = PALETTE[:-1]

#: Alpha at or below this (post-resize, 0-255) is treated as "not there". The
#: source alpha is binary; anything in between is BOX-resize halo.
DEFAULT_ALPHA_THRESHOLD = 110

# Defaults validated by the sweeps described in the calibration note above.
DEFAULT_SAT = 2.3
DEFAULT_GAMMA = 1.0
DEFAULT_BLACK_FLOOR = 0
DEFAULT_DESPECKLE = True


# ---------------------------------------------------------------------------
# Per-asset tuning
# ---------------------------------------------------------------------------
#
# Only one axis actually needs to differ per asset -- saturation -- and it
# splits cleanly along "does this sprite have screen text on it".
#
#   * FULL-BODY poses (idle / walk / typing / scan / success / loop_*) carry
#     the "CYPHEX" wordmark across the head screen. That wordmark survives as
#     a bright-red band with black notches punched through it for the letter
#     gaps. sat=2.3 keeps those notches. sat=2.8 promotes the notches
#     themselves into bright red and the band fuses into one solid bar --
#     most visible on `scan` at cols=36, where 2.3 still shows letterforms and
#     2.8 shows a brick. So full bodies cap at 2.3.
#
#   * HEAD CAMEOS (expr_*) have no wordmark -- just a bezel ring, a glyph, and
#     black. Nothing fuses, so they take the harder push: sat=2.8 makes the
#     ring a clean bright-red outline with a deep-red drop shadow instead of
#     the muddy two-tone smear 1.9-2.3 leaves, and "x_x" / ". . ." stay
#     perfectly legible. This is why the head cameos read crisper at small
#     sizes than the full bodies do.
#
#   * `hero.png` is a 292x323 showcase render, not an animation frame. Its
#     extra source resolution means at cols=36 the "CYPHEX" wordmark comes out
#     fully letter-legible, so it wants the wordmark-preserving 2.3.
#
# gamma / black_floor / despeckle are the module defaults everywhere -- the
# sweep found no asset that wanted anything else (see calibration note).
#
# Keys are the asset stem (filename without extension); `params_for` falls
# back to the module defaults for anything not listed.
ASSET_OVERRIDES: Dict[str, dict] = {
    # --- full-body poses: sat capped at 2.3 to preserve the wordmark -------
    "idle":           dict(sat=2.3),
    "walk":           dict(sat=2.3),
    "typing":         dict(sat=2.3),
    "scan":           dict(sat=2.3),
    "success":        dict(sat=2.3),
    "loop_loading":   dict(sat=2.3),
    "loop_scanning":  dict(sat=2.3),
    "loop_uploading": dict(sat=2.3),

    # --- head cameos: no wordmark to protect, push harder for a clean ring -
    "expr_neutral":   dict(sat=2.8),
    "expr_thinking":  dict(sat=2.8),
    "expr_focused":   dict(sat=2.8),
    "expr_alert":     dict(sat=2.8),
    "expr_hacking":   dict(sat=2.8),
    "expr_error":     dict(sat=2.8),

    # --- showcase ---------------------------------------------------------
    "hero":           dict(sat=2.3),
}

#: Column widths the CLI actually renders at.
DEFAULT_COLS: Tuple[int, ...] = (16, 20, 24, 28, 36)

#: Sprites that are reference material, not renderable frames.
SKIP_STEMS = frozenset({"size_16", "size_32", "size_64"})


def params_for(name: str) -> dict:
    """Resolve the tuned parameters for an asset.

    ``name`` may be a bare stem (``"idle"``), a filename (``"idle.png"``) or a
    full path -- only the stem is used for the lookup. Unknown assets get the
    module defaults.
    """
    stem = os.path.splitext(os.path.basename(str(name)))[0]
    base = dict(
        sat=DEFAULT_SAT,
        gamma=DEFAULT_GAMMA,
        black_floor=DEFAULT_BLACK_FLOOR,
        palette=PALETTE,
        alpha_threshold=DEFAULT_ALPHA_THRESHOLD,
        despeckle=DEFAULT_DESPECKLE,
    )
    base.update(ASSET_OVERRIDES.get(stem, {}))
    return base


# ---------------------------------------------------------------------------
# Sizing
# ---------------------------------------------------------------------------

def grid_for_cols(src: Union[str, "os.PathLike[str]", Image.Image],
                  cols: int) -> Tuple[int, int]:
    """Return the ``(width, height)`` pixel grid ``remaster`` would use for
    ``cols`` terminal columns.

    Width is exactly ``cols``. Height preserves the source aspect ratio in
    square-pixel space and is rounded to an even number so the half-block
    renderer can pair every pixel row with a partner (``rows = height // 2``).
    A terminal cell is roughly twice as tall as it is wide, and that 1:2 cell
    aspect is exactly what the two-pixel-rows-per-cell packing absorbs -- so
    no extra squash factor belongs here.
    """
    img = _as_image(src)
    cols = max(1, int(cols))
    w, h = img.size
    if w <= 0 or h <= 0:
        return cols, 2
    new_h = int(round(cols * (h / w)))
    if new_h < 2:
        new_h = 2
    if new_h % 2:
        new_h += 1
    return cols, new_h


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def _as_image(src: Union[str, "os.PathLike[str]", Image.Image]) -> Image.Image:
    if isinstance(src, Image.Image):
        return src if src.mode == "RGBA" else src.convert("RGBA")
    return Image.open(os.fspath(src)).convert("RGBA")


def _box_resize_premultiplied(img: Image.Image,
                              size: Tuple[int, int]) -> np.ndarray:
    """Area-average ``img`` down to ``size`` without letting the transparent
    surround bleed into the sprite.

    PIL resizes RGBA channels independently, so a transparent-*black* border
    pixel ``(0,0,0,0)`` drags its opaque neighbours toward black and leaves a
    dark fringe. Premultiplying by alpha first, resizing (BOX is linear, so it
    composes correctly with premultiplication), then unpremultiplying gives
    each output pixel the colour it would have if only its *visible* source
    pixels contributed.

    Returns a float32 array of shape ``(h, w, 4)`` with straight
    (un-premultiplied) RGB in 0-255 and alpha in 0-255.
    """
    arr = np.asarray(img, dtype=np.float32)
    alpha = arr[..., 3:4] / 255.0
    premul = np.concatenate([arr[..., :3] * alpha, arr[..., 3:4]], axis=2)

    small = np.asarray(
        Image.fromarray(premul.astype(np.uint8), "RGBA").resize(size, Image.BOX),
        dtype=np.float32,
    )

    a = small[..., 3:4]
    # Unpremultiply. Fully transparent pixels divide by ~0; their colour is
    # irrelevant because they get zeroed at the end of the pipeline anyway.
    rgb = np.where(a > 0.0, small[..., :3] * 255.0 / np.maximum(a, 1e-6), 0.0)
    return np.concatenate([np.clip(rgb, 0.0, 255.0), a], axis=2)


def _snap_to_palette(rgb: np.ndarray,
                     palette: Sequence[Sequence[int]]) -> np.ndarray:
    """Replace every pixel with its nearest palette entry (euclidean in RGB).

    ``rgb`` is ``(h, w, 3)`` float; the return is ``(h, w, 3)`` uint8.
    """
    pal = np.asarray(palette, dtype=np.float32)           # (k, 3)
    flat = rgb.reshape(-1, 1, 3)                          # (n, 1, 3)
    d2 = ((flat - pal[None, :, :]) ** 2).sum(axis=2)      # (n, k)
    idx = d2.argmin(axis=1)                               # (n,)
    return pal[idx].reshape(rgb.shape).astype(np.uint8)


def _despeckle(rgb: np.ndarray, opaque: np.ndarray) -> np.ndarray:
    """Absorb isolated single-pixel specks into their surroundings.

    A pixel is rewritten only when ALL of these hold:

      * it is opaque, and has at least three opaque orthogonal neighbours
        (so silhouette-edge pixels, which have fewer, are never touched);
      * every one of those opaque neighbours is the same colour as every
        other one;
      * that colour is not the pixel's own.

    Anything belonging to a stroke survives untouched: a pixel in a
    one-pixel-wide horizontal line has left and right neighbours of its own
    colour, so the second condition fails immediately. Only true specks --
    the leftover JPEG-noise pixels scattered across the torso plating and
    inside the bezel ring -- match, and they get absorbed into the colour
    that already surrounds them.

    DO NOT "improve" this by also deleting orphans (opaque pixels with zero
    opaque neighbours). It looks like an obvious extra cleanup and it is a
    trap: this art uses isolated single pixels as *glyphs*. Measured on
    ``expr_thinking`` at cols=24, the orphan pixels are at (10,15), (13,15)
    and (16,15) -- those three are the entire ". . ." thinking expression.
    Dropping orphans would silently delete the animation's whole meaning.
    The requirement here is deliberately "all neighbours agree", which never
    fires on a pixel floating in transparency.

    Args:
        rgb: ``(h, w, 3)`` uint8, already palette-snapped.
        opaque: ``(h, w)`` bool mask of pixels that survived the alpha cut.

    Returns:
        A new ``(h, w, 3)`` uint8 array.
    """
    h, w = rgb.shape[:2]
    if h < 3 or w < 3:
        return rgb

    # Pack each colour into one integer so neighbours can be compared cheaply.
    key = (rgb[..., 0].astype(np.int32) << 16
           | rgb[..., 1].astype(np.int32) << 8
           | rgb[..., 2].astype(np.int32))
    key = np.where(opaque, key, -1)

    MISSING = -1
    def shift(a: np.ndarray, dy: int, dx: int) -> np.ndarray:
        out = np.full_like(a, MISSING)
        ys = slice(max(0, dy), h + min(0, dy))
        xs = slice(max(0, dx), w + min(0, dx))
        yd = slice(max(0, -dy), h + min(0, -dy))
        xd = slice(max(0, -dx), w + min(0, -dx))
        out[yd, xd] = a[ys, xs]
        return out

    neigh = np.stack([shift(key, -1, 0), shift(key, 1, 0),
                      shift(key, 0, -1), shift(key, 0, 1)])   # (4, h, w)
    valid = neigh >= 0
    count = valid.sum(axis=0)

    # min and max over the *valid* neighbours only; equal => they all agree.
    hi = np.where(valid, neigh, np.iinfo(np.int32).max).min(axis=0)
    lo = np.where(valid, neigh, MISSING).max(axis=0)

    agree = (count >= 3) & (hi == lo)
    replace = agree & opaque & (key != hi)

    out = rgb.copy()
    out[replace, 0] = ((hi[replace] >> 16) & 0xFF).astype(np.uint8)
    out[replace, 1] = ((hi[replace] >> 8) & 0xFF).astype(np.uint8)
    out[replace, 2] = (hi[replace] & 0xFF).astype(np.uint8)
    return out


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def remaster_to_grid(
    src: Union[str, "os.PathLike[str]", Image.Image],
    grid_w: int,
    grid_h: int,
    *,
    sat: float = DEFAULT_SAT,
    gamma: float = DEFAULT_GAMMA,
    black_floor: int = DEFAULT_BLACK_FLOOR,
    palette: Sequence[Sequence[int]] = PALETTE,
    alpha_threshold: int = DEFAULT_ALPHA_THRESHOLD,
    despeckle: bool = DEFAULT_DESPECKLE,
) -> Image.Image:
    """Remaster ``src`` onto an explicit ``grid_w`` x ``grid_h`` pixel grid.

    This runs the full pipeline described in the module docstring. Use it when
    you want to dictate the exact grid (a fixed-size sprite-sheet cell, say);
    use :func:`remaster` when you want the aspect-preserving grid for a given
    terminal column count.

    Args:
        src: path or PIL image. Converted to RGBA.
        grid_w: output width in pixels.
        grid_h: output height in pixels. Should be even if the result is
            headed for a half-block renderer.
        sat: saturation multiplier applied around each pixel's own grey mean.
            1.0 is a no-op; 2.3-2.8 is the useful range for this art.
        gamma: exponent applied as ``(v/255) ** gamma``. Below 1.0 lifts
            midtones, above 1.0 adds contrast. 1.0 for this art -- see the
            module's calibration note for why both directions hurt.
        black_floor: pixels whose channel mean is below this are crushed to
            pure black before the palette snap; 0 disables it. Measured on the
            *channel mean*, not Rec.601 luma, because luma badly under-weights
            the red channel and this art is almost entirely red.
        palette: sequence of RGB triples to snap to.
        alpha_threshold: alpha strictly above this becomes 255, the rest 0.
        despeckle: run the isolated-speck absorption pass after the snap.

    Returns:
        A hard-edged, palette-snapped ``RGBA`` image of size
        ``(grid_w, grid_h)`` holding at most ``len(palette)`` colours plus
        full transparency, with strictly binary alpha.
    """
    img = _as_image(src)
    grid_w = max(1, int(grid_w))
    grid_h = max(1, int(grid_h))

    # 1. downsample first -- this is the noise filter, not a resize detail
    arr = _box_resize_premultiplied(img, (grid_w, grid_h))
    rgb = arr[..., :3]
    alpha = arr[..., 3]

    # 2. gamma
    if gamma and gamma != 1.0:
        rgb = np.power(np.clip(rgb, 0.0, 255.0) / 255.0, float(gamma)) * 255.0

    # 3. saturation about the per-pixel grey mean
    if sat and sat != 1.0:
        mean = rgb.mean(axis=2, keepdims=True)
        rgb = mean + (rgb - mean) * float(sat)

    rgb = np.clip(rgb, 0.0, 255.0)

    # 4. optional black floor
    if black_floor and black_floor > 0:
        rgb[rgb.mean(axis=2) < float(black_floor)] = 0.0

    # 5. snap to the designed palette -> hard edges, flat colours
    snapped = _snap_to_palette(rgb, palette)

    # 6. binarise alpha (the fractional values are BOX-resize halo)
    opaque = alpha > float(alpha_threshold)

    # 7. absorb isolated specks
    if despeckle:
        snapped = _despeckle(snapped, opaque)

    hard_alpha = np.where(opaque, 255, 0).astype(np.uint8)
    out = np.concatenate([snapped, hard_alpha[..., None]], axis=2)
    out[~opaque] = 0

    return Image.fromarray(out, "RGBA")


def remaster(
    src: Union[str, "os.PathLike[str]", Image.Image],
    cols: int,
    *,
    sat: float = DEFAULT_SAT,
    gamma: float = DEFAULT_GAMMA,
    black_floor: int = DEFAULT_BLACK_FLOOR,
    palette: Sequence[Sequence[int]] = PALETTE,
    alpha_threshold: int = DEFAULT_ALPHA_THRESHOLD,
    despeckle: bool = DEFAULT_DESPECKLE,
) -> Image.Image:
    """Remaster ``src`` for a render ``cols`` terminal columns wide.

    The returned image is exactly ``cols`` pixels wide and ``2 * rows`` pixels
    tall (always even), preserving the source aspect ratio in square-pixel
    space -- the 1:2 terminal cell aspect is absorbed by the half-block
    renderer pairing two pixel rows per cell. Feed the result straight to
    ``mascot_backend_halfblock.render_frame(img, cols)``; that call's internal
    resize is a verified no-op on this grid, so nothing re-muddies the pixels.

    See :func:`remaster_to_grid` for the meaning of every keyword.
    """
    w, h = grid_for_cols(src, cols)
    return remaster_to_grid(
        src, w, h,
        sat=sat, gamma=gamma, black_floor=black_floor,
        palette=palette, alpha_threshold=alpha_threshold, despeckle=despeckle,
    )


def remaster_asset(src: Union[str, "os.PathLike[str]"], cols: int,
                   **overrides) -> Image.Image:
    """:func:`remaster` with this asset's tuned parameters from
    :data:`ASSET_OVERRIDES` applied automatically.

    Any keyword passed here wins over the table.
    """
    params = params_for(src)
    params.update(overrides)
    return remaster(src, cols, **params)


# ---------------------------------------------------------------------------
# Batch pre-render
# ---------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
ASSET_DIR = os.path.join(HERE, "assets", "mascot")
REMASTER_DIR = os.path.join(ASSET_DIR, "remastered")


def source_stems(asset_dir: str = ASSET_DIR) -> list:
    """Every renderable sprite stem in ``asset_dir`` (reference sizes skipped)."""
    stems = []
    for fn in sorted(os.listdir(asset_dir)):
        if not fn.lower().endswith(".png"):
            continue
        stem = os.path.splitext(fn)[0]
        if stem in SKIP_STEMS:
            continue
        stems.append(stem)
    return stems


def build_all(
    asset_dir: str = ASSET_DIR,
    out_dir: str = REMASTER_DIR,
    cols_list: Iterable[int] = DEFAULT_COLS,
) -> list:
    """Pre-render the whole asset set to ``out_dir`` as ``<stem>_<cols>.png``.

    The originals are never written to -- they are the only source we have and
    are irreplaceable. Returns the list of paths written.
    """
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for stem in source_stems(asset_dir):
        src = os.path.join(asset_dir, stem + ".png")
        for cols in cols_list:
            remaster_asset(src, cols).save(
                os.path.join(out_dir, f"{stem}_{cols}.png"))
            written.append(os.path.join(out_dir, f"{stem}_{cols}.png"))
    return written


def load_remastered(stem: str, cols: int,
                    out_dir: str = REMASTER_DIR) -> Image.Image:
    """Load a pre-rendered remaster, falling back to remastering on the fly."""
    path = os.path.join(out_dir, f"{stem}_{cols}.png")
    if os.path.exists(path):
        return Image.open(path).convert("RGBA")
    return remaster_asset(os.path.join(ASSET_DIR, stem + ".png"), cols)


if __name__ == "__main__":
    paths = build_all()
    print(f"wrote {len(paths)} remastered sprites to {REMASTER_DIR}")
