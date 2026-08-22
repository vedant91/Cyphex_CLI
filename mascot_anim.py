"""CYPHEX mascot animation frames -- the single source of truth.

This module owns *what* the mascot does. It hands the render loop a list of
PIL images per state and guarantees one property above all others:

    EVERY FRAME OF EVERY STATE HAS THE SAME PIXEL CANVAS SIZE, AND THEREFORE
    RENDERS TO THE SAME NUMBER OF TERMINAL ROWS.

Why that sentence is in capitals
--------------------------------
The shipped mascot had a redraw bug that users saw as "sometimes it cuts in
half and another robot appends". It was not a rendering artifact -- it was
arithmetic. The redraw loop draws a frame, then cursor-ups by a *single
assumed* row count before drawing the next one. The old frame lists violated
that assumption:

    idle       3 frames   sizes {(109,177)}               rows {23}
    searching 12 frames   sizes {(154,173)}               rows {16}
    thinking  12 frames   sizes {(107,107),(123,168)}     rows {19, 14}  <-- bug
    success    2 frames   sizes {(143,174)}               rows {17}
    error      2 frames   sizes {(108,107)}               rows {14}

`thinking` hard-cut between a 19-row full body and a 14-row head cameo. On
that cut the loop cursor-upped 14 rows after having drawn 19, so five rows of
the previous robot were never overwritten (the "half robot") and the next
frame landed below them (the "another robot appends"). Every *state* also had
a different height from every other state, so state transitions drifted the
same way.

The fix is structural, not a patch: one canvas for the whole mascot. Every
sprite -- full body poses and head-only expression cameos alike -- is
composited onto that one canvas with the feet planted on the bottom edge and
transparent padding everywhere else. A head cameo is padded, never rendered at
its own smaller natural size. :func:`canvas_rows` is then a pure function of
the column width, the render loop's cursor-up distance is a constant for the
whole session, and the class of bug is gone rather than fixed.

The secondary cause is the caller's to fix, and this module exists to make it
easy: if the animation starts near the bottom of the terminal, printing a tall
frame *scrolls*, which invalidates cursor-up arithmetic exactly the same way.
Call :func:`canvas_rows` before the first draw, compare it against the
terminal height, and scroll the needed room in deliberately (print N newlines
then cursor-up N) so the frame origin can never move underneath you.

Why the animation is synthesized
--------------------------------
The source art is a handful of *static* poses. There is no hand-drawn
in-between anywhere in the asset set, so every bit of motion here is
synthesized at import time from four cheap primitives:

* **Eased brightness on a sine curve.** The old idle was a three-frame
  100%/90%/100% square wave, which the eye reads as a stutter, not a breath.
  A 12-frame sine sweep at 11fps reads as breathing.
* **One-pixel vertical bob.** Free, and it is what actually sells "alive".
  Amplitude is half a terminal row, so on the sub-cell backends (quadrant,
  sextant) it is genuine sub-character motion.
* **Ordered-dither cross-fades.** Pose changes are dissolves, not cuts. A
  hard cut between two framings is the thing that read as a glitch.
* **Localized glow.** A gaussian row band multiplied over the sprite --
  antenna beacon pulses, upload energy drifting up the chassis.

Keeping synthesis on-palette
----------------------------
The art is repaired by :mod:`mascot_remaster`, which snaps every pixel to a
six-colour designed palette. That is what makes it crisp, and it is also why
naive brightness animation fails: on a six-colour ramp a 10% brightness change
either does nothing at all or flips a whole colour tier at once, so a "smooth"
sine comes out as three hard steps.

Two mechanisms fix that, and both preserve hard edges and flat colour:

* :data:`ANIM_PALETTE` subdivides the designed red ramp into ~1.1x steps and
  extends it with two bloom entries above hot red for the beacon. Every base
  colour is still an exact member, so an unmodulated frame snaps back to
  precisely the shipped remaster and only animated pixels ever land on an
  interpolated entry. It is a finer ramp of the same designed reds, not a
  wider gamut -- the art stays flat-coloured and hard-edged.
* The snap is *ordered-dithered* between a pixel's two nearest palette
  entries, so a brightness sweep converts pixels progressively instead of all
  at once. With the ramp this fine the two candidates are near-identical reds
  and the dither is all but invisible; on a coarse palette the same mechanism
  leaves a visibly dashed outline, which is why both fixes are needed rather
  than either alone. A pixel sitting exactly on a palette colour has
  projection fraction zero and can never dither, which is what keeps
  un-modulated frames byte-identical.

Cross-fades follow the same discipline: blend the two sprites' RGB, then
re-snap, so intermediate frames stay on-palette and crisp instead of going
muddy. Coverage is carried by an ordered dither on the alpha, so alpha stays
strictly binary -- no partial alpha ever reaches the terminal, because partial
alpha is what produced fringing in the first place.

Geometry
--------
All three renderers agree on row count for a given sprite, but they do *not*
agree on the pixel grid, and handing a quadrant-grid frame to the half-block
backend halves the row count -- re-introducing the exact bug this module
exists to kill. So frames are mode-specific and :data:`DEFAULT_MODE` is
``"halfblock"``, whose square-pixel grid renders correctly under every
backend. Ask for density explicitly::

    frames = mascot_anim.frames_for("idle", 28, mode="quadrant")
    text   = mascot_backend_subcell.render_frame(frames[i], 28, mode="quadrant")

`cols` is the only free parameter of the geometry. Per column width:

* sprites are placed at one shared scale, so the character never changes size
  between poses;
* horizontal placement anchors on each sprite's **foot centroid**, not on the
  image centre. This matters: ``scan.png`` is 154px wide because of its light
  beam, and centring it on the image would shove the body ~20 source pixels
  right of where ``loop_scanning.png``'s body sits -- a visible lurch in the
  middle of the searching cross-fade. Anchoring on the feet lands every pose's
  body on the same axis;
* head cameos are scaled up (:data:`CAMEO_SCALE`) and clamped into the canvas,
  which lands them near-centred -- a deliberate push-in for the cutaway;
* the canvas reserves a little headroom at the top for the bob, and everything
  is clamped so nothing can ever clip.

Sibling modules are optional. :mod:`mascot_remaster` and
:mod:`mascot_backend_subcell` are used when importable and fully substituted
locally when not, so this module never fails to import.

Public API
----------
``STATES``            ``{state: [Image, ...]}`` at the module defaults.
``frames_for``        frames for a state at a given width/mode (memoized).
``canvas_rows``       terminal rows every frame occupies. The invariant.
``canvas_size``       pixel canvas size for a width/mode.
``FPS_HINT``          per-state preferred frame rate.
``ONE_SHOT``          states that play once instead of looping.
``selftest``          asserts the invariant against the real backends.
"""

from __future__ import annotations

import math
import os
from collections import namedtuple

from PIL import Image, ImageEnhance

try:
    import numpy as np
    _HAVE_NUMPY = True
except Exception:  # pragma: no cover - numpy is present in every shipped env
    np = None
    _HAVE_NUMPY = False


# ---------------------------------------------------------------------------
# Optional siblings
# ---------------------------------------------------------------------------

try:
    import mascot_remaster as _remaster_mod
except Exception:  # pragma: no cover - exercised by the no-sibling fallback
    _remaster_mod = None

try:
    import mascot_backend_subcell as _subcell
except Exception:  # pragma: no cover
    _subcell = None

try:
    import mascot_backend_halfblock as _halfblock
except Exception:  # pragma: no cover
    _halfblock = None


HERE = os.path.dirname(os.path.abspath(__file__))
ASSET_DIR = os.path.join(HERE, "assets", "mascot")
QA_DIR = os.path.join(HERE, "assets", "qa")


# ---------------------------------------------------------------------------
# Palettes
# ---------------------------------------------------------------------------

#: The six colours the mascot is *designed* in -- mirrored from
#: :mod:`mascot_remaster` so this module still works standalone.
BASE_PALETTE = (
    (10, 10, 12),      # near-black chassis fill / screen interior
    (60, 14, 16),      # deep red shadow
    (120, 26, 28),     # mid red
    (200, 40, 42),     # bright red outline -- the shape-defining colour
    (255, 72, 68),     # hot red highlight
    (225, 215, 215),   # off-white specular
)

#: The mascot's brightness ramp, darkest to brightest. The first five entries
#: are the designed reds; the last two extend the ramp above hot red so the
#: antenna beacon has somewhere to glow to without clipping straight to the
#: off-white specular.
_RAMP = (
    (10, 10, 12),
    (60, 14, 16),
    (120, 26, 28),
    (200, 40, 42),
    (255, 72, 68),
    (255, 116, 106),   # bloom 1 -- lit beacon
    (255, 168, 154),   # bloom 2 -- beacon at full pulse
)

#: How many sub-steps each ramp segment is divided into for
#: :data:`ANIM_PALETTE`.
#:
#: This is the knob that decides whether a brightness sweep reads as smooth.
#: On the bare six-colour palette the tier ratios are 1.4x to 2.8x, so a 10%
#: brightness change either does nothing or flips an entire colour region at
#: once -- which is exactly why the shipped three-frame idle read as a
#: stutter rather than a breath. Subdividing to ~1.1x steps means a sine
#: sweep walks the outline continuously down and back up the ramp, and it
#: also all but removes visible ordered-dither speckle, because a brightened
#: pixel now lands almost exactly *on* a palette entry instead of halfway
#: between two.
_RAMP_STEPS = 4


def _build_anim_palette():
    """Subdivide the red ramp, keeping every base colour an exact member.

    Base membership is load-bearing: it is what makes an unmodulated frame
    snap back to precisely the colours :mod:`mascot_remaster` produced, so
    the resting mascot is byte-identical to the shipped art and only
    *animated* pixels ever touch an interpolated entry.
    """
    out = []
    for i in range(len(_RAMP) - 1):
        a = _RAMP[i]
        b = _RAMP[i + 1]
        for s in range(_RAMP_STEPS):
            f = s / float(_RAMP_STEPS)
            out.append(tuple(int(round(a[c] + (b[c] - a[c]) * f))
                             for c in range(3)))
    out.append(_RAMP[-1])
    out.append(BASE_PALETTE[5])          # off-white specular, off-ramp
    return tuple(out)


#: The palette animated frames snap to: the designed ramp, subdivided, plus
#: the off-white specular. Still flat colours and hard edges -- this is a
#: finer ramp of the same designed reds, not a wider gamut.
ANIM_PALETTE = _build_anim_palette()

#: Alpha above this is opaque. Matches :mod:`mascot_remaster`; the source
#: alpha is binary and everything in between is resample halo.
ALPHA_THRESHOLD = 110

#: 4x4 Bayer matrix, normalised to the open interval (0, 1). Open on both
#: ends deliberately: a threshold of exactly 0 would let a pixel sitting
#: precisely on a palette colour dither anyway, and a threshold of exactly 1
#: would make fully-covered pixels drop out of a cross-fade.
_BAYER4 = (
    (0, 8, 2, 10),
    (12, 4, 14, 6),
    (3, 11, 1, 9),
    (15, 7, 13, 5),
)


# ---------------------------------------------------------------------------
# Sprites and per-sprite placement policy
# ---------------------------------------------------------------------------

#: How much bigger a head cameo is drawn than its natural relative size.
#:
#: The cameos are close-up shots, so drawing them at the same scale as the
#: full-body poses makes them read as a shrunken head sitting on the floor.
#: 1.45 fills ~86% of the canvas height, which reads as a camera push-in --
#: and it is free, because it still fits inside the width the light beam
#: already forces the canvas to reserve.
CAMEO_SCALE = 1.45

#: ``stem -> (scale, anchor policy)``.
#:
#: ``"foot"`` sprites are aligned on their foot centroid and set the canvas
#: width budget. ``"center"`` sprites only have to *fit*: they are placed
#: from the foot anchor and then clamped into the canvas, which for a cameo
#: this large lands it near-centred without letting it inflate the canvas.
_SPRITES = {
    "idle":           (1.0, "foot"),
    "loop_scanning":  (1.0, "foot"),
    "scan":           (1.0, "foot"),
    "loop_loading":   (1.0, "foot"),
    "loop_uploading": (1.0, "foot"),
    "typing":         (1.0, "foot"),
    "success":        (1.0, "foot"),
    "expr_thinking":  (CAMEO_SCALE, "center"),
    "expr_alert":     (CAMEO_SCALE, "center"),
    "expr_error":     (CAMEO_SCALE, "center"),
}

#: Vertical headroom reserved above the content, in square-pixel units, for
#: the bob to move into. Mode-independent on purpose -- :func:`canvas_rows`
#: must not depend on which renderer the caller ends up using. 1.5 is the
#: smallest value that leaves every mode at least its full bob amplitude
#: (sextant needs the most, at 2 canvas pixels).
_HEADROOM_SQ = 1.5

#: Bob amplitude in terminal rows. Half a row means one pixel on the
#: half-block and quadrant grids and 1.5 (rounding to 0/1/2) on sextant.
_BOB_ROWS = 0.5

#: Subpixel grid per renderer mode: (columns, rows) of image pixels per
#: terminal cell. Mirrored from :mod:`mascot_backend_subcell`.
_SUBGRID = {
    "halfblock": (1, 2),
    "quadrant": (2, 2),
    "sextant": (2, 3),
}

#: Frames are grid-specific; only the half-block square-pixel grid survives
#: being handed to a different backend with its row count intact.
DEFAULT_MODE = "halfblock"

#: Column width :data:`STATES` is built at.
DEFAULT_COLS = 24


# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------

STATE_ORDER = (
    "idle", "searching", "thinking", "working", "uploading", "success", "error",
)

#: Preferred frame rate per state, so the render loop can run the smooth
#: looping states fast and the flourishes faster still. The old flat 6fps is
#: a large part of why the animation read as choppy: at 6fps a 12-frame sine
#: takes two full seconds per breath and the eye resolves every step.
FPS_HINT = {
    "idle": 11,
    "searching": 12,
    "thinking": 12,
    "working": 10,
    "uploading": 12,
    "success": 14,
    "error": 12,
}

#: States that play once and stop rather than looping. Preserved from the
#: shipped semantics -- ``Mascot.success()`` / ``.error()`` block briefly on
#: a one-shot flourish.
ONE_SHOT = frozenset({"success", "error"})

#: Intended frame count per state. Asserted by :func:`selftest`, so a plan
#: edit that changes a length fails loudly instead of drifting.
FRAME_COUNTS = {
    "idle": 12,
    "searching": 14,
    "thinking": 14,
    "working": 12,
    "uploading": 12,
    "success": 10,
    "error": 10,
}


# ---------------------------------------------------------------------------
# Source measurement
# ---------------------------------------------------------------------------

_Metrics = namedtuple("_Metrics", "size bbox foot")

_metrics_cache = {}


def _load_source(stem):
    img = Image.open(os.path.join(ASSET_DIR, stem + ".png"))
    img.load()
    return img.convert("RGBA") if img.mode != "RGBA" else img


def _measure(stem):
    """Measure a source sprite: opaque bbox and foot centroid.

    The foot centroid is the horizontal centre of mass of the bottom 12% of
    the opaque bounding box. It is the alignment anchor because it is the one
    landmark that is stable across the whole asset set -- measured, it sits
    between x=53 and x=60 on every sprite including the head cameos, while
    image centres range from 53 to 77. Anchoring on image centre is what
    would make ``scan.png``'s beam drag the body sideways.
    """
    if stem in _metrics_cache:
        return _metrics_cache[stem]

    img = _load_source(stem)
    w, h = img.size
    alpha = img.split()[3]

    # Column/row opacity profiles without numpy, so measurement never
    # depends on the optional dependency.
    px = alpha.load()
    opaque_rows = []
    for y in range(h):
        xs = [x for x in range(w) if px[x, y] > ALPHA_THRESHOLD]
        opaque_rows.append(xs)

    ys = [y for y, xs in enumerate(opaque_rows) if xs]
    if not ys:
        m = _Metrics((w, h), (0, 0, w, h), w / 2.0)
        _metrics_cache[stem] = m
        return m

    y0, y1 = ys[0], ys[-1] + 1
    x0 = min(min(xs) for xs in opaque_rows if xs)
    x1 = max(max(xs) for xs in opaque_rows if xs) + 1

    band = max(2, int((y1 - y0) * 0.12))
    foot_xs = [x for y in range(max(y0, y1 - band), y1) for x in opaque_rows[y]]
    foot = sum(foot_xs) / len(foot_xs) if foot_xs else (x0 + x1) / 2.0

    m = _Metrics((w, h), (x0, y0, x1, y1), foot)
    _metrics_cache[stem] = m
    return m


def _canvas_budget():
    """Return ``(src_left, src_right, src_w, src_h)`` in source pixels.

    ``src_left``/``src_right`` are how far the foot-anchored sprites reach
    either side of the shared body axis; ``src_w`` widens beyond their sum
    only if a centred sprite (a scaled-up cameo) would not otherwise fit.
    ``src_h`` is the tallest scaled content.
    """
    if _canvas_budget._cached is not None:
        return _canvas_budget._cached

    left = right = 0.0
    fit_w = 0.0
    height = 0.0
    for stem, (k, policy) in _SPRITES.items():
        m = _measure(stem)
        x0, y0, x1, y1 = m.bbox
        height = max(height, (y1 - y0) * k)
        if policy == "foot":
            left = max(left, (m.foot - x0) * k)
            right = max(right, (x1 - m.foot) * k)
        else:
            fit_w = max(fit_w, (x1 - x0) * k)

    width = max(left + right, fit_w)
    _canvas_budget._cached = (left, right, width, height)
    return _canvas_budget._cached


_canvas_budget._cached = None


# ---------------------------------------------------------------------------
# Geometry -- the invariant
# ---------------------------------------------------------------------------

def _check_mode(mode):
    mode = DEFAULT_MODE if mode is None else str(mode)
    if mode not in _SUBGRID:
        raise ValueError(
            "unknown mode %r (expected one of %s)"
            % (mode, ", ".join(sorted(_SUBGRID)))
        )
    return mode


def canvas_rows(cols):
    """Terminal rows every mascot frame occupies at ``cols`` columns wide.

    This is the number the render loop cursor-ups by, and it is deliberately
    a function of ``cols`` alone -- not of the state, not of the frame, and
    not of the renderer mode. All three backends agree on row count for a
    given sprite, so the answer holds whichever one draws it.

    Call this *before* the first frame is printed and make sure that many
    rows exist below the cursor. Printing a tall frame at the bottom of the
    terminal scrolls it, and a scroll moves the frame origin out from under
    the cursor-up arithmetic just as surely as a wrong row count does.
    """
    cols = max(1, int(cols))
    _, _, src_w, src_h = _canvas_budget()
    content_sq = cols * src_h / src_w
    return max(1, int(math.ceil((content_sq + _HEADROOM_SQ) / 2.0)))


def canvas_size(cols, mode=None):
    """Pixel canvas size ``(w, h)`` every frame is composited onto.

    Half-block frames are square-pixel (``cols`` x ``2*rows``). The sub-cell
    modes pack more image pixels into the same cells -- quadrant doubles
    horizontally, sextant also multiplies vertically by 3/2 -- which is why
    frames are grid-specific and must be rendered by the backend they were
    built for.
    """
    mode = _check_mode(mode)
    sub_cols, sub_rows = _SUBGRID[mode]
    cols = max(1, int(cols))
    return cols * sub_cols, canvas_rows(cols) * sub_rows


def _scales(cols, mode):
    """Source-pixel -> canvas-pixel scale factors ``(sx, sy)``.

    They are not equal outside half-block mode and must not be. A terminal
    cell is one wide by two tall in square-pixel terms, so a quadrant
    subpixel is half as wide as it is tall and needs twice as many
    horizontal samples to cover the same physical width. The relation that
    keeps physical pixels square is ``sx = 2*sy*sub_cols/sub_rows``, which
    makes ``sy`` come out mode-independent -- the reason row counts agree
    across every renderer.
    """
    sub_cols, sub_rows = _SUBGRID[mode]
    _, _, src_w, _ = _canvas_budget()
    cols = max(1, int(cols))
    sx = cols * sub_cols / src_w
    sy = cols * sub_rows / (2.0 * src_w)
    return sx, sy


def _bob_amp(mode):
    """Bob amplitude in canvas pixels for this mode (half a terminal row)."""
    _, sub_rows = _SUBGRID[mode]
    return _BOB_ROWS * sub_rows


# ---------------------------------------------------------------------------
# Art repair (delegates to mascot_remaster; substituted locally if absent)
# ---------------------------------------------------------------------------

def _local_params(stem):
    """The per-asset remaster parameters, mirrored for standalone use.

    Full-body poses carry the "CYPHEX" wordmark across the head screen and
    cap at sat=2.3 to keep its letter gaps from fusing into a solid bar.
    Head cameos have no wordmark to protect and take the harder push.
    """
    sat = 2.8 if stem.startswith("expr_") else 2.3
    return dict(sat=sat, gamma=1.0, black_floor=0,
                palette=BASE_PALETTE, alpha_threshold=ALPHA_THRESHOLD,
                despeckle=True)


def _local_remaster_to_grid(img, grid_w, grid_h, sat=2.3, gamma=1.0,
                            black_floor=0, palette=BASE_PALETTE,
                            alpha_threshold=ALPHA_THRESHOLD, despeckle=True):
    """Standalone copy of the de-JPEG repair pipeline.

    Order matters and is the whole trick: resize to the small target *first*
    with a BOX (area-average) filter, because that is what low-pass-filters
    the JPEG ringing away instead of sharpening it into mush. Only then
    gamma, saturate about the per-pixel grey mean, and snap to the designed
    palette. Alpha is binarised because partial alpha here is resample halo,
    and halo is what produces fringing.
    """
    if not _HAVE_NUMPY:
        # Last-resort path: geometry stays exactly right, crispness does not.
        out = img.resize((grid_w, grid_h), Image.BOX)
        r, g, b, a = out.split()
        a = a.point(lambda v: 255 if v > alpha_threshold else 0)
        return Image.merge("RGBA", (r, g, b, a))

    arr = np.asarray(img.convert("RGBA"), dtype=np.float32)
    alpha = arr[..., 3:4] / 255.0
    premul = np.concatenate([arr[..., :3] * alpha, arr[..., 3:4]], axis=2)
    small = np.asarray(
        Image.fromarray(np.clip(premul, 0, 255).astype(np.uint8), "RGBA")
        .resize((grid_w, grid_h), Image.BOX),
        dtype=np.float32,
    )
    a_small = small[..., 3:4]
    rgb = np.where(a_small > 0, small[..., :3] * 255.0 / np.maximum(a_small, 1e-6), 0.0)

    if gamma and gamma != 1.0:
        rgb = np.power(np.clip(rgb, 0, 255) / 255.0, float(gamma)) * 255.0
    if sat and sat != 1.0:
        mean = rgb.mean(axis=2, keepdims=True)
        rgb = mean + (rgb - mean) * float(sat)
    rgb = np.clip(rgb, 0.0, 255.0)
    if black_floor:
        rgb[rgb.mean(axis=2) < float(black_floor)] = 0.0

    pal = np.asarray(palette, dtype=np.float32)
    flat = rgb.reshape(-1, 3)
    idx = ((flat[:, None, :] - pal[None, :, :]) ** 2).sum(-1).argmin(1)
    snapped = pal[idx].reshape(rgb.shape)

    opaque = (a_small[..., 0] > float(alpha_threshold))
    out = np.zeros((grid_h, grid_w, 4), dtype=np.uint8)
    out[..., :3] = np.clip(snapped, 0, 255).astype(np.uint8)
    out[..., 3] = np.where(opaque, 255, 0)
    out[~opaque] = 0
    return Image.fromarray(out, "RGBA")


_sprite_cache = {}


def _remastered(stem, grid_w, grid_h):
    """Repaired sprite at exactly ``grid_w x grid_h``, memoized.

    The whole source image is repaired at the target size -- never resized
    afterwards -- so nothing re-muddies the palette-snapped pixels. Placement
    onto the canvas is an integer paste, which resamples nothing.
    """
    key = (stem, grid_w, grid_h)
    hit = _sprite_cache.get(key)
    if hit is not None:
        return hit

    src = _load_source(stem)
    if _remaster_mod is not None:
        try:
            params = _remaster_mod.params_for(stem)
            img = _remaster_mod.remaster_to_grid(src, grid_w, grid_h, **params)
        except Exception:
            img = _local_remaster_to_grid(src, grid_w, grid_h,
                                          **_local_params(stem))
    else:
        img = _local_remaster_to_grid(src, grid_w, grid_h, **_local_params(stem))

    _sprite_cache[key] = img
    return img


# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------

_Placed = namedtuple("_Placed", "img x y top bottom left right")

_placed_cache = {}


def _placed(stem, cols, mode):
    """Repair and position one sprite on the shared canvas (bob = 0).

    Returns the sprite image plus its paste origin and the canvas-space
    bounding box of its opaque content, which the glow helpers use to place
    row bands relative to the body rather than to the canvas.
    """
    key = (stem, cols, mode)
    hit = _placed_cache.get(key)
    if hit is not None:
        return hit

    k, policy = _SPRITES[stem]
    m = _measure(stem)
    sx, sy = _scales(cols, mode)
    cw, ch = canvas_size(cols, mode)
    src_left, _, src_w, _ = _canvas_budget()

    sw, sh = m.size
    grid_w = max(1, int(round(sw * k * sx)))
    grid_h = max(1, int(round(sh * k * sy)))
    img = _remastered(stem, grid_w, grid_h)

    # Content bbox in this sprite's own repaired pixel space.
    bx0 = m.bbox[0] * k * sx
    bx1 = m.bbox[2] * k * sx
    by0 = m.bbox[1] * k * sy
    by1 = m.bbox[3] * k * sy

    if policy == "foot":
        x = (src_left - m.foot * k) * sx
    else:
        x = (src_w - (m.bbox[2] - m.bbox[0]) * k) / 2.0 * sx - bx0
    y = ch - by1  # feet planted on the bottom edge

    x = int(round(x))
    y = int(round(y))

    # Clamp so no sprite can ever be clipped, whatever the rounding did.
    x = min(max(x, -int(math.floor(bx0))), cw - int(math.ceil(bx1)))
    y = min(max(y, -int(math.floor(by0))), ch - int(math.ceil(by1)))

    placed = _Placed(img, x, y,
                     top=y + int(math.floor(by0)),
                     bottom=y + int(math.ceil(by1)),
                     left=x + int(math.floor(bx0)),
                     right=x + int(math.ceil(bx1)))
    _placed_cache[key] = placed
    return placed


# ---------------------------------------------------------------------------
# Frame buffers
# ---------------------------------------------------------------------------
#
# A frame in flight is a float RGB canvas plus a boolean coverage mask. Every
# effect is a cheap array op on ~30x40 pixels, all precomputed once at import
# and memoized, so nothing here costs anything per render tick.

class _Buf(object):
    """Float RGB canvas + boolean coverage, plus the placed content bbox."""

    __slots__ = ("rgb", "op", "top", "bottom", "left", "right")

    def __init__(self, rgb, op, top, bottom, left, right):
        self.rgb = rgb
        self.op = op
        self.top = top
        self.bottom = bottom
        self.left = left
        self.right = right


def _buf(stem, cols, mode, bob=0):
    """Composite one sprite onto the shared canvas, lifted ``bob`` pixels."""
    p = _placed(stem, cols, mode)
    cw, ch = canvas_size(cols, mode)

    canvas = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
    canvas.paste(p.img, (p.x, p.y - int(bob)), p.img)

    arr = np.asarray(canvas, dtype=np.float32)
    return _Buf(arr[..., :3].copy(), arr[..., 3] > 127,
                p.top - bob, p.bottom - bob, p.left, p.right)


def _bayer(h, w):
    """Bayer threshold tile of shape (h, w), values in (0, 1)."""
    base = (np.asarray(_BAYER4, dtype=np.float32) + 0.5) / 16.0
    reps_y = -(-h // 4)
    reps_x = -(-w // 4)
    return np.tile(base, (reps_y, reps_x))[:h, :w]


def _snap(rgb, op, dither=True, palette=ANIM_PALETTE):
    """Snap a float RGB canvas to ``palette`` and return an RGBA image.

    With ``dither`` the choice is an ordered dither between the pixel's two
    nearest palette entries, weighted by where the pixel falls on the segment
    between them. A pixel sitting exactly on a palette colour projects to
    zero and can never dither, so an unmodulated frame comes out identical to
    the plain nearest-neighbour snap; a pixel that brightness pushed a third
    of the way to the next tier converts about a third of its neighbourhood,
    which is what makes a sine sweep read as a gradient instead of a flip.
    """
    h, w = op.shape
    pal = np.asarray(palette, dtype=np.float32)
    flat = np.clip(rgb, 0.0, 255.0).reshape(-1, 3)

    d = ((flat[:, None, :] - pal[None, :, :]) ** 2).sum(-1)
    if dither and pal.shape[0] > 1:
        order = np.argpartition(d, 1, axis=1)[:, :2]
        # argpartition does not order the two it selects; sort them.
        first = d[np.arange(d.shape[0])[:, None], order]
        swap = first[:, 0] > first[:, 1]
        i1 = np.where(swap, order[:, 1], order[:, 0])
        i2 = np.where(swap, order[:, 0], order[:, 1])
        c1 = pal[i1]
        c2 = pal[i2]
        seg = c2 - c1
        denom = np.maximum((seg * seg).sum(-1), 1e-6)
        f = np.clip(((flat - c1) * seg).sum(-1) / denom, 0.0, 1.0)
        thr = _bayer(h, w).reshape(-1)
        out = np.where((f > thr)[:, None], c2, c1)
    else:
        out = pal[d.argmin(1)]

    rgba = np.zeros((h, w, 4), dtype=np.uint8)
    rgba[..., :3] = out.reshape(h, w, 3).astype(np.uint8)
    rgba[..., 3] = np.where(op, 255, 0)
    rgba[~op] = 0
    return Image.fromarray(rgba, "RGBA")


def _dissolve(a, b, t):
    """Ordered-dither cross-fade between two buffers. Returns a new buffer.

    Coverage is dithered rather than blended so alpha stays strictly binary:
    ``alpha = a_op*(1-t) + b_op*t`` is compared against the Bayer tile, so a
    pixel covered only by ``a`` drops out progressively as ``t`` rises rather
    than the whole silhouette switching at the midpoint.

    Colour is un-premultiplied back out of the coverage-weighted sum, which
    means a pixel covered by only one of the two sprites keeps that sprite's
    full-brightness colour instead of fading toward black. All of the motion
    is carried by the dither; none of it is carried by muddying the palette.
    Overlapping pixels get the straight lerp, and re-snapping afterwards puts
    them back on-palette.

    At ``t == 0`` and ``t == 1`` this is exactly ``a`` and exactly ``b``.
    """
    t = float(min(max(t, 0.0), 1.0))
    a_op = a.op.astype(np.float32)
    b_op = b.op.astype(np.float32)
    cover = a_op * (1.0 - t) + b_op * t

    num = a.rgb * (a_op * (1.0 - t))[..., None] + b.rgb * (b_op * t)[..., None]
    rgb = num / np.maximum(cover, 1e-6)[..., None]

    op = cover > _bayer(*a.op.shape)
    lerp = lambda p, q: int(round(p * (1.0 - t) + q * t))
    return _Buf(rgb, op,
                lerp(a.top, b.top), lerp(a.bottom, b.bottom),
                lerp(a.left, b.left), lerp(a.right, b.right))


def _gain(buf, factor):
    """Uniform brightness multiply. Returns a new buffer."""
    return _Buf(buf.rgb * float(factor), buf.op,
                buf.top, buf.bottom, buf.left, buf.right)


def _band(buf, centre, sigma, amount, wrap=False):
    """Multiply a soft gaussian row band over the buffer.

    ``centre`` and ``sigma`` are canvas rows. ``wrap`` measures distance
    cyclically over the content height so a drifting band can leave the top
    and re-enter at the bottom without a seam -- which is what lets the
    uploading state loop.
    """
    h = buf.rgb.shape[0]
    rows = np.arange(h, dtype=np.float32)
    dist = rows - float(centre)
    if wrap:
        span = max(1.0, float(buf.bottom - buf.top))
        dist = (dist + span * 0.5) % span - span * 0.5
    g = np.exp(-0.5 * (dist / max(1e-3, float(sigma))) ** 2)
    mult = 1.0 + float(amount) * g
    return _Buf(buf.rgb * mult[:, None, None], buf.op,
                buf.top, buf.bottom, buf.left, buf.right)


def _beacon(buf, amount):
    """Glow the antenna by ``amount``.

    Deliberately narrow. A wider band catches the top edge of the head
    screen, and because the source art has a blown-out specular pixel up
    there, a strong wide glow turns that pixel white and reads as a render
    fault rather than as a beacon. Centre one row into the content with a
    ~1.5 row sigma and only the antenna stalk and bulb light up.
    """
    if amount <= 0.0:
        return buf
    span = max(1.0, float(buf.bottom - buf.top))
    return _band(buf, buf.top + span * 0.04, max(0.9, span * 0.045), amount)


# ---------------------------------------------------------------------------
# Easing helpers
# ---------------------------------------------------------------------------

def _sine(t, phase=0.0):
    """Sine over a normalised loop position, in [-1, 1]."""
    return math.sin(2.0 * math.pi * (t + phase))


def _rise(t, phase=0.0):
    """Raised cosine over a normalised loop position, in [0, 1].

    Zero at ``t = 0`` and back to zero at ``t = 1``, so anything driven by
    it loops seamlessly with no discontinuity at the wrap.
    """
    return 0.5 - 0.5 * math.cos(2.0 * math.pi * (t + phase))


def _bob(t, amp, phase=0.0):
    """Bob offset in whole canvas pixels for loop position ``t``."""
    return int(round(amp * _rise(t, phase)))


# ---------------------------------------------------------------------------
# State builders
# ---------------------------------------------------------------------------
#
# Every builder returns exactly FRAME_COUNTS[state] buffers. Looping states
# are written so frame N-1 flows into frame 0 with no discontinuity.

def _build_idle(cols, mode):
    """Calm sine breathe, slow one-pixel bob, one antenna blip per loop.

    This state runs for long stretches, so it has to be alive without being
    distracting. The breathe peaks a quarter of the way through the loop and
    the beacon halfway, so the beacon fires while the body is on its way
    *down* -- they read as two separate signs of life rather than fusing into
    one throb -- and the beacon's sixth-power window makes it a brief blip
    rather than a slow pulse.
    """
    n = FRAME_COUNTS["idle"]
    amp = _bob_amp(mode)
    out = []
    for i in range(n):
        t = i / n
        b = _buf("idle", cols, mode, _bob(t, amp))
        b = _gain(b, 1.0 + 0.16 * _sine(t))
        blip = max(0.0, _sine(t, -0.25)) ** 6
        out.append(_beacon(b, 1.40 * blip))
    return out


def _build_searching(cols, mode):
    """The light-beam hero moment: pulse, cross-fade to the beam, fade back.

    ``scan.png`` is the pose with the beam and ``loop_scanning.png`` is the
    idle-scan pose; the old build hard-cut between them. Both are foot
    anchored onto the shared canvas, so the body stays on its axis while the
    beam -- which is why the canvas reserves the extra width on the right --
    dithers in and out around it.
    """
    amp = _bob_amp(mode)
    out = []

    for i in range(6):                      # base pose, breathing
        t = i / 6.0
        b = _buf("loop_scanning", cols, mode, _bob(t, amp, 0.15))
        out.append(_gain(b, 1.0 + 0.10 * _sine(t)))

    base = _buf("loop_scanning", cols, mode, 0)
    beam = _buf("scan", cols, mode, 0)

    for t, lift in ((0.34, 1.06), (0.68, 1.14)):   # dissolve in, charging
        out.append(_gain(_dissolve(base, beam, t), lift))

    for lift in (1.45, 1.22, 1.04):                # the flash, easing out
        out.append(_gain(beam, lift))

    for t, lift in ((0.68, 1.08), (0.34, 1.02)):   # dissolve back
        out.append(_gain(_dissolve(base, beam, t), lift))

    out.append(_gain(base, 1.0))                   # settle, matches frame 0
    return out


def _build_thinking(cols, mode):
    """The state that used to break: a cross-fade, not a cut, to the cameo.

    ``loop_loading.png`` is a full body and ``expr_thinking.png`` is a
    107x107 head close-up; hard-cutting between them changed the render from
    19 rows to 14 and left half a robot behind. Here the cameo is scaled up
    and padded onto the same canvas, and the framing change is a dissolve, so
    the row count is constant across the whole transition and the cutaway
    reads as a deliberate push-in.
    """
    amp = _bob_amp(mode)
    out = []

    for i in range(5):                      # full body, thinking away
        t = i / 5.0
        b = _buf("loop_loading", cols, mode, _bob(t, amp, 0.1))
        out.append(_gain(b, 1.0 + 0.11 * _sine(t)))

    body = _buf("loop_loading", cols, mode, 0)
    head = _buf("expr_thinking", cols, mode, 0)

    # The two poses barely overlap -- a full body against a head filling most
    # of the canvas -- so the dither has a lot of non-overlapping area to
    # carry and the mid-fade frames are the busiest in the whole set. Three
    # steps rather than two shortens each one's dwell, and dipping the
    # brightness across the fade sinks the busiest pixels toward the dark end
    # of the ramp so the scramble reads as a push-in through shadow instead
    # of as noise.
    for t, dip in ((0.28, 0.84), (0.55, 0.70), (0.80, 0.84)):
        out.append(_gain(_dissolve(body, head, t), dip))

    for i in range(4):                      # cameo, the "..." pulsing
        t = i / 4.0
        h = _buf("expr_thinking", cols, mode, _bob(t, max(1, int(amp))))
        out.append(_gain(h, 1.06 + 0.10 * _sine(t)))

    for t, dip in ((0.70, 0.82), (0.35, 0.88)):     # pull back out
        out.append(_gain(_dissolve(body, head, t), dip))

    return out


def _build_working(cols, mode):
    """Laptop pose for long local operations: bob, breathe, key-tap flicker.

    The flicker is a fast gaussian band low on the body where the laptop is,
    running at three times the loop rate, so it reads as hands working rather
    than as the whole chassis pulsing.
    """
    n = FRAME_COUNTS["working"]
    amp = _bob_amp(mode)
    out = []
    for i in range(n):
        t = i / n
        b = _buf("typing", cols, mode, _bob(t, amp))
        b = _gain(b, 1.0 + 0.08 * _sine(t))
        span = max(1.0, float(b.bottom - b.top))
        tap = max(0.0, _sine(t * 3.0)) ** 3
        out.append(_band(b, b.top + span * 0.78, span * 0.16, 0.30 * tap))
    return out


def _build_uploading(cols, mode):
    """Energy drifting upward through the chassis.

    The band centre sweeps from the feet to the head over one loop and the
    distance is measured cyclically, so it leaves the top and re-enters at
    the bottom with no seam at the wrap.
    """
    n = FRAME_COUNTS["uploading"]
    amp = _bob_amp(mode)
    out = []
    for i in range(n):
        t = i / n
        b = _buf("loop_uploading", cols, mode, _bob(t, amp, 0.25))
        span = max(1.0, float(b.bottom - b.top))
        centre = b.bottom - span * t
        b = _band(b, centre, max(1.0, span * 0.16), 0.80, wrap=True)
        out.append(_gain(b, 1.0 + 0.05 * _sine(t)))
    return out


def _build_success(cols, mode):
    """One-shot flourish: a bright flash easing down to rest, with a hop.

    Preserves the shipped "blocking one-shot" semantics -- the caller plays
    it through once and returns -- but over ten eased frames instead of two
    hard ones, so the flash decays rather than snapping off.
    """
    amp = _bob_amp(mode)
    hop = max(1, int(round(amp)))
    plan = (
        (1.85, hop), (1.62, hop), (1.42, hop), (1.26, 0), (1.15, 0),
        (1.08, 0), (1.03, 0), (1.0, 0), (1.0, 0), (1.0, 0),
    )
    return [_gain(_buf("success", cols, mode, b), g) for g, b in plan]


def _build_error(cols, mode):
    """One-shot alarm strobe across the alert and X_X cameos.

    The cuts are deliberately hard -- an alarm should snap -- but both poses
    sit on the same canvas at the same row count, so it reads as a strobe
    instead of as the redraw tearing. The rhythm is two fast alert/error
    pairs, then a dip and a hold, so it lands as a beat rather than a flicker.
    """
    plan = (
        ("expr_alert", 1.70), ("expr_alert", 1.00),
        ("expr_error", 1.80), ("expr_error", 1.05),
        ("expr_alert", 1.55), ("expr_alert", 1.00),
        ("expr_error", 1.80), ("expr_error", 1.05),
        ("expr_error", 0.82), ("expr_error", 1.00),
    )
    return [_gain(_buf(stem, cols, mode, 0), g) for stem, g in plan]


_BUILDERS = {
    "idle": _build_idle,
    "searching": _build_searching,
    "thinking": _build_thinking,
    "working": _build_working,
    "uploading": _build_uploading,
    "success": _build_success,
    "error": _build_error,
}


# ---------------------------------------------------------------------------
# No-numpy fallback
# ---------------------------------------------------------------------------

def _build_plain(state, cols, mode):
    """Degraded builder used only when numpy is unavailable.

    Geometry -- the invariant this module exists for -- is identical. Only
    the synthesis quality drops: brightness comes from ImageEnhance and
    cross-fades from ``Image.blend`` with alpha re-binarised, so intermediate
    frames are softer than the dithered path would give.
    """
    cw, ch = canvas_size(cols, mode)

    def flat(stem, bob=0, gain=1.0):
        p = _placed(stem, cols, mode)
        canvas = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
        canvas.paste(p.img, (p.x, p.y - int(bob)), p.img)
        if gain != 1.0:
            canvas = ImageEnhance.Brightness(canvas).enhance(gain)
        return canvas

    def mix(a, b, t):
        out = Image.blend(a, b, t)
        r, g, bl, al = out.split()
        return Image.merge("RGBA", (r, g, bl,
                                    al.point(lambda v: 255 if v > 127 else 0)))

    n = FRAME_COUNTS[state]
    stem = {"idle": "idle", "searching": "loop_scanning",
            "thinking": "loop_loading", "working": "typing",
            "uploading": "loop_uploading", "success": "success",
            "error": "expr_error"}[state]
    alt = {"searching": "scan", "thinking": "expr_thinking",
           "error": "expr_alert"}.get(state)

    frames = []
    for i in range(n):
        t = i / n
        gain = 1.0 + 0.12 * _sine(t)
        bob = _bob(t, _bob_amp(mode))
        if alt and n - 5 <= i < n - 1:
            frames.append(mix(flat(stem), flat(alt), (i - (n - 5)) / 4.0))
        else:
            frames.append(flat(stem, bob, gain))
    return frames


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_frame_cache = {}


def frames_for(state, cols=DEFAULT_COLS, mode=None):
    """Return the animation frames for ``state`` at ``cols`` columns wide.

    Memoized per ``(state, cols, mode)`` -- the whole set is built once and
    the render loop only ever indexes a list, so nothing is recomputed on a
    frame tick. Unknown states fall back to ``idle`` rather than raising, so
    a typo in a caller degrades to a calm mascot instead of a crash.

    Every returned image has the same ``.size``, and that size renders to
    exactly ``canvas_rows(cols)`` terminal rows under the backend matching
    ``mode``.
    """
    mode = _check_mode(mode)
    cols = max(1, int(cols))
    state = state if state in _BUILDERS else "idle"

    key = (state, cols, mode)
    hit = _frame_cache.get(key)
    if hit is not None:
        return hit

    if _HAVE_NUMPY:
        bufs = _BUILDERS[state](cols, mode)
        frames = tuple(_snap(b.rgb, b.op) for b in bufs)
    else:  # pragma: no cover - numpy is present in every shipped env
        frames = tuple(_build_plain(state, cols, mode))

    _frame_cache[key] = frames
    return frames


def build_states(cols=DEFAULT_COLS, mode=None):
    """Return ``{state: [Image, ...]}`` for every state at one width."""
    return {name: list(frames_for(name, cols, mode)) for name in STATE_ORDER}


def __getattr__(name):
    """Lazily materialise :data:`STATES` / :data:`AVAILABLE` (PEP 562).

    These used to be built at import. That cost ~90ms of numpy on every
    ``import mascot_anim``, and the CLI's renderer asks for a different
    width and mode than the module defaults -- so the whole build was thrown
    away unused on the path that actually matters. Deferring it keeps the
    documented module attributes working (``mascot_anim.STATES`` and
    ``from mascot_anim import STATES`` both still resolve) while making the
    import itself cheap for the common case of a caller that only wants
    :func:`frames_for` at its own width.
    """
    if name == "STATES":
        try:
            value = build_states()
        except Exception:  # pragma: no cover - a bad asset must not raise here
            value = {}
        globals()["STATES"] = value
        globals()["AVAILABLE"] = bool(value)
        return value
    if name == "AVAILABLE":
        return bool(__getattr__("STATES"))
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _render_rows(img, cols, mode):
    """Line count of a real render, via whichever backend can do ``mode``."""
    if mode == "halfblock" and _halfblock is not None:
        return _halfblock.render_frame(img, cols).count("\n") + 1
    if _subcell is not None:
        return _subcell.render_frame(img, cols, mode=mode).count("\n") + 1
    if _halfblock is not None and mode == "halfblock":
        return _halfblock.render_frame(img, cols).count("\n") + 1
    return None


def selftest(cols_list=(16, 20, 24, 28), modes=None, verbose=True):
    """Assert the fixed-height invariant, for real, against the backends.

    Checks, per column width and renderer mode:

    1. every frame of every state has the same ``.size`` -- the canvas;
    2. every state has its intended frame count;
    3. the actual line count of a real ANSI render equals
       :func:`canvas_rows` for every single frame.

    Check 3 is the one that matters. Checks 1 and 2 could pass on a module
    that still disagreed with the renderer about how tall a frame is, and
    that disagreement is precisely the bug.
    """
    modes = tuple(_SUBGRID) if modes is None else tuple(modes)
    checked = 0
    for mode in modes:
        for cols in cols_list:
            rows = canvas_rows(cols)
            size = canvas_size(cols, mode)
            for state in STATE_ORDER:
                frames = frames_for(state, cols, mode)
                assert len(frames) == FRAME_COUNTS[state], (
                    "%s@%d/%s: %d frames, expected %d"
                    % (state, cols, mode, len(frames), FRAME_COUNTS[state]))
                sizes = {f.size for f in frames}
                assert sizes == {size}, (
                    "%s@%d/%s: canvas drift %s (expected %s)"
                    % (state, cols, mode, sorted(sizes), size))
                for i, f in enumerate(frames):
                    got = _render_rows(f, cols, mode)
                    if got is None:
                        continue
                    assert got == rows, (
                        "%s@%d/%s frame %d rendered %d rows, canvas_rows says %d"
                        % (state, cols, mode, i, got, rows))
                    checked += 1
            if verbose:
                print("  cols=%-3d mode=%-9s canvas=%-9s rows=%-3d  "
                      "%d states OK"
                      % (cols, mode, "%dx%d" % size, rows, len(STATE_ORDER)))
    if verbose:
        print("  %d individual frame renders verified" % checked)
    return True


def dump_filmstrip(state, cols=DEFAULT_COLS, mode=None, out_dir=QA_DIR,
                   upscale=8):
    """Write a QA filmstrip PNG: every frame of ``state``, left to right.

    Upscaled NEAREST over a dark ground so a human can see whether the motion
    reads smoothly and whether anything jitters or changes size between
    frames -- the two failure modes that are invisible in a row-count assert.
    """
    mode = _check_mode(mode)
    frames = frames_for(state, cols, mode)
    if not frames:
        return None

    w, h = frames[0].size
    gap = 1
    sheet = Image.new("RGB",
                      ((w + gap) * len(frames) * upscale, h * upscale),
                      (14, 12, 14))
    for i, f in enumerate(frames):
        tile = Image.new("RGB", (w, h), (14, 12, 14))
        tile.paste(f, (0, 0), f)
        sheet.paste(tile.resize((w * upscale, h * upscale), Image.NEAREST),
                    (i * (w + gap) * upscale, 0))

    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "anim_%s_%d.png" % (state, cols))
    sheet.save(path)
    return path


def _cli():
    print("CYPHEX mascot animation -- self-test")
    print("  numpy=%s  mascot_remaster=%s  halfblock=%s  subcell=%s"
          % (_HAVE_NUMPY, _remaster_mod is not None,
             _halfblock is not None, _subcell is not None))
    left, right, src_w, src_h = _canvas_budget()
    print("  source budget: left=%.1f right=%.1f w=%.1f h=%.1f px"
          % (left, right, src_w, src_h))
    print()
    selftest()
    print()
    for state in STATE_ORDER:
        print("  %-10s %2d frames @ %2dfps%s"
              % (state, FRAME_COUNTS[state], FPS_HINT[state],
                 "  (one-shot)" if state in ONE_SHOT else ""))
    print()
    written = 0
    for cols in (16, 20, 24, 28):
        for state in STATE_ORDER:
            path = dump_filmstrip(state, cols)
            written += 1
            if cols == 28:
                print("  wrote %s" % path)
    print("  (%d filmstrips total, cols 16/20/24/28)" % written)
    print("\nALL CHECKS PASSED")


if __name__ == "__main__":
    _cli()
