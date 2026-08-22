"""
CYPHEX Terminal Mascot — SENTRY
════════════════════════════════════════════════════════════════════════════
A tiny animated pixel-art robot companion that lives in the terminal and
redraws itself in place (ANSI cursor-up + line-clear, never scroll-spams)
on a background thread. It reacts to CLI state:

    mascot.idle()                        resting / breathing
    mascot.searching(label="...")        scan-pulse + light-beam flash
    mascot.thinking(label="...")         load-pulse + "..." head cameo
    mascot.success(msg="...")            brightness flash + settle
    mascot.error(msg="...")              alert/error head-cameo strobe

Each of `idle` / `searching` / `thinking` also works as a context manager:

    with mascot.searching("scanning target..."):
        ...do the real work...
    # __exit__ stops the mascot cleanly, or flips to the error strobe first
    # if the block raised.

`searching(..., flourish=True)` / `thinking(..., flourish=True)` — and the
always-flourish `success` / `error` — are one-shot: they block briefly in
the calling thread, play the beat, then erase. This is the safe way to
bracket a call site that immediately hands the terminal to something else
afterwards (a subprocess, a Rich Live panel, etc.) without leaving a
competing redraw thread running underneath it.

WHERE THE PIXELS COME FROM
--------------------------------------------------------------------------
This module no longer composes its own frames. `mascot_anim` owns *what*
the mascot does and hands back a list of PIL frames per state, already
repaired by `mascot_remaster` (the shipped PNGs were sliced from
WhatsApp-compressed JPEGs — idle.png carries ~6200 distinct colours for art
designed in six — so every frame is BOX-downsampled to the target size
first, then saturated and snapped to the six-colour designed palette with
hard binary alpha). What reaches the terminal is genuinely flat, hard-edged
pixel art rather than resampled JPEG mush.

`mascot_anim` also guarantees the property this module's redraw loop is
built on:

    EVERY FRAME OF EVERY STATE RENDERS TO EXACTLY canvas_rows(cols) ROWS.

THE REDRAW BUG, AND WHY IT CANNOT COME BACK
--------------------------------------------------------------------------
Users saw the old mascot "cut in half with another robot appended". That
was arithmetic, not a rendering artifact. The old frame table had frames of
different heights inside a single state (`thinking` hard-cut between a
19-row full body and a 14-row head cameo) while the loop cursor-upped by a
single assumed height. Five rows of the previous robot were never
overwritten, and the next frame landed below them.

Three independent defences are in place here, and the code deliberately
does not rely on any one of them alone:

  1. MEASURED HEIGHT, NEVER ASSUMED. `_draw` counts the rows it is about to
     emit from the payload it actually holds (`payload.count("\\n") + 1`),
     stores that in `self._drawn_rows` at draw time, and cursor-ups by that
     exact number next tick. It never recomputes a height from a different
     frame and never trusts a predicted one.
  2. DRIFT IS ERASED, NOT ABSORBED. If a frame's real height ever differs
     from what is currently on screen, the old region is fully erased and
     the new one re-reserved before anything is drawn. So even if a future
     asset change broke `mascot_anim`'s fixed-canvas guarantee, the failure
     mode is a one-frame flicker rather than a stack of half robots.
  3. SPACE IS RESERVED UP FRONT. Before the first frame of a session, N
     newlines are printed and then cursor-upped by N. That forces any
     terminal scrolling to happen ONCE, deliberately, before any cursor-up
     arithmetic exists to be invalidated. This is the fix for the mascot
     rendering at the very bottom of the screen and getting sliced: without
     it, printing a tall frame near the bottom scrolls the region out from
     under the cursor and every subsequent cursor-up lands in the wrong
     place.

On top of that the terminal size is re-read every tick (a cheap syscall).
If it changed, the region is erased and re-planned rather than drawn into
stale geometry — and if the terminal is too short or too narrow for even
the smallest frame, the mascot degrades to the Tier 0 plain glyph line
instead of painting a giant broken sprite.

TIERED RENDERING
--------------------------------------------------------------------------
The CURRENT terminal's capability is probed fresh (never hardcoded) and the
best available tier is used:

    Tier 3 — real inline pixel images (Kitty / iTerm2-WezTerm protocols),
             via mascot_backend_image.
    Tier 2 — 24-bit truecolor Unicode sub-cell art (COLORTERM truecolor).
    Tier 1 — 256-color quantized sub-cell art (TERM has '256color').
    Tier 0 — a single plain, uncoloured status line (no escape codes, no
             animation) — the fallback for non-tty / NO_COLOR, for a tty
             with no detected colour/image support, and now also for a
             terminal too small to hold a frame.

Within Tiers 1-2 there is a second, orthogonal ladder — how many pixels are
packed into each character cell:

    sextant   2x3 subpixels/cell — finest, but the glyphs are Unicode 13
              and missing from Menlo/SF Mono, so it is used ONLY when the
              probe says the terminal draws them AND the user opted in via
              CYPHEX_MASCOT_SUBCELL.
    quadrant  2x2 subpixels/cell — the default. Twice the horizontal detail
              of half-blocks at effectively zero font risk.
    halfblock 1x2 subpixels/cell — universal fallback.

Colours for the text LABEL beside a frame are NOT reinvented — they are the
exact MONO ELECTRIC BLUE ramp from terminal_ui.py's HUD_THEME (imported
when available; mirrored, same convention as cx.py's plain-ANSI fallback
palette, if terminal_ui can't be imported for some reason).

Non-TTY / NO_COLOR / no-color-support-detected: every public call degrades
to at most one plain, uncoloured status line — no escape codes, no
animation, no cursor games — matching terminal_ui.py's own "no escape spam
on pipes/CI" rule. Every entry point is wrapped so a bug in here can never
crash the host CLI or leave the terminal in a dirty state (hidden cursor,
half-drawn frame). Pillow and every mascot_* sibling are imported
defensively, and `mascot_anim` is imported LAZILY — only once a real tty
render is about to happen — so `import mascot` stays cheap on pipes and in
CI, and can never fail the host CLI.
"""
import atexit
import os
import re
import shutil
import sys
import threading
import time

_ANSI_STRIP = re.compile(r"\033\[[0-9;?]*[A-Za-z]")

try:
    from terminal_ui import PHOS, PHOS_DIM, REF, CAUT, WARN_HOT, APEX, LABEL, _fg as _hex_fg
    _ANSI_RESET = "\033[0m"
except ImportError:
    # Mirror terminal_ui.py's MONO ELECTRIC BLUE ramp verbatim (same values as
    # terminal_ui.py:54-65 / HUD_THEME) so the mascot stays on-brand even when
    # terminal_ui/rich can't be imported. Same convention cx.py already uses
    # for its own plain-ANSI fallback palette — keep these hex values in sync
    # with terminal_ui.py by hand if that ramp ever changes.
    PHOS, PHOS_DIM, REF = "#3b82f6", "#1a4890", "#7dabff"
    CAUT, WARN_HOT, APEX, LABEL = "#2563c6", "#a9c9ff", "#d6e6ff", "#5f7391"

    def _hex_fg(hexcolor):
        r, g, b = (int(hexcolor[i:i + 2], 16) for i in (1, 3, 5))
        return f"\033[38;2;{r};{g};{b}m"

    _ANSI_RESET = "\033[0m"


# ═══════════════════════════════════════════════════════════════════════
#  Sizing
# ═══════════════════════════════════════════════════════════════════════
#
# DEFAULT_TARGET_COLS was 28. It is 20 now, and the drop is the point.
#
# The user asked for the mascot "small and clear, use more small pixels".
# Those pull in opposite directions on the half-block backend, which samples
# ONE pixel per column — shrinking it there just makes the blocks chunkier.
# The sub-cell backends break the tie: quadrant packs 2x2 subpixels per cell,
# so a 20-column quadrant render samples 40 pixels across, MORE horizontal
# detail than the old 28-column half-block render had, in 8 fewer columns.
#
# The QA sheets say the same thing (assets/qa/density_*.png, generated by
# mascot_backend_subcell). At 20 columns the half-block render is a fat blob
# whose "CYPHEX" screen wordmark is one unreadable bright bar with two
# notches — that is exactly the "bursted pixels" complaint. The quadrant
# render at the SAME 20 columns resolves the wordmark into separable
# letterforms, splits the bezel into a bright outline plus a deep-red inner
# shadow instead of one fat band, and draws the antenna as a thin stroke.
#
# 24 and 28 are legible too, but they are not better: at 28 the BOX
# downsample ratio drops far enough that less JPEG noise is averaged away and
# the torso — the weakest region of the source art, low-contrast plating that
# JPEG already destroyed — goes visibly mottled. Bigger is noisier here, not
# crisper.
#
# The vertical footprint is the other half of "small": mascot_anim's shared
# canvas is 15 rows at 24 columns, against 23 rows for the old idle at 28.
# The mascot still fits in a 24-row terminal, which is also what makes the
# scroll-safety reservation below cheap enough to always do.
#
# 24 rather than 20 is a deliberate art call: the source sprites are recovered
# from JPEG-compressed reference art, and the torso plating is the region that
# compression damaged worst. Extra columns do not repair it (verified across
# 18/20/22/24), but they do buy back the head, arms and legs reading as a whole
# robot rather than a head over speckle. Chosen by the author over the crisper
# head-only crops for exactly that reason.
#
# 16 is the floor — the full-body torso is an unreadable red blob there —
# so the shrink ladder stops at 16 and falls through to Tier 0 below that.
DEFAULT_TARGET_COLS = 24

#: Widths to try, largest first, when the requested one does not fit the
#: terminal. Only entries strictly smaller than the request are considered.
_COLS_LADDER = (28, 24, 20, 18, 16)

#: Never render a frame narrower than this — below it the art is mush and a
#: plain Tier 0 glyph line is the honest answer.
_MIN_TARGET_COLS = 16

#: Rows kept free below the frame so the mascot never sits flush against the
#: bottom of the window (where the next host `print` would scroll it away).
_VERTICAL_HEADROOM = 2

#: Columns reserved around the label line so it never wraps — a wrapped
#: label silently adds a row and is exactly the kind of height drift the
#: redraw loop must not see.
_LABEL_MARGIN = 4

#: Fallback frame rate. Real rates come from mascot_anim.FPS_HINT per state
#: (11-14fps); this is only used when that module is unavailable or when a
#: caller pins `Mascot(fps=...)` explicitly. The old flat 6fps was itself a
#: large part of why the animation read as choppy — at 6fps a 12-frame sine
#: breath takes two seconds and the eye resolves every single step.
FPS = 12

#: How long to wait before re-checking, when the terminal is currently too
#: small to render into. Slow on purpose: this is a "wait for the user to
#: resize" poll, not an animation tick.
_RETRY_INTERVAL = 0.5


def _c(text, color):
    """Wrap `text` in the exact truecolor escape for one of the imported
    HUD_THEME hex constants (or its mirror above). Never invents a colour."""
    return _hex_fg(color) + text + _ANSI_RESET


# ── Tier-0 plain-glyph fallback (kept exactly as before — already correct
#    and tested; two marks added for the two new mascot_anim states, which
#    the companion window can select via its state file) ─────────────────
_STATIC_MARK = {
    "idle": "·", "searching": "?", "thinking": "…",
    "working": "…", "uploading": "↑",
    "success": "✓", "error": "✗",
}


# ═══════════════════════════════════════════════════════════════════════
#  Optional siblings — every one of these failing to import just narrows
#  which tiers are reachable; none of them can break `import mascot`.
# ═══════════════════════════════════════════════════════════════════════
_ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "mascot")

try:
    from PIL import Image
except Exception:
    Image = None

try:
    import mascot_backend_image as _img_backend
except Exception:
    _img_backend = None

try:
    import mascot_backend_halfblock as _hb_backend
except Exception:
    _hb_backend = None

try:
    import mascot_backend_subcell as _sub_backend
except Exception:
    _sub_backend = None

try:
    import mascot_companion as _companion
except Exception:
    _companion = None


# ── mascot_anim is imported LAZILY ──────────────────────────────────────
# It pulls in numpy and builds real animation frames, which costs ~85ms. The
# host CLI imports this module unconditionally at startup, but the mascot
# only ever draws on an interactive tty — so the cost is deferred until a
# render is genuinely about to happen and is never paid on a pipe or in CI.
_ANIM = None
_ANIM_TRIED = False


def _anim():
    """The mascot_anim module, imported on first real use. None if it (or
    its dependencies) can't be loaded — the caller then degrades to Tier 0."""
    global _ANIM, _ANIM_TRIED
    if not _ANIM_TRIED:
        _ANIM_TRIED = True
        try:
            import mascot_anim as _m
            # Only accept it if it can actually produce frames.
            if _m.frames_for("idle", DEFAULT_TARGET_COLS):
                _ANIM = _m
        except Exception:
            _ANIM = None
    return _ANIM


# ═══════════════════════════════════════════════════════════════════════
#  Capability probing — the CURRENT terminal, fresh on every session.
# ═══════════════════════════════════════════════════════════════════════
def _term_size():
    """(columns, lines) of the current terminal. A cheap syscall, called
    every tick so a mid-animation resize is noticed rather than drawn over."""
    try:
        s = shutil.get_terminal_size(fallback=(80, 24))
        return max(1, int(s.columns)), max(1, int(s.lines))
    except Exception:
        return 80, 24


def _select_tier():
    """Best-to-worst capability probe:
        3 — mascot_backend_image, if kitty_available() or iterm_available()
        2 — sub-cell/half-block truecolor, if COLORTERM is truecolor/24bit
        1 — sub-cell/half-block 256-color, if TERM contains '256color'
        0 — plain static glyph (no colour/image support detected, or the
            animation frames / render backends are unavailable)
    Re-run at the start of each render session, matching _enabled()'s own
    re-check-every-call convention (not cached at import)."""
    if _anim() is None:
        return 0
    if _img_backend is not None:
        try:
            if _img_backend.kitty_available() or _img_backend.iterm_available():
                return 3
        except Exception:
            pass
    if _hb_backend is None and _sub_backend is None:
        return 0
    try:
        if os.environ.get("COLORTERM") in ("truecolor", "24bit"):
            return 2
        if "256color" in os.environ.get("TERM", ""):
            return 1
    except Exception:
        pass
    return 0


def _select_mode():
    """Pick the sub-cell density for a text-tier render.

    Delegates to mascot_backend_subcell.probe_glyph_support(), which does
    environment sniffing ONLY — no terminal I/O, so it cannot hang under a
    pipe, in CI, in tmux, or in an editor terminal.

    Sextant is deliberately double-gated. probe_glyph_support() already
    refuses to auto-recommend it (a wrong quadrant guess costs nothing; a
    wrong sextant guess turns the whole mascot into tofu boxes), so it only
    comes back when CYPHEX_MASCOT_SUBCELL asked for it — and we additionally
    require the probe's own `sextant` flag before honouring it.
    """
    if _sub_backend is None:
        return "halfblock"
    try:
        probe = _sub_backend.probe_glyph_support()
        mode = probe.get("recommended") or "quadrant"
        if mode == "sextant" and not probe.get("sextant"):
            mode = "quadrant"
        if mode == "quadrant" and not probe.get("quadrant"):
            mode = "halfblock"
        return mode if mode in ("halfblock", "quadrant", "sextant") else "halfblock"
    except Exception:
        return "halfblock"


class _Plan:
    """Everything decided once per render session: which tier, which glyph
    density, how wide, and the terminal geometry those answers were valid
    for. The loop re-plans whenever `term` stops matching reality."""

    __slots__ = ("tier", "kind", "mode", "cols", "rows", "truecolor",
                 "term", "size_req")

    def __init__(self, tier, kind, mode, cols, rows, truecolor, term, size_req):
        self.tier = tier
        self.kind = kind            # 'kitty' | 'iterm' | 'text'
        self.mode = mode            # 'halfblock' | 'quadrant' | 'sextant'
        self.cols = cols
        self.rows = rows            # PREDICTED frame height; never trusted
                                    # for cursor arithmetic — see _draw.
        self.truecolor = truecolor
        self.term = term            # (columns, lines) this plan assumes
        self.size_req = size_req    # what the caller originally asked for


def _plan(size, term, label_rows):
    """Decide how to draw, or return None to mean "fall back to Tier 0".

    Returns None when there is no capable tier, when mascot_anim is
    unavailable, or when the terminal is too short/narrow to hold even the
    smallest frame — that last case is the one that used to render a giant
    sliced sprite at the bottom of the screen.
    """
    tier = _select_tier()
    if tier == 0:
        return None
    anim = _anim()
    if anim is None:
        return None

    term_cols, term_lines = term

    # Tier 3 draws a real image, so it wants the square-pixel canvas; the
    # sub-cell grids are non-square by construction and would come out
    # squashed through an image protocol.
    mode = "halfblock" if tier == 3 else _select_mode()

    try:
        requested = max(1, int(size))
    except Exception:
        requested = DEFAULT_TARGET_COLS

    # Try the requested width, then progressively smaller ones. Only widths
    # strictly below the request are considered — a caller asking for a small
    # mascot never gets a bigger one back.
    candidates = [requested] + [c for c in _COLS_LADDER if c < requested]
    for cols in candidates:
        if cols < _MIN_TARGET_COLS:
            continue
        if cols + _LABEL_MARGIN > term_cols:
            continue
        try:
            rows = int(anim.canvas_rows(cols))
        except Exception:
            continue
        if rows + label_rows + _VERTICAL_HEADROOM > term_lines:
            continue

        kind = "text"
        if tier == 3 and _img_backend is not None:
            try:
                if _img_backend.kitty_available():
                    kind = "kitty"
                elif _img_backend.iterm_available():
                    kind = "iterm"
                else:
                    return None
            except Exception:
                return None
        elif mode == "halfblock" and _hb_backend is None and _sub_backend is None:
            return None

        return _Plan(tier, kind, mode, cols, rows, tier != 1, term, requested)

    # Nothing fits. Tier 0 is the correct answer, not a shrunken disaster.
    return None


# ═══════════════════════════════════════════════════════════════════════
#  ANSI region primitives — the whole redraw fix lives in these three.
# ═══════════════════════════════════════════════════════════════════════
def _seq_reserve(n):
    """Guarantee `n` rows exist at and below the cursor, WITHOUT moving it.

    Print n newlines — which scrolls the terminal if and only if it has to —
    then cursor-up n. Net effect: the cursor is back where it started
    (relative to the content it was on), and there are now definitely n rows
    of room below it.

    This is the scroll fix. Every cursor-up in this module is arithmetic
    against a fixed origin, and a scroll silently slides that origin upward.
    Forcing the scroll to happen ONCE, here, before any origin exists, is
    what makes the arithmetic valid for the rest of the session. Without it,
    starting an animation on the last line of the terminal means the first
    tall frame scrolls the screen and every subsequent frame draws in the
    wrong place — the mascot the user saw sliced off at the bottom.
    """
    if n <= 0:
        return ""
    return ("\n" * n) + f"\033[{n}A"


def _seq_clear_region(n):
    """Erase an n-row region and leave the cursor back at its top.

    Assumes the cursor is on the row immediately AFTER the region, which is
    exactly where a completed `_draw` leaves it.
    """
    if n <= 0:
        return ""
    return f"\033[{n}A\r" + ("\033[K\n" * n) + f"\033[{n}A"


def _kitty_delete_sequence():
    """The APC command that deletes/frees the mascot's image from a Kitty
    terminal's image table. Issued on erase (in addition to the normal
    cursor-up + line-clear dance) because Kitty image placements are an
    overlay independent of the text grid — clearing text alone does not
    reliably remove them."""
    if _img_backend is None:
        return ""
    try:
        cmd = (
            _img_backend.KITTY_APC_START
            + f"a=d,d=I,i={_img_backend.DEFAULT_KITTY_IMAGE_ID}".encode("ascii")
            + _img_backend.KITTY_APC_END
        )
        return cmd.decode("ascii", "replace")
    except Exception:
        return ""


class _MascotSession:
    """Context-manager returned by idle()/searching()/thinking(). On a clean
    exit it stops the mascot; on an exception it flips to the error strobe
    first (so a failure is visually distinct) and never swallows the error."""
    __slots__ = ("_m",)

    def __init__(self, mascot):
        self._m = mascot

    def __enter__(self):
        return self._m

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            try:
                self._m.error(str(exc) if exc else exc_type.__name__)
            except Exception:
                pass
        else:
            self._m.stop()
        return False


class _NoopSession:
    """Returned instead of _MascotSession if something inside the mascot
    itself misbehaves — `with mascot.searching(...):` must never break the
    caller just because the eye-candy did."""
    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


_NOOP = _NoopSession()


class Mascot:
    """One animated companion, redrawn in place on a background thread.
    Safe to start/stop repeatedly; always leaves the cursor visible and the
    terminal free of half-drawn frames on exit, including on exceptions."""

    def __init__(self, stream=None, fps=FPS, target_cols=DEFAULT_TARGET_COLS):
        self._stream = stream or sys.stdout
        # Per-state rates come from mascot_anim.FPS_HINT. An explicit,
        # non-default `fps=` pins every state to that rate instead.
        try:
            fps = int(fps)
        except Exception:
            fps = FPS
        self._fps_override = fps if fps != FPS else None
        self._interval = 1.0 / max(1, fps)
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._state = "idle"
        self._label = ""
        self._target_cols = target_cols
        self._active_kind = None
        # THE height invariant: how many rows are on screen RIGHT NOW,
        # written at draw time from the payload that was actually emitted.
        self._drawn_rows = 0
        self._region_open = False
        self._cursor_hidden = False
        atexit.register(self._atexit_cleanup)

    # ── availability ─────────────────────────────────────────────────────
    def _enabled(self):
        """Re-checked on every call (not cached) — matches terminal_ui.py's
        own _tty()/_cols(), which re-query fresh each render rather than
        trusting a value captured at import time (e.g. under pytest capsys,
        or if NO_COLOR is set/unset mid-run)."""
        try:
            if not self._stream.isatty():
                return False
        except Exception:
            return False
        if os.environ.get("NO_COLOR"):
            return False
        return True

    def _effective_tier(self):
        """0 whenever _enabled() is False (non-tty/NO_COLOR — the existing
        short-circuit, unchanged) OR whenever a real tty has no detected
        colour/image support at all; otherwise the best tier available."""
        if not self._enabled():
            return 0
        return _select_tier()

    def _plan_for(self, label, size, term=None):
        """Plan a render, or None to mean Tier 0. Honours the non-tty /
        NO_COLOR short-circuit before probing anything else."""
        if not self._enabled():
            return None
        try:
            return _plan(size, term or _term_size(), 1 if label else 0)
        except Exception:
            return None

    def _interval_for(self, state):
        """Seconds between frames for `state` — mascot_anim's per-state
        FPS_HINT (11-14fps; smoother states run faster), unless the caller
        pinned an explicit fps on this instance."""
        if self._fps_override:
            return 1.0 / max(1, self._fps_override)
        anim = _ANIM
        fps = FPS
        if anim is not None:
            try:
                fps = int(anim.FPS_HINT.get(state, FPS))
            except Exception:
                fps = FPS
        return 1.0 / max(1, fps)

    def _frames_for(self, state, plan):
        """The frame list for `state` on this plan's grid. Memoized inside
        mascot_anim per (state, cols, mode), so this is a dict hit after the
        first call and nothing is rebuilt on a render tick.

        The mode MUST match the backend that will draw them: handing a
        quadrant-grid frame to the half-block renderer halves its row count
        and re-introduces the exact height bug this module guards against."""
        anim = _anim()
        if anim is None:
            return ()
        try:
            return anim.frames_for(state, plan.cols, mode=plan.mode) or ()
        except Exception:
            return ()

    # ── low-level draw / erase ──────────────────────────────────────────
    def _write(self, s):
        try:
            self._stream.write(s)
            self._stream.flush()
        except Exception:
            pass

    def _label_suffix(self, label, term_cols):
        """Colour-wrapped label text for the line printed under a frame.
        Truncated to the terminal width (minus a small left margin) so a
        long label never wraps — a wrapped label is an extra row the redraw
        arithmetic never accounted for."""
        if not label:
            return ""
        # Some call sites (e.g. cx.py's plain-ANSI fallback messages) pass a
        # string that already carries its own colour codes — strip them so
        # they can't break out of the LABEL colour wrap below or throw off
        # the width math against a raw escape-code byte count.
        text = _ANSI_STRIP.sub("", label).replace("\n", " ").replace("\r", " ")
        if not text:
            return ""
        avail = max(term_cols - _LABEL_MARGIN, 0)
        if len(text) > avail:
            text = text[: max(avail - 1, 0)].rstrip() + "…"
        return ("  " + _c(text, LABEL)) if text else ""

    def _render_one(self, plan, img):
        """Render one PIL frame at this plan's tier/density. Returns
        (payload, frame_rows, kind), or (None, 0, None) if rendering failed
        for any reason — the caller treats that as a dropped tick (skip this
        redraw), never a crash.

        `frame_rows` for the text tiers is COUNTED FROM THE PAYLOAD, not
        predicted from the image or the plan. That is deliberate: it is the
        only number that is guaranteed to describe what is about to appear
        on screen."""
        try:
            if plan.kind == "kitty" and _img_backend is not None:
                payload = _img_backend.kitty_render_frame(img, plan.cols)
                rows = _img_backend.compute_rows(img, plan.cols)
                return payload.decode("ascii", "replace"), rows, "kitty"
            if plan.kind == "iterm" and _img_backend is not None:
                payload = _img_backend.iterm_render_frame(img, plan.cols)
                rows = _img_backend.compute_rows(img, plan.cols)
                return payload.decode("ascii", "replace"), rows, "iterm"

            if plan.mode != "halfblock" and _sub_backend is not None:
                text = _sub_backend.render_frame(
                    img, plan.cols, truecolor=plan.truecolor, mode=plan.mode
                )
            elif _hb_backend is not None:
                text = _hb_backend.render_frame(
                    img, plan.cols, truecolor=plan.truecolor
                )
            elif _sub_backend is not None:
                text = _sub_backend.render_frame(
                    img, plan.cols, truecolor=plan.truecolor, mode="halfblock"
                )
            else:
                return None, 0, None
            return text, text.count("\n") + 1, "text"
        except Exception:
            return None, 0, None

    def _draw(self, plan, payload, frame_rows, label, kind):
        """Draw one already-rendered frame in place.

        The height contract, in order:

        * `total` is the real height of what is about to be written —
          measured frame rows plus one row iff a label line will follow.
        * On the FIRST draw of a region, `_seq_reserve(total)` forces any
          terminal scroll to happen now, before an origin exists to be
          invalidated.
        * If `total` disagrees with what is currently on screen, the old
          region is ERASED IN FULL and re-reserved before drawing. With
          mascot_anim's fixed canvas this branch should never fire, and the
          code deliberately does not assume that: if it ever does fire, the
          result is one clean flicker instead of a stack of half robots.
        * Otherwise cursor-up by `self._drawn_rows` — the height that was
          actually drawn last time, never a recomputed or predicted one.
        * `self._drawn_rows` is then set to `total`, at draw time.
        """
        suffix = self._label_suffix(label, plan.term[0])
        # For the text tiers, count the rows off the payload HERE rather than
        # trusting the count that was passed in. `_draw` is the only place
        # that knows what is genuinely about to be written, so it is the only
        # honest place to measure — that is what makes "cursor-up by exactly
        # what was drawn" a property of the code rather than a convention two
        # functions have to keep agreeing on.
        lines = payload.split("\n") if kind == "text" else None
        frame_rows = len(lines) if lines is not None else max(1, int(frame_rows))
        total = frame_rows + (1 if suffix else 0)

        parts = []
        if not self._region_open:
            if not self._cursor_hidden:
                parts.append("\033[?25l")  # flicker-free redraw
                self._cursor_hidden = True
            parts.append("\r")
            parts.append(_seq_reserve(total))
            self._region_open = True
            self._drawn_rows = 0
        elif self._drawn_rows and total != self._drawn_rows:
            # Height drift. Erase everything that is there before drawing
            # anything new — never let two differently-sized frames coexist.
            if self._active_kind == "kitty":
                parts.append(_kitty_delete_sequence())
            parts.append(_seq_clear_region(self._drawn_rows))
            parts.append(_seq_reserve(total))
            self._drawn_rows = 0
        elif self._drawn_rows:
            parts.append(f"\033[{self._drawn_rows}A\r")
        else:
            parts.append("\r")

        if lines is not None:
            # Clear-to-end-of-line per row, so a shorter line can never leave
            # a tail of the previous frame behind it.
            for line in lines:
                parts.append(line)
                parts.append("\033[K\n")
        else:
            # Image protocols land the cursor on the row after the placement
            # themselves (per mascot_backend_image's contract).
            parts.append(payload)

        if suffix:
            parts.append(suffix)
            parts.append("\033[K\n")

        self._write("".join(parts))
        self._drawn_rows = total
        self._active_kind = kind

    def _erase_region(self):
        """Erase the drawn frame but stay in "animating" mode (cursor stays
        hidden). Used when re-planning mid-session — on a terminal resize, or
        when a state change would land on different geometry."""
        if self._drawn_rows:
            # Clamp to the CURRENT terminal height. If the terminal shrank
            # since we drew, the region no longer fits on screen: walking up
            # self._drawn_rows would clamp at the top, scroll blank rows in,
            # and strand sprite rows in scrollback we can no longer reach.
            rows = min(self._drawn_rows, max(1, _term_size()[1] - 1))
            out = ""
            if self._active_kind == "kitty":
                out += _kitty_delete_sequence()
            out += _seq_clear_region(rows)
            self._write(out)
        self._drawn_rows = 0
        self._region_open = False
        self._active_kind = None

    def _erase(self):
        """Full teardown: erase the frame AND restore the cursor."""
        self._erase_region()
        if self._cursor_hidden:
            self._write("\033[?25h")  # restore cursor only if we ever hid it
            self._cursor_hidden = False

    def _print_static(self, state, label):
        mark = _STATIC_MARK.get(state, "·")
        label = _ANSI_STRIP.sub("", label) if label else label
        msg = f"  {mark} {label}".rstrip() if label else f"  {mark}"
        try:
            print(msg, file=self._stream)
        except Exception:
            pass

    # ── the shared animation loop ────────────────────────────────────────
    def _animate(self, get_state, should_stop, sleep):
        """Drive the in-place animation until `should_stop()`.

        Shared by the background thread and by the companion window's
        standalone loop, so both get identical scroll-safety, height-drift
        and resize handling rather than two hand-rolled copies that can
        diverge.

        `get_state()` returns (state, label, size); `should_stop()` ends the
        loop; `sleep(seconds)` waits (and may return early on stop).
        """
        plan = None
        frames = ()
        frames_key = None
        tick = 0
        anim = _anim()
        one_shot = getattr(anim, "ONE_SHOT", frozenset()) if anim else frozenset()

        while not should_stop():
            state, label, size = get_state()
            term = _term_size()

            # Re-plan on a size request change or a terminal resize. A resize
            # invalidates the cursor arithmetic exactly the way a scroll does,
            # so erase the stale region rather than drawing into it.
            if plan is None or plan.size_req != size or plan.term != term:
                if plan is not None:
                    self._erase_region()
                plan = self._plan_for(label, size, term)
                frames_key = None

            if plan is None:
                # Too small / no capable tier right now. Hand the terminal
                # back completely — frame erased AND cursor restored, since
                # we may sit here indefinitely waiting for a resize — then
                # poll slowly. `_draw` re-hides the cursor if we resume.
                # Idempotent: writes nothing once already torn down.
                self._erase()
                sleep(_RETRY_INTERVAL)
                continue

            key = (state, plan.cols, plan.mode)
            if key != frames_key:
                frames = self._frames_for(state, plan)
                frames_key = key
                tick = 0
            if not frames:
                sleep(_RETRY_INTERVAL)
                continue

            if state in one_shot:
                # One-shot states hold on their last frame instead of
                # re-firing forever (only reachable via the companion
                # window's state file).
                idx = min(tick, len(frames) - 1)
            else:
                idx = tick % len(frames)

            payload, rows, kind = self._render_one(plan, frames[idx])
            if payload is not None:
                self._draw(plan, payload, rows, label, kind)
            tick += 1
            sleep(self._interval_for(state))

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self):
        """Idempotent — a no-op if already running (or if disabled / no
        capable tier detected)."""
        if self._effective_tier() == 0:
            return self
        try:
            with self._lock:
                if self._thread is not None and self._thread.is_alive():
                    return self
                self._stop_evt.clear()
                self._drawn_rows = 0
                self._region_open = False
                self._thread = threading.Thread(
                    target=self._render_loop, name="cyphex-mascot", daemon=True
                )
                self._thread.start()
        except Exception:
            pass
        return self

    def stop(self):
        """Idempotent — safe to call even if never started. Always leaves
        the cursor visible and erases any lines the mascot drew."""
        t = None
        try:
            with self._lock:
                t = self._thread
                self._thread = None
            if t is not None and t.is_alive():
                self._stop_evt.set()
                t.join(timeout=1.0)
        except Exception:
            pass
        finally:
            self._erase()

    def _atexit_cleanup(self):
        try:
            self.stop()
        except Exception:
            pass

    def _render_loop(self):
        def get_state():
            with self._lock:
                return self._state, self._label, self._target_cols

        try:
            self._animate(
                get_state,
                self._stop_evt.is_set,
                self._stop_evt.wait,
            )
        except Exception:
            pass

    def _flourish(self, state, label, cycles, size):
        """Blocking one-shot: stop any running session, play `state` in the
        CALLING thread, then erase. Guaranteed to be fully done (cursor
        restored) before it returns — the safe way to cue a beat right
        before something else (a subprocess, a Rich Live panel) takes over
        the terminal.

        mascot_anim's `success`/`error` are already authored as complete
        one-shot beats (a flash easing down, an alarm strobe with a closing
        dip), so they play exactly one pass; `cycles` still applies to the
        looping states used with flourish=True.
        """
        # Stop FIRST, unconditionally. success()/error() promise never to
        # leave a session running, and a background thread still redrawing
        # underneath a Tier 0 status line would interleave with it.
        self.stop()
        plan = self._plan_for(label, size)
        if plan is None:
            self._print_static(state, label)
            return self
        try:
            frames = self._frames_for(state, plan)
            if not frames:
                self._print_static(state, label)
                return self
            anim = _anim()
            one_shot = getattr(anim, "ONE_SHOT", frozenset()) if anim else frozenset()
            passes = 1 if state in one_shot else max(1, int(cycles))
            interval = self._interval_for(state)
            for i in range(len(frames) * passes):
                payload, rows, kind = self._render_one(plan, frames[i % len(frames)])
                if payload is None:
                    continue
                self._draw(plan, payload, rows, label, kind)
                time.sleep(interval)
        except Exception:
            pass
        finally:
            self._erase()
        return self

    def _enter(self, state, label, size):
        if self._effective_tier() == 0:
            self._print_static(state, label)
            return _NOOP
        try:
            with self._lock:
                self._state, self._label, self._target_cols = state, label, size
            self.start()
            return _MascotSession(self)
        except Exception:
            return _NOOP

    # ── public state transitions ────────────────────────────────────────
    def idle(self, *, size=DEFAULT_TARGET_COLS):
        """Resting / breathing. Usable as `with mascot.idle():`."""
        return self._enter("idle", "", size)

    def searching(self, label="", *, flourish=False, size=DEFAULT_TARGET_COLS):
        """Scan-pulse + periodic light-beam flash — "actively hunting".
        Usable as `with mascot.searching("scanning target..."):`, or pass
        flourish=True for a brief one-shot beat instead of a held state."""
        if flourish:
            return self._flourish("searching", label, 1, size)
        return self._enter("searching", label, size)

    def thinking(self, label="", *, flourish=False, size=DEFAULT_TARGET_COLS):
        """Load-pulse + periodic "..." head-cameo push-in — "processing".
        Same two forms as searching()."""
        if flourish:
            return self._flourish("thinking", label, 1, size)
        return self._enter("thinking", label, size)

    def success(self, msg="", *, size=DEFAULT_TARGET_COLS):
        """One-shot brightness flash + settle, then erases. Always
        blocking/brief — never leaves a session running."""
        return self._flourish("success", msg, 1, size)

    def error(self, msg="", *, size=DEFAULT_TARGET_COLS):
        """One-shot alert/error head-cameo strobe, then erases. Always
        blocking/brief."""
        return self._flourish("error", msg, 1, size)


# Module-level singleton + thin function wrappers, so callers just do
# `import mascot` and `mascot.searching("...")` / `with mascot.thinking(...):`
# — mirroring terminal_ui.py's module-level `soc` Console / `render_*` style.
_singleton = Mascot()


def idle(*, size=DEFAULT_TARGET_COLS):
    return _singleton.idle(size=size)


def searching(label="", *, flourish=False, size=DEFAULT_TARGET_COLS):
    return _singleton.searching(label, flourish=flourish, size=size)


def thinking(label="", *, flourish=False, size=DEFAULT_TARGET_COLS):
    return _singleton.thinking(label, flourish=flourish, size=size)


def success(msg="", *, size=DEFAULT_TARGET_COLS):
    return _singleton.success(msg, size=size)


def error(msg="", *, size=DEFAULT_TARGET_COLS):
    return _singleton.error(msg, size=size)


def stop():
    return _singleton.stop()


def open_companion_window(**kwargs):
    """Thin passthrough to mascot_companion.open_companion_window() — spawns
    a SEPARATE dedicated terminal window to host the mascot, for terminals
    that can't render it well integrated. EXPLICIT-CALL-ONLY: nothing in
    this module (or any existing CLI call site) invokes this automatically —
    it exists purely as an opt-in entry point for a caller (e.g. a CLI flag)
    that has already decided the integrated render isn't an option. See
    mascot_companion.py's own module docstring for the full contract. Never
    raises; returns False if unavailable/failed."""
    if _companion is None:
        return False
    try:
        return _companion.open_companion_window(**kwargs)
    except Exception:
        return False


def _hero_image(cols, mode):
    """hero.png, repaired and sized to `cols` on `mode`'s subpixel grid.

    Loaded from disk only when render_hero() is actually called, so it never
    adds startup cost for the CLI call sites (none of which use it). Routed
    through the same remaster pipeline as the animation frames, so the
    banner is palette-snapped pixel art rather than resampled JPEG mush.
    """
    path = os.path.join(_ASSET_DIR, "hero.png")
    if not os.path.exists(path):
        return None
    if _sub_backend is not None:
        try:
            return _sub_backend.prepare_source(path, cols, mode=mode)
        except Exception:
            pass
    if Image is None:
        return None
    try:
        img = Image.open(path)
        img.load()
        return img.convert("RGBA") if img.mode != "RGBA" else img
    except Exception:
        return None


def render_hero(size=64):
    """Render hero.png (the larger/cleaner banner art) at the current
    best-supported capability tier, for a caller with a natural
    big/banner-style spot (e.g. a CLI startup splash) to print directly.
    Optional — not used by any existing call site; hero.png is only loaded
    from disk the first time this is actually called.

    `size` is clamped to what the terminal can actually show, so an
    over-wide request produces a smaller banner rather than a wrapped, torn
    one. Returns the payload string to print, or "" if unavailable (no
    capability / non-tty / hero.png missing) — never raises."""
    try:
        if not _singleton._enabled():
            return ""
        tier = _select_tier()
        if tier == 0:
            return ""
        term_cols, _ = _term_size()
        cols = max(_MIN_TARGET_COLS, min(int(size), term_cols - 2))
        mode = "halfblock" if tier == 3 else _select_mode()

        kind = "text"
        if tier == 3 and _img_backend is not None:
            if _img_backend.kitty_available():
                kind = "kitty"
            elif _img_backend.iterm_available():
                kind = "iterm"

        img = _hero_image(cols, mode)
        if img is None:
            return ""
        plan = _Plan(tier, kind, mode, cols, 0, tier != 1, (term_cols, 24), cols)
        payload, _rows, _kind = _singleton._render_one(plan, img)
        return payload or ""
    except Exception:
        return ""


def render_and_print_state_loop(state_file_path, poll_interval=0.3):
    """Standalone render loop for the companion-window process
    (mascot_companion_loop.py, launched by mascot_companion.open_companion_
    window()): polls `state_file_path` for a single-word state name and
    redraws the matching animation in place.

    Runs the SAME `_animate` loop the integrated background thread uses, so
    the companion window gets identical tiering, scroll reservation,
    height-drift protection and resize handling — there is exactly one
    implementation of the redraw contract in this module, not two.

    Runs until interrupted (KeyboardInterrupt/SystemExit); the caller is
    responsible for hiding/showing the cursor around this call, matching
    every other entry point's cursor-safety convention (this function also
    guarantees its own frame lines are erased and its own cursor-hide is
    undone in its `finally`, so it's safe either way)."""
    m = Mascot()
    anim = _anim()
    known = set(getattr(anim, "STATE_ORDER", ())) if anim else set()

    def get_state():
        try:
            with open(state_file_path, "r") as f:
                state = f.readline().strip() or "idle"
        except Exception:
            state = "idle"
        if known and state not in known:
            state = "idle"
        return state, "", m._target_cols

    try:
        if m._effective_tier() == 0:
            # No capable tier: one plain line per poll, exactly as before.
            while True:
                m._print_static(get_state()[0], "")
                time.sleep(poll_interval)
        m._animate(get_state, lambda: False, time.sleep)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception:
        pass
    finally:
        try:
            m._erase()
        except Exception:
            pass


if __name__ == "__main__":
    # Manual smoke test: python3 mascot.py
    print("CYPHEX mascot — standalone demo (Ctrl+C to skip a beat)\n")
    with searching("scanning target..."):
        time.sleep(3.0)
    success("scan complete — 0 critical findings")
    time.sleep(0.4)
    with thinking("asking the model..."):
        time.sleep(3.0)
    error("model timed out")
    time.sleep(0.4)
    print("\ndone.")
