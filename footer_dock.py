"""
CYPHEX footer dock — the pinned bottom bar (status rail + input box + buddy).

    ...scan output scrolls up here, inside the scroll region...
        ▄     ╾╴ SYS NOMINAL ╶╌╴ THRT ▲00 ●00 ╶╌╴ DEFCON ▊5        ← rail
     ▛▀▀▀▀▀▀▜ ╭────────────────────────────────────────────────╮
    ▐▌ [o]  ▐ │ ⌖ cx ▸ 4/9  DYNAMIC VULNERABILITY SCAN  ·  42s │  ← box
     ▙▄▄▄▄▄▄▟ ╰────────────────────────────────────────────────╯

HOW IT STAYS PINNED
A DECSTBM scroll region covers every row except the bottom ROWS. Output
printed anywhere above — by this process, or by the scan child cx.py spawns
— scrolls inside the region and never touches the footer. The region is
terminal state, not process state, so the child inherits it for free; it
only has to repaint the buddy, which it learns it may do from the
CYPHEX_DOCK env var the owning process sets.

Every paint is ONE os.write wrapped in DECSC/DECRC (ESC 7 / ESC 8), so the
output cursor is exactly where it was afterwards. Writes from the animator
thread also take the bound Rich console's lock, because Rich flushes large
renders in several syscalls and a paint landing between two of them could
split an escape sequence.

THE BUDDY IS THE SPRITE ART, REDRAWN AT FOOTER SIZE
assets/mascot/expr_*.png is a TV head: antenna, left ear, thick red bezel,
and a face drawn ON the screen — "!", "x_x", ">_", "> <", "...", "CYPHEX".
Downsampling those pixels to 3 rows leaves mush, but the faces are text,
and terminal text stays crisp at any size. So the head is block glyphs and
the face is real characters: the same expressions, legible. The head is
the input box's height; the antenna rides in the rail row above it, so the
footer never grows past the box.

In WezTerm and iTerm2 (the iTerm2 inline-image protocol) the slot shows the
actual sprite PNG instead, animated at ~8 fps with frames synthesised from
the stills (EFFECT: flash, scanline sweep, glitch, pulse) — see ART /
art_frames() / image_protocol(). CYPHEX_BUDDY=glyph or =image forces either.

While a task runs, the rail row becomes a Claude-Code-style status line:
a spinner, a rotating "doing word" (VERBS) and the elapsed time.

THE SCAN HERO PINS ON TOP OF THE FOOTER, NOT AT THE SCREEN TOP
pin_header() stacks a block (the scan's hero panel) directly above the rail
for the rest of the run. Bottom-anchored on purpose: a scroll region whose
top margin is below row 1 makes the terminal DISCARD lines scrolled out of
it instead of moving them to scrollback (measured in WezTerm: 44 of 60 lines
lost), so a top-pinned header would eat the scan transcript.

Degradation: no TTY, a non-POSIX console, TERM=dumb, or a terminal smaller
than MIN_ROWS x MIN_COLS -> available() is False and every call is a no-op
returning False; callers keep today's inline behaviour.
"""
import atexit
import base64
import io
import os
import sys
import threading
import time

import ui_palette as P

ROWS = 4              # rail + the 3-row input box
BUDDY_W = 9           # ear + bezel + 6-cell screen + bezel
GUTTER = BUDDY_W + 2  # " " + buddy + " "  — the box starts at column GUTTER+1
MIN_ROWS = 14         # below this the region would leave too little to read
MIN_COLS = 48
MIN_OUTPUT = 12       # rows the transcript keeps when a header is pinned
TICK_S = 0.12         # animator cadence: sprite frames flip at ~8 fps
GLYPH_EVERY = 2       # glyph faces advance every 2nd tick (~4 fps reads better)
VERB_EVERY = 24       # spinner verb rotates every ~3 s
ENV = "CYPHEX_DOCK"

_ESC = "\033"
_SAVE, _RESTORE = _ESC + "7", _ESC + "8"
_HIDE, _SHOW = _ESC + "[?25l", _ESC + "[?25h"
_EL0 = _ESC + "[K"                      # erase cursor..end of line
_ED0 = _ESC + "[J"                      # erase cursor..end of screen
_RST = _ESC + "[0m"

# Four rows: antenna (in the rail row), bezel top, screen, bezel bottom.
# Every face is 6 cells — the screen's width, which is exactly "CYPHEX", the
# neutral face in the art. Only unambiguously narrow glyphs go on the screen
# (the chassis blocks are ambiguous-width, but the rest of the UI already
# depends on them being narrow), so the box never desynchronises.
_ANT, _TOP, _L, _R, _BOT = "    ▄    ", " ▛▀▀▀▀▀▀▜", "▌", "▐", " ▙▄▄▄▄▄▄▟"
_ANT_A, _TOP_A, _L_A, _R_A, _BOT_A = "    o    ", " +------+", "|", "|", " +------+"
_EAR, _EAR_A = "▐", "|"
_BADGE, _BADGE_A = "✓", "v"           # success: the check bubble in success.png
_BADGE_COL = 6

#: One entry per expression in assets/mascot; frames cycle on the animator.
FACES = {
    "neutral":  ["CYPHEX"],
    "focused":  [" >_   ", " >    "],
    "scanning": [" [o]  ", "  [o] "],
    "thinking": [" .    ", " ..   ", " ...  "],
    "hacking":  [" > <  ", " >_<  "],
    "loading":  [" ━    ", " ━━   ", " ━━━  ", " ━━━━ "],
    "alert":    ["  !   "],
    "success":  ["CYPHEX"],
    "error":    [" x_x  "],
}
FACES_ASCII = dict(FACES, loading=[" =    ", " ==   ", " ===  ", " ==== "])
#: The mascot.py / trace vocabulary, mapped onto the art's expressions.
ALIASES = {"idle": "neutral", "searching": "scanning",
           "working": "hacking", "uploading": "loading"}


def expression(state):
    state = ALIASES.get(state, state)
    return state if state in FACES else "neutral"


# ── real sprite art (inline-image terminals) ─────────────────────────────
# WezTerm and iTerm2 can draw a PNG into a block of cells (the iTerm2 inline
# image protocol), so there the buddy slot shows the actual sprite instead of
# the glyph redraw. (file, crop height or None): the loop_* and success
# sprites are full bodies — the crop keeps the head (and success's check
# bubble), measured on the source art.
_ART_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "mascot")
ART = {
    "neutral":  ("expr_neutral", None),
    "focused":  ("expr_focused", None),
    "scanning": ("loop_scanning", 104),
    "thinking": ("expr_thinking", None),
    "hacking":  ("expr_hacking", None),
    "loading":  ("loop_loading", 104),
    "alert":    ("expr_alert", None),
    "success":  ("success", 100),
    "error":    ("expr_error", None),
}
_frame_cache = {}

# Stills only ship one pose each, so motion is synthesised from them: a
# flash for alert/error, a scanline sweeping the screen for scanning/loading/
# focused, slice glitches for hacking, a slow pulse for thinking. neutral
# and success stay still — an idle footer should not churn the terminal.
EFFECT = {"alert": "flash", "error": "flash", "scanning": "sweep",
          "loading": "sweep", "focused": "sweep", "hacking": "glitch",
          "thinking": "pulse"}


def image_protocol() -> bool:
    """True where the iTerm2 inline-image protocol will render. Env-only
    detection (no terminal query). tmux swallows the OSC without passthrough,
    so it is excluded; CYPHEX_BUDDY=glyph|image overrides either way."""
    forced = os.environ.get("CYPHEX_BUDDY", "").lower()
    if forced in ("glyph", "image"):
        return forced == "image"
    if os.environ.get("TMUX"):
        return False
    return (os.environ.get("TERM_PROGRAM") in ("WezTerm", "iTerm.app")
            or "WEZTERM_EXECUTABLE" in os.environ or "WEZTERM_PANE" in os.environ)


def _load_still(expr):
    from PIL import Image
    name, crop_h = ART[expr]
    img = Image.open(os.path.join(_ART_DIR, name + ".png")).convert("RGBA")
    if crop_h:
        img = img.crop((0, 0, img.width, crop_h))
    box = img.getbbox()
    return img.crop(box) if box else img


def _screen_mask(img):
    """Where a scanline may glow: the screen, which in the art is the
    transparent hole the bezel encloses. Flood the transparent area from the
    image border; transparent pixels the flood cannot reach are the screen.
    Bezel, chassis and the red face are opaque, so they are never lit."""
    from PIL import Image
    w, h = img.size
    alpha = img.getchannel("A").load()
    clear = lambda x, y: alpha[x, y] <= 128
    outside = set()
    stack = [(x, y) for x in range(w) for y in (0, h - 1)] + \
            [(x, y) for y in range(h) for x in (0, w - 1)]
    while stack:
        x, y = stack.pop()
        if (x, y) in outside or not (0 <= x < w and 0 <= y < h) or not clear(x, y):
            continue
        outside.add((x, y))
        stack += ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1))
    mask = Image.new("L", img.size, 0)
    m = mask.load()
    for y in range(h):
        for x in range(w):
            if clear(x, y) and (x, y) not in outside:
                m[x, y] = 255
    return mask


def _effect_frames(img, effect):
    from PIL import Image, ImageChops, ImageEnhance
    alpha = img.getchannel("A")

    def bright(k):
        out = ImageEnhance.Brightness(img).enhance(k)
        out.putalpha(alpha)
        return out

    if effect == "flash":
        # 2 Hz at TICK_S: fast full-brightness flashing strains the eyes
        # (WCAG 2.3.1 draws the line at 3 flashes a second).
        return [img, img, bright(1.9), bright(1.9)]
    if effect == "pulse":
        return [img, bright(0.8), bright(0.6), bright(0.8)]
    if effect == "sweep":
        mask = _screen_mask(img)
        box = mask.getbbox() or (0, 0, img.width, img.height)
        band = max((box[3] - box[1]) // 6, 2)
        frames = []
        for i in range(8):
            y = box[1] + ((box[3] - box[1] - band) * i) // 7
            rows = Image.new("L", img.size, 0)
            rows.paste(255, (0, y, img.width, y + band))
            glow = Image.new("RGBA", img.size, (*P.rgb(P.REF), 0))
            glow.putalpha(ImageChops.multiply(mask, rows).point(lambda v: v * 100 // 255))
            frames.append(Image.alpha_composite(img, glow))
        return frames
    if effect == "glitch":
        frames = [img]
        slice_h = max(img.height // 10, 1)
        for shifts in ((3, -2, 0, 4, -3), (-4, 0, 3, -2, 2)):
            f = img.copy()
            for n, dx in enumerate(shifts):
                y = (2 * n + 1) * slice_h
                if y + slice_h > img.height:
                    break
                strip = img.crop((0, y, img.width, y + slice_h))
                f.paste((0, 0, 0, 0), (0, y, img.width, y + slice_h))
                f.paste(strip, (dx, y))
            frames += [f, img]
        return frames
    return [img]


def art_frames(expr):
    """The sprite for an expression as a list of PNG frames (the still
    first), cropped to the head; [] if Pillow or the asset is missing."""
    if expr in _frame_cache:
        return _frame_cache[expr]
    frames = []
    try:
        img = _load_still(expr)
        from PIL import Image
        for f in _effect_frames(img, EFFECT.get(expr)):
            buf = io.BytesIO()
            # 64-colour palette: pixel art survives it, and it cuts each
            # frame ~4x — at ~8 fps that is the difference between a few
            # dozen KB/s of terminal traffic and a few hundred.
            f.quantize(64, method=Image.Quantize.FASTOCTREE).save(buf, format="PNG", optimize=True)
            frames.append(buf.getvalue())
    except Exception:
        frames = []
    _frame_cache[expr] = frames
    return frames


def _image_seq(png):
    """OSC 1337 inline image filling the BUDDY_W x ROWS buddy slot.
    doNotMoveCursor: the slot's last row is the screen's last row, and a
    cursor advanced past it would scroll the whole screen."""
    args = (f"inline=1;width={BUDDY_W};height={ROWS};preserveAspectRatio=1;"
            f"doNotMoveCursor=1;size={len(png)}")
    return f"{_ESC}]1337;File={args}:{base64.b64encode(png).decode()}\a"


_lock = threading.RLock()
_st = {
    "active": False, "owner": False, "size": None,
    "state": "neutral", "frame": 0, "rail": "",
    "task": None, "detail": "", "started": 0.0, "caret": "idle",
    "drawn": None,      # expression currently shown as an image, if any
    "head": None,       # pin_header's render(cols, max_rows) callable
    "head_rows": [],    # the pinned block's ANSI lines, as painted
    "verb0": 0,         # where the spinner's verb rotation starts this task
}
_console_lock = None
_anim_stop = None
_anim_thread = None


# ── capability ───────────────────────────────────────────────────────────
def _size():
    try:
        s = os.get_terminal_size(sys.stdout.fileno())
        return s.lines, s.columns
    except (OSError, ValueError, AttributeError):
        return None


def _dims():
    """(rows, cols) — last synced size, live size, or a safe default, so a
    paint can never raise because the tty stopped answering TIOCGWINSZ."""
    return _st["size"] or _size() or (24, 80)


def available() -> bool:
    if os.name != "posix" or os.environ.get("TERM", "") in ("", "dumb"):
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    size = _size()
    return bool(size) and size[0] >= MIN_ROWS and size[1] >= MIN_COLS


def active() -> bool:
    return _st["active"]


def _ascii():
    try:
        import terminal_ui
        return bool(terminal_ui._ascii_mode())
    except Exception:
        return not (sys.stdout.encoding or "").lower().startswith("utf")


def _raw(s):
    """Write straight to the tty fd — bypasses Python's buffer so a paint is
    never reordered behind, or split across, buffered output."""
    data = s.encode("utf-8", "replace")
    try:
        fd = sys.stdout.fileno()
        while data:
            n = os.write(fd, data)
            data = data[n:]
    except (OSError, ValueError):
        pass


def _write(s):
    """One syscall, cursor saved/restored around it, under the Rich lock."""
    lock = _console_lock
    if lock is not None:
        lock.acquire()
    try:
        _raw(_SAVE + _HIDE + s + _RESTORE + _SHOW)
    finally:
        if lock is not None:
            lock.release()


def _cup(row, col=1):
    return f"{_ESC}[{row};{col}H"


# ── region ───────────────────────────────────────────────────────────────
def _region_bottom(rows):
    """Last row the transcript scrolls in: above the footer and any header."""
    return rows - ROWS - len(_st["head_rows"])


def _region_seq(rows):
    # DECSTBM homes the cursor; callers wrap it in DECSC/DECRC.
    return f"{_ESC}[1;{_region_bottom(rows)}r"


def _render_head(render, cols, max_rows):
    """render's lines if they fit in max_rows, else [] — never raises."""
    if max_rows < 1:
        return []
    try:
        lines = list(render(cols, max_rows) or [])
    except Exception:
        return []
    return lines if len(lines) <= max_rows else []


def _sync_region(save=True):
    """Re-issue the scroll region if the terminal was resized. save=False is
    for use while the input editor owns the cursor: it repositions itself
    absolutely afterwards, and DECSC there would clobber the saved output
    position the REPL is holding across the read."""
    size = _size()
    if not size or size == _st["size"]:
        return False
    _st["size"] = size
    seq = _refit_head(size) + _region_seq(size[0])
    if save:
        _write(seq)
    else:
        _raw(seq)
    return True


def _refit_head(size):
    """Re-render a pinned header for a resized terminal at the SAME height
    (a taller one would land on top of the output cursor); if it no longer
    fits, drop it. Returns the erase sequence for rows it gave back."""
    old = _st["head_rows"]
    if not old:
        return ""
    lines = _render_head(_st["head"], size[1], len(old))
    if len(lines) == len(old):
        _st["head_rows"] = lines
        return ""
    return _unpin(size[0])


def reserve(rail_ansi=""):
    """Claim the bottom ROWS for the footer. Owner process only."""
    with _lock:
        if _st["active"]:
            return True
        if not available():
            return False
        # Scroll existing content up so the footer rows are free, then park
        # the cursor back where the output left off.
        _raw("\n" * ROWS + f"{_ESC}[{ROWS}A")
        _st.update(active=True, owner=True, size=None, rail=rail_ansi)
        _sync_region()
        os.environ[ENV] = "1"
        _paint_all()
        return True


def adopt(console=None, standalone=True):
    """Child side: paint into a footer the parent reserved, or (standalone)
    reserve one ourselves when there is no parent REPL. Returns True when a
    dock is live."""
    global _console_lock
    if console is not None:
        _console_lock = getattr(console, "_lock", None)
    with _lock:
        if _st["active"]:
            return True
        if not available():
            return False
        if os.environ.get(ENV) == "1":
            _st.update(active=True, owner=False, size=None)
            _sync_region()
            return True
    if not standalone:
        return False
    try:
        import terminal_ui
        rail = terminal_ui.rail_ansi({}, _size()[1] - GUTTER)
    except Exception:
        rail = ""
    return reserve(rail)


def release():
    """Give the rows back (owner) or just stop animating (adopter)."""
    stop_task()
    with _lock:
        if not _st["active"]:
            return
        rows = _dims()[0]
        if _st["owner"]:
            first = _region_bottom(rows) + 1
            clear = "".join(_cup(r) + _EL0 for r in range(first, rows + 1))
            _write(f"{_ESC}[r" + clear)
            os.environ.pop(ENV, None)
        elif _st["head_rows"]:
            # A scan child hands the parent's footer back as it found it.
            _write(_unpin(rows))
        _st.update(active=False, owner=False, size=None, head=None, head_rows=[])


atexit.register(release)


# ── pinned header (scan hero) ────────────────────────────────────────────
def pin_header(render, console=None):
    """Pin render's block directly above the rail until release(). render is
    called as render(cols, max_rows) -> ANSI lines at most cols wide, or []
    when nothing fits; it is re-called at the same height on resize. Returns
    False — the caller prints inline — when no dock is live or the terminal
    is too short to keep MIN_OUTPUT transcript rows."""
    if not _st["active"] and not adopt(console):
        return False
    with _lock:
        if _st["head_rows"]:
            return False                # one header per run
        rows, cols = _dims()
        lines = _render_head(render, cols, rows - ROWS - MIN_OUTPUT)
        if not lines:
            return False
        h = len(lines)
        lock = _console_lock
        if lock is not None:
            lock.acquire()
        try:
            try:
                sys.stdout.flush()
            except (OSError, ValueError):
                pass
            # Free h rows at the region's bottom the way reserve() frees the
            # footer's: LFs from the output cursor scroll (into scrollback,
            # the region still starts at row 1) only as far as needed, and
            # CUU puts the cursor back on the same line of text.
            _raw("\n" * h + f"{_ESC}[{h}A")
            _st.update(head=render, head_rows=lines)
            _write(_region_seq(rows) + _paint_head())
        finally:
            if lock is not None:
                lock.release()
    return True


def _unpin(rows):
    """Drop the header (caller holds _lock); returns the sequence that
    erases its rows and gives them back to the scroll region."""
    first = _region_bottom(rows) + 1
    clear = "".join(_cup(r) + _EL0 for r in range(first, rows - ROWS + 1))
    _st.update(head=None, head_rows=[])
    return clear + _region_seq(rows)


def _paint_head():
    rows = _dims()[0]
    top = _region_bottom(rows) + 1
    return "".join(_cup(top + i) + _EL0 + line + _RST
                   for i, line in enumerate(_st["head_rows"]))


# ── painting ─────────────────────────────────────────────────────────────
def buddy_rows(state="neutral", frame=0, ascii_mode=False):
    """The buddy as 4 ANSI rows (antenna, bezel, screen, bezel), each exactly
    BUDDY_W cells."""
    state = expression(state)
    faces = (FACES_ASCII if ascii_mode else FACES)[state]
    face = faces[frame % len(faces)]
    ant, top, lw, rw, bot = ((_ANT_A, _TOP_A, _L_A, _R_A, _BOT_A) if ascii_mode
                             else (_ANT, _TOP, _L, _R, _BOT))
    bezel, screen = P.fg(P.PHOS), P.fg(P.WARN)
    antenna = bezel + ant + _RST
    if state == "success":
        badge = _BADGE_A if ascii_mode else _BADGE
        antenna = (bezel + ant[:_BADGE_COL] + P.fg(P.OK) + badge
                   + bezel + ant[_BADGE_COL + 1:] + _RST)
    return [antenna,
            bezel + top + _RST,
            P.fg(P.CHASSIS) + (_EAR_A if ascii_mode else _EAR)
            + bezel + lw + screen + face + bezel + rw + _RST,
            bezel + bot + _RST]


def _paint_buddy(force=False):
    top = _dims()[0] - ROWS + 1          # antenna shares the rail row
    expr = expression(_st["state"])
    frames = art_frames(expr) if image_protocol() and not _ascii() else []
    if frames:
        # Resend only when the shown frame changes (or a full repaint wiped
        # it): a still expression costs nothing per tick, an animated one
        # flips a frame every tick.
        key = (expr, _st["frame"] % len(frames))
        if not force and _st["drawn"] == key:
            return ""
        _st["drawn"] = key
        blank = "".join(_cup(top + i) + " " * GUTTER for i in range(ROWS))
        return blank + _cup(top, 2) + _image_seq(frames[key[1]])
    _st["drawn"] = None
    art = buddy_rows(_st["state"], _st["frame"] // GLYPH_EVERY, _ascii())
    # The whole gutter, spaces included: they wipe whatever a resize reflowed there.
    return "".join(_cup(top + i) + " " + r + " " for i, r in enumerate(art))


def _paint_rail():
    # No rail of our own (a scan child adopting the parent's footer) means
    # leave the row alone: erasing it would wipe the parent's rail.
    if not _st["rail"]:
        return ""
    # Starts after the gutter: the buddy's antenna occupies the left of it.
    return _cup(_dims()[0] - ROWS + 1, GUTTER + 1) + _EL0 + _st["rail"]


#: Claude-Code-style "doing words" for the line above the box while a task
#: runs; one rotates in every VERB_EVERY ticks.
VERBS = ("Fingerprinting", "Triangulating", "Decompiling", "Fuzzing",
         "Taint-tracing", "Sandboxing", "Hashing", "Deobfuscating",
         "Correlating", "Cross-referencing", "Enumerating", "Hardening",
         "Patching", "Calibrating sensors", "Reticulating splines",
         "Discombobulating", "Defragmenting", "Quantum-tunnelling",
         "Interrogating packets", "Spelunking the AST")
SPIN = "·✢✳✶✻✽✻✶✳✢"
SPIN_ASCII = "-\\|/"


def _paint_status():
    """The rail row while a task runs: ✻ Verb… (12s · ctrl+c to stop)."""
    rows, cols = _dims()
    ascii_mode = _ascii()
    spin = SPIN_ASCII if ascii_mode else SPIN
    frame = _st["frame"]
    verb = VERBS[(_st["verb0"] + frame // VERB_EVERY) % len(VERBS)]
    started = _st["started"]
    meta = f"  ({time.time() - started:.0f}s · ctrl+c to stop)" if started else ""
    room = cols - GUTTER - 1
    head = f"{spin[frame % len(spin)]} "
    text = (verb + ("..." if ascii_mode else "…"))[:max(room - len(head), 0)]
    meta = meta[:max(room - len(head) - len(text), 0)]
    return (_cup(rows - ROWS + 1, GUTTER + 1) + _EL0 + P.fg(P.REF) + head
            + P.fg(P.READOUT) + text + P.fg(P.LABEL) + meta + _RST)


def _box_parts():
    try:
        import terminal_ui
        g = terminal_ui.deck_box_glyphs()
        segs = terminal_ui.deck_prompt_segments({"caret": _st["caret"]})
    except Exception:
        g = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"}
        segs = [("| ", P.PHOS_DIM), ("cx ", P.READOUT), ("> ", P.PHOS_DIM)]
    return g, segs


def _paint_task():
    """The box in running mode: prompt caret + what the pipeline is doing."""
    rows, cols = _dims()
    width = cols - GUTTER
    g, segs = _box_parts()
    label = _st["task"]
    if _st["detail"]:
        label = f"{label}  ·  {_st['detail']}"
    prompt = "".join(t for t, _ in segs)
    room = max(width - len(prompt) - 2, 1)
    text = label[:room]                 # elapsed lives on the status line
    wall = P.fg(P.PHOS_DIM)
    row = ("".join(P.fg(c) + t for t, c in segs) + P.fg(P.READOUT) + text + _RST
           + " " * (room - len(text)) + " " + wall + g["v"] + _RST)
    top = rows - ROWS + 2
    col = GUTTER + 1
    return (_cup(top, col) + _EL0 + wall + g["tl"] + g["h"] * (width - 2) + g["tr"] + _RST
            + _cup(top + 1, col) + _EL0 + row
            + _cup(top + 2, col) + _EL0 + wall + g["bl"] + g["h"] * (width - 2) + g["br"] + _RST)


def _paint_running():
    return _paint_task() + _paint_status() if _st["task"] else ""


def _paint_all(lead=""):
    rail = _paint_status() if _st["task"] else _paint_rail()
    _write(lead + _paint_head() + rail + _paint_buddy(force=True)
           + (_paint_task() if _st["task"] else ""))


def repaint(rail_ansi=None):
    with _lock:
        if not _st["active"]:
            return False
        if rail_ansi is not None:
            _st["rail"] = rail_ansi
        _sync_region()
        _paint_all()
        return True


def set_state(state, label=None):
    """Point the buddy at a pipeline state. False when no dock is live, so
    callers (mascot.py) know to fall back to their inline rendering."""
    if not _st["active"] and not adopt(standalone=False):
        return False
    with _lock:
        _st["state"] = expression(state)
        # A caller's label is detail UNDER the running task (e.g. which agent
        # is probing), not a replacement for it; repeats of the task are noise.
        if label and _st["task"] is not None and str(label) not in _st["task"]:
            _st["detail"] = str(label)
        _write(_paint_buddy() + _paint_running())
    return True


# ── input hand-off (REPL) ────────────────────────────────────────────────
def begin_input(rail_ansi=None):
    """Paint the idle footer and save the output cursor. Returns the anchor
    callable deck_input's editor positions the box with, or None."""
    stop_task()     # outside _lock: it joins the animator, which needs _lock
    with _lock:
        if not _st["active"]:
            return None
        _st.update(state="neutral", frame=0, task=None, caret="idle")
        if rail_ansi is not None:
            _st["rail"] = rail_ansi
        # Always re-issue the region, and erase below the output cursor (in
        # normal flow those rows are blank): a scan child killed mid-run
        # leaves its smaller region and its pinned header behind. ED0 runs
        # first — DECSTBM homes the cursor — and the footer repaints after.
        _st["size"] = _size() or _st["size"]
        _paint_all(lead=_ED0 + _region_seq(_dims()[0]))
        _raw(_SAVE)
    return box_anchor


def box_anchor():
    """(top_row, left_col0, width, menu_bottom) for the input box; the popup
    menu may use rows up to menu_bottom — the scroll region's last row, just
    above the rail. Resize-safe: re-issues the region without touching the
    saved output cursor."""
    if _sync_region(save=False):
        _raw(_paint_rail() + _paint_buddy(force=True))
    rows, cols = _dims()
    return rows - ROWS + 2, GUTTER, cols - GUTTER, _region_bottom(rows)


def end_input():
    if _st["active"]:
        _raw(_RESTORE)


# ── running task (scan child) ────────────────────────────────────────────
def start_task(label, state="working", animate=True, caret="executing"):
    """Show `label` in the box while work runs; optionally animate the buddy
    and tick the elapsed clock on a daemon thread."""
    global _anim_stop, _anim_thread
    if not _st["active"] and not adopt(standalone=False):
        return False
    with _lock:
        if _st["task"] is None:
            _st["verb0"] = int(time.time()) % len(VERBS)
        _st.update(task=str(label), detail="", caret=caret,
                   state=expression(state))
        if not _st["started"]:
            _st["started"] = time.time()
        _paint_all()
        if animate and _anim_thread is None:
            _anim_stop = threading.Event()
            _anim_thread = threading.Thread(target=_animate, args=(_anim_stop,),
                                            name="cyphex-dock", daemon=True)
            _anim_thread.start()
    return True


def _animate(stop):
    while not stop.wait(TICK_S):
        with _lock:
            if not _st["active"]:
                return
            _st["frame"] += 1
            if _sync_region():
                # Resized: everything moved. Blank the rail row first — an
                # adopting child has no rail of its own to repaint, and the
                # reflowed leftovers there are worse than an empty row until
                # the REPL repaints its rail at the next prompt.
                _paint_all(lead=_cup(_dims()[0] - ROWS + 1, GUTTER + 1) + _EL0)
            else:
                _write(_paint_running() + _paint_buddy())


def stop_task():
    global _anim_stop, _anim_thread
    if _anim_stop is not None:
        _anim_stop.set()
    t = _anim_thread
    _anim_stop = _anim_thread = None
    if t is not None and t is not threading.current_thread():
        t.join(timeout=1.0)
    with _lock:
        was_running = _st["task"] is not None
        _st.update(task=None, detail="", started=0.0)
        if was_running and _st["active"]:
            # Hand the rail row back: our rail, or blank for the REPL's.
            _write(_cup(_dims()[0] - ROWS + 1, GUTTER + 1) + _EL0 + _paint_rail())
