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
actual sprite PNG instead — see ART / image_protocol(). CYPHEX_BUDDY=glyph
or =image forces either.

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
TICK_S = 0.25         # animator cadence; the elapsed clock updates each tick
ENV = "CYPHEX_DOCK"

_ESC = "\033"
_SAVE, _RESTORE = _ESC + "7", _ESC + "8"
_HIDE, _SHOW = _ESC + "[?25l", _ESC + "[?25h"
_EL0 = _ESC + "[K"                      # erase cursor..end of line
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
_png_cache = {}


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


def art_png(expr):
    """PNG bytes of the sprite for an expression, cropped to the head and
    trimmed to its opaque bounds; None if Pillow or the asset is missing."""
    if expr in _png_cache:
        return _png_cache[expr]
    data = None
    try:
        from PIL import Image
        name, crop_h = ART[expr]
        img = Image.open(os.path.join(_ART_DIR, name + ".png")).convert("RGBA")
        if crop_h:
            img = img.crop((0, 0, img.width, crop_h))
        box = img.getbbox()
        if box:
            img = img.crop(box)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        data = buf.getvalue()
    except Exception:
        data = None
    _png_cache[expr] = data
    return data


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
def _region_seq(rows):
    # DECSTBM homes the cursor; callers wrap it in DECSC/DECRC.
    return f"{_ESC}[1;{rows - ROWS}r"


def _sync_region(save=True):
    """Re-issue the scroll region if the terminal was resized. save=False is
    for use while the input editor owns the cursor: it repositions itself
    absolutely afterwards, and DECSC there would clobber the saved output
    position the REPL is holding across the read."""
    size = _size()
    if not size or size == _st["size"]:
        return False
    _st["size"] = size
    if save:
        _write(_region_seq(size[0]))
    else:
        _raw(_region_seq(size[0]))
    return True


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
        if _st["owner"]:
            rows = (_dims() or (24, 80))[0]
            clear = "".join(_cup(r) + _EL0 for r in range(rows - ROWS + 1, rows + 1))
            _write(f"{_ESC}[r" + clear)
            os.environ.pop(ENV, None)
        _st.update(active=False, owner=False, size=None)


atexit.register(release)


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
    png = art_png(expr) if image_protocol() and not _ascii() else None
    if png:
        # A still image per expression: resend only when the face changes
        # (or a full repaint wiped it), never on the animator's tick.
        if not force and _st["drawn"] == expr:
            return ""
        _st["drawn"] = expr
        blank = "".join(_cup(top + i, 2) + " " * BUDDY_W for i in range(ROWS))
        return blank + _cup(top, 2) + _image_seq(png)
    _st["drawn"] = None
    art = buddy_rows(_st["state"], _st["frame"], _ascii())
    return "".join(_cup(top + i, 2) + r for i, r in enumerate(art))


def _paint_rail():
    # No rail of our own (a scan child adopting the parent's footer) means
    # leave the row alone: erasing it would wipe the parent's rail.
    if not _st["rail"]:
        return ""
    # Starts after the gutter: the buddy's antenna occupies the left of it.
    return _cup(_dims()[0] - ROWS + 1, GUTTER + 1) + _EL0 + _st["rail"]


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
    label, started = _st["task"], _st["started"]
    if _st["detail"]:
        label = f"{label}  ·  {_st['detail']}"
    tail = f"  ·  {time.time() - started:.0f}s" if started else ""
    prompt = "".join(t for t, _ in segs)
    room = max(width - len(prompt) - 2, 1)
    text = (label + tail)[:room]
    wall = P.fg(P.PHOS_DIM)
    row = ("".join(P.fg(c) + t for t, c in segs) + P.fg(P.READOUT) + text + _RST
           + " " * (room - len(text)) + " " + wall + g["v"] + _RST)
    top = rows - ROWS + 2
    col = GUTTER + 1
    return (_cup(top, col) + _EL0 + wall + g["tl"] + g["h"] * (width - 2) + g["tr"] + _RST
            + _cup(top + 1, col) + _EL0 + row
            + _cup(top + 2, col) + _EL0 + wall + g["bl"] + g["h"] * (width - 2) + g["br"] + _RST)


def _paint_all():
    out = _paint_rail() + _paint_buddy(force=True)
    if _st["task"]:
        out += _paint_task()
    _write(out)


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
        _write(_paint_buddy() + (_paint_task() if _st["task"] else ""))
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
        _sync_region()
        _paint_all()
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
    return rows - ROWS + 2, GUTTER, cols - GUTTER, rows - ROWS


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
            _sync_region()
            _write(_paint_buddy() + (_paint_task() if _st["task"] else ""))


def stop_task():
    global _anim_stop, _anim_thread
    if _anim_stop is not None:
        _anim_stop.set()
    t = _anim_thread
    _anim_stop = _anim_thread = None
    if t is not None and t is not threading.current_thread():
        t.join(timeout=1.0)
    with _lock:
        _st.update(task=None, detail="", started=0.0)
