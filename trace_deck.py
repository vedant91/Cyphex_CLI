"""
CYPHEX — Trace Deck

The compact live view of the waypoint trace: a small mascot on the left,
the current goal and its sub-steps on the right, inside one bordered box.

    ╭─ ◈ CYPHEX ─ 4/9 DYNAMIC VULNERABILITY SCAN ──────── 12.4s ─╮
    │     ╹     goal · Prove which candidates are exploitable    │
    │   ▛▀▀▀▀▜  ✓ crawler         24 endpoints            1.2s   │
    │   ▌▘ ▸▸▐  ✓ api discovery   8 routes                0.4s   │
    │   ▙▄▄▄▄▟  ⠋ agent 03 SQLi   probing /api/orders            │
    │    ▀  ▀                                                    │
    ╰────────────────────────────────────────────────────────────╯

WHY THIS EXISTS, AND WHY IT IS SMALL
The mascot previously rendered at 24 columns and owned its own terminal
region, which made it a decoration competing with the pipeline output. Here
it is 8 columns and lives *inside* the trace box, next to the thing it is
reacting to — the same relationship a coding agent's companion has to its
status line. Its expression is not ambient: it is bound to the trace state,
so a glance at the buddy tells you the same thing the text does.

WHY THE ART IS HAND-AUTHORED
The first version downsampled mascot.py's pixel-art sprite to 8 columns. It
did not work, and could not: mascot.py itself sets _MIN_TARGET_COLS = 16 and
documents that below it the art is mush. Squeezing a 109x177 sprite —
already recovered from JPEG-compressed reference art — through a 13x
reduction produced disconnected fragments with no silhouette. So the buddy
is drawn at the size it is displayed, as 8x5 block glyphs, one authored
frame set per state. Resampling cannot invent structure at this scale;
drawing can.

WHY IT IS A SEPARATE MODULE
It renders `backend.observability.trace.TraceRecorder`, which is the single
source of truth. This module holds no state a maintainer could disagree
with — it is a pure view. It deliberately does NOT live in terminal_ui.py,
and since the art became glyphs it needs neither Pillow, nor the sprite
assets, nor any of mascot.py's terminal-owning session machinery.

DEGRADATION — two levels, each verified:
  1. Full    — TTY: the animated buddy beside the live trace, in one box.
  2. No TTY  — CI, pipes: one static line per completed step, no box, no
               escapes. The trace is still fully recorded either way; the
               durable record is the event log, not this view.
"""

import os
import sys
import time

# Colour constants + helpers come from terminal_ui so the deck stays on the
# same palette as every other panel. Imported defensively: a missing/broken
# terminal_ui must degrade this to plain text, never break a scan.
try:
    from terminal_ui import (
        PHOS, PHOS_DIM, REF, CAUT, WARN, WARN_HOT, APEX, LABEL, READOUT, TGT,
        soc as _soc, _tty as _ui_tty, _ascii_mode as _ui_ascii,
    )
    _UI = True
except Exception:  # pragma: no cover - defensive
    PHOS = PHOS_DIM = REF = CAUT = WARN = LABEL = READOUT = TGT = ""
    WARN_HOT = APEX = ""
    _soc = None
    _UI = False

    def _ui_tty(console=None):
        return sys.stdout.isatty()

    def _ascii_fallback(console=None):
        return True

    _ui_ascii = _ascii_fallback

from backend.observability.trace import RUNNING, OK, WARN as ST_WARN, FAIL, SKIP


_STATUS_GLYPH = {
    OK: ("✓", "v"),
    ST_WARN: ("▲", "!"),
    FAIL: ("✗", "x"),
    SKIP: ("·", "-"),
}
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_ASCII = "|/-\\"


def _status_style(status):
    return {OK: PHOS, ST_WARN: CAUT, FAIL: WARN, SKIP: LABEL}.get(status, READOUT)


_ANSI_RE = None


def _visible(s: str) -> str:
    """The printable content of an ANSI-coloured row, escapes stripped."""
    global _ANSI_RE
    if _ANSI_RE is None:
        import re
        _ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
    return _ANSI_RE.sub("", s)


# ── mascot frame source ──────────────────────────────────────────────────
# The buddy here is HAND-AUTHORED block art, not the downsampled pixel-art
# sprite the full-size mascot uses, and that is a deliberate reversal of the
# first implementation.
#
# mascot.py sets _MIN_TARGET_COLS = 16 and documents why: below that the
# sprite is mush and a plain glyph line is the honest answer. The deck wants
# 8 columns. Feeding a 109x177 sprite — itself recovered from JPEG-compressed
# reference art — through a 13x downsample produced disconnected fragments
# with no readable silhouette: at 8 cols "idle" rendered as
#
#     ▄▄▄▄        ▀█  ▄█        ▀  ▀▀        ▀▀▀▀▀
#
# which is not a robot by any reading. Resampling cannot invent structure
# that few pixels; the only way to be legible at this size is to draw it at
# this size. So each state is authored directly as 8x5 block glyphs.
#
# This also drops Pillow and the sprite assets from the deck's dependency
# set entirely, so the "no mascot" degradation level no longer exists — the
# buddy renders anywhere the box does.
#
# GLYPH WIDTH: the chassis uses ▀ ▄ ▌ which Unicode classes as
# East-Asian-Ambiguous, i.e. double-width under some CJK locales. They are
# kept because the shipped subcell renderer already depends on them being
# narrow, so the deck is exactly as safe as the rest of the UI and no more.
# The FACE glyphs are all unambiguously narrow (▘ ▂ ▪ ▸ ▴ ◜ ◝ ✕), since
# those are the ones that change per state and would desynchronise the box
# width if they measured differently frame to frame.
DECK_COLS = 8
DECK_MODE = "glyph"

#: Antenna, 4-cell face, 4-cell feet — per animation frame, per state.
#: Frames cycle at the deck's redraw rate; single-frame states are static.
_SPRITE_STATES = {
    "idle":      [("╻", "▘  ▘", "▀  ▀"), ("╻", "▂  ▂", "▀  ▀")],
    "searching": [("╹", "▘ ▸▸", "▀  ▀"), ("╹", "▘▸▸ ", "▀  ▀"),
                  ("╹", "▘▸  ", "▀  ▀")],
    "thinking":  [("╹", "▪   ", "▀  ▀"), ("╹", "▪▪  ", "▀  ▀"),
                  ("╹", "▪▪▪ ", "▀  ▀")],
    "working":   [("╻", "▘  ▘", "▄  ▀"), ("╻", "▘  ▘", "▀  ▄")],
    "uploading": [("╹", "▴  ▴", "▀  ▀"), ("╹", "▘  ▘", "▀  ▀")],
    "success":   [("╹", "◜  ◝", "▀  ▀")],
    "error":     [("╻", "✕  ✕", "▀  ▀"), ("╻", "▘  ▘", "▀  ▀")],
}

#: ASCII twin of _SPRITE_STATES, for terminals that cannot render the block
#: glyphs at all (legacy Windows consoles, non-UTF-8 locales). Same 8x5 grid
#: and the same per-state faces, so the deck's geometry is identical either
#: way — only the character vocabulary changes, exactly as _STATUS_GLYPH and
#: the box characters already do.
_SPRITE_STATES_ASCII = {
    "idle":      [("|", "o  o", "^  ^"), ("|", "-  -", "^  ^")],
    "searching": [("|", "o  >", "^  ^"), ("|", "o >>", "^  ^"),
                  ("|", "o>> ", "^  ^")],
    "thinking":  [("|", ".   ", "^  ^"), ("|", "..  ", "^  ^"),
                  ("|", "... ", "^  ^")],
    "working":   [("|", "o  o", "_  ^"), ("|", "o  o", "^  _")],
    "uploading": [("|", "^  ^", "^  ^"), ("|", "o  o", "^  ^")],
    "success":   [("|", "\\  /", "^  ^")],
    "error":     [("|", "x  x", "^  ^"), ("|", "o  o", "^  ^")],
}

#: Chassis rows, Unicode and ASCII. Index 0/1/2 = top, face row walls, bottom.
_CHASSIS = ("\u259b\u2580\u2580\u2580\u2580\u259c", "\u258c", "\u2590",
            "\u2599\u2584\u2584\u2584\u2584\u259f")
_CHASSIS_ASCII = ("+----+", "|", "|", "+----+")

#: States whose antenna reads as "powered" — brighter than the chassis.
_ACTIVE_STATES = {"searching", "thinking", "working", "uploading", "success"}

STATE_FOR_WAYPOINT = {
    "1": "uploading",    # fetching source
    "2": "searching",    # static analysis
    "3": "working",      # sandbox deploy
    "3b": "searching",   # network sweep
    "4": "searching",    # dynamic scan
    "5": "thinking",     # genome build — the highlighted one
    "6": "working",      # attack simulation
    "7": "thinking",     # report
    "8": "working",      # patch + verify
}


def _ansi(hex_color):
    """Truecolor escape for a ramp hex, or "" when colour is unavailable."""
    if not hex_color or not hex_color.startswith("#"):
        return ""
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return f"\033[38;2;{r};{g};{b}m"


_RST = "\033[0m"


class _FrameSource:
    """Hand-authored buddy frames, rendered to ANSI rows of exactly `cols`
    visible cells.

    The interface is unchanged from the image-backed version it replaces —
    `.cols`, `.rows`, `.ok`, `.rows_for(state, idx)` — so TraceDeck's
    composition code did not need to change.
    """

    def __init__(self, cols=None, mode=None):
        self.cols = DECK_COLS if cols is None else cols
        self.mode = DECK_MODE if mode is None else mode
        self._cache = {}
        self.rows = 5
        # Always available: no Pillow, no assets, no image pipeline.
        self.ok = self.cols >= DECK_COLS

    def _compose(self, state, idx):
        try:
            ascii_mode = bool(_ui_ascii())
        except Exception:
            ascii_mode = False
        table = _SPRITE_STATES_ASCII if ascii_mode else _SPRITE_STATES
        top, lwall, rwall, bot = _CHASSIS_ASCII if ascii_mode else _CHASSIS
        frames = table.get(state) or table["idle"]
        antenna, face, feet = frames[idx % len(frames)]

        chassis = _ansi(PHOS)
        accent = _ansi(REF)
        # The error face is the one thing that must not read as decoration.
        if state == "error":
            face_c = _ansi(WARN_HOT) or accent
        elif state == "success":
            face_c = _ansi(APEX) or accent
        else:
            face_c = accent
        ant_c = accent if state in _ACTIVE_STATES else _ansi(PHOS_DIM)
        rst = _RST if chassis else ""

        pad = " " * max(self.cols - DECK_COLS, 0)
        return [
            f"   {ant_c}{antenna}{rst}    {pad}",
            f" {chassis}{top}{rst} {pad}",
            f" {chassis}{lwall}{rst}{face_c}{face}{rst}{chassis}{rwall}{rst} {pad}",
            f" {chassis}{bot}{rst} {pad}",
            f"  {chassis}{feet}{rst}  {pad}",
        ]

    def rows_for(self, state, idx):
        """Rendered rows, or blank padding if anything goes wrong."""
        key = (state, idx)
        if key in self._cache:
            return self._cache[key]
        try:
            rows = self._compose(state, idx)
        except Exception:
            rows = [" " * self.cols] * self.rows
        self._cache[key] = rows
        return rows


class TraceDeck:
    """
    Live view over a TraceRecorder.

    Subscribes to the recorder, so every waypoint/step transition repaints.
    The mascot frame advances on each repaint, which means the animation is
    driven by real pipeline progress rather than a decorative timer — the
    buddy visibly works harder when the pipeline is doing more.
    """

    def __init__(self, recorder, console=None, width=None, animate=True):
        self.recorder = recorder
        self.console = console or _soc
        self.frames = _FrameSource()
        self.animate = animate
        self._frame_idx = 0
        self._live = None
        self._printed_steps = set()
        self._width = width
        self.tty = bool(_ui_tty(self.console)) if _UI else sys.stdout.isatty()

    # ── lifecycle ───────────────────────────────────────────────────────
    def __enter__(self):
        try:
            self.recorder.subscribe(self._on_change)
            if self.tty:
                from rich.live import Live
                self._live = Live(self._renderable(), console=self.console,
                                  refresh_per_second=12, transient=False)
                self._live.__enter__()
        except Exception:
            self._live = None
        return self

    def __exit__(self, *exc):
        try:
            if self._live is not None:
                self._live.update(self._renderable(final=True))
                self._live.__exit__(*exc)
        except Exception:
            pass
        self._live = None
        return False

    def _on_change(self, recorder):
        self._frame_idx += 1
        if self._live is not None:
            try:
                self._live.update(self._renderable())
            except Exception:
                pass
        elif not self.tty:
            self._print_plain_delta()

    # ── non-TTY path ────────────────────────────────────────────────────
    def _print_plain_delta(self):
        """One static line per newly-finished step. No escapes, no redraw —
        safe for CI logs and pipes, where a Live region would be noise."""
        try:
            wp = self.recorder.current
            if wp is None:
                return
            for st in wp.steps:
                key = (id(wp), id(st))
                if st.status == RUNNING or key in self._printed_steps:
                    continue
                self._printed_steps.add(key)
                mark = _STATUS_GLYPH.get(st.status, ("·", "-"))[1]
                detail = f"  {st.detail}" if st.detail else ""
                print(f"    [{mark}] {wp.num} {st.label}{detail}  ({st.duration_s:.1f}s)")
        except Exception:
            pass

    # ── rendering ───────────────────────────────────────────────────────
    def _mascot_state(self, wp):
        if wp is None:
            return "idle"
        status = wp.derived_status() if wp.status != RUNNING else RUNNING
        if status == FAIL:
            return "error"
        if wp.status != RUNNING and status in (OK, ST_WARN):
            return "success"
        key = str(wp.num).split("/")[0].strip()
        return STATE_FOR_WAYPOINT.get(key, "working")

    def _renderable(self, final=False):
        from rich.panel import Panel
        from rich.text import Text
        try:
            from terminal_ui import _box as _ui_box
            box = _ui_box(self.console)
        except Exception:
            from rich.box import ROUNDED
            box = ROUNDED

        ascii_mode = bool(_ui_ascii(self.console)) if _UI else True
        wp = self.recorder.current
        body = Text()

        mascot_rows = []
        if self.frames.ok:
            mascot_rows = self.frames.rows_for(self._mascot_state(wp),
                                               self._frame_idx if self.animate else 0)

        # Right-hand column: goal first, then the step tail. The goal is
        # deliberately line one — it is the thing that makes this a trace
        # of intent rather than a progress bar.
        lines = []
        if wp is None:
            lines.append(("goal · ", LABEL, "waiting for the first waypoint", READOUT, ""))
        else:
            lines.append(("goal · ", LABEL, wp.goal, REF, ""))
            budget = max(len(mascot_rows) - 1, 3)
            for st in wp.steps[-budget:]:
                if st.status == RUNNING:
                    spin = (_SPINNER_ASCII if ascii_mode else _SPINNER)
                    glyph = spin[self._frame_idx % len(spin)]
                    style = REF
                else:
                    glyph = _STATUS_GLYPH.get(st.status, ("·", "-"))[1 if ascii_mode else 0]
                    style = _status_style(st.status)
                dur = "" if st.status == RUNNING else f"{st.duration_s:5.1f}s"
                lines.append((f"{glyph} ", style, st.label, READOUT,
                              f"{st.detail}", dur))

        # Compose: mascot column, gutter, then the text column.
        #
        # Two things this has to get right, both learned the hard way:
        #  - Mascot rows are raw ANSI. Appending them as plain strings makes
        #    Rich count the escape bytes as printable width, which throws the
        #    box alignment out and wraps rows mid-escape. Text.from_ansi()
        #    parses them into styled spans with the correct cell width.
        #  - Every text row must be hard-truncated to the remaining budget.
        #    A wrapped line silently adds a row, which breaks the one
        #    invariant the fixed-height canvas exists to guarantee.
        gutter = 2
        total_w = self._width or max(int(getattr(self.console, "width", 80) or 80), 40)
        mascot_w = (self.frames.cols + gutter) if mascot_rows else 0
        text_budget = max(total_w - mascot_w - 6, 20)

        height = max(len(mascot_rows), len(lines)) if mascot_rows else len(lines)
        for i in range(height):
            if mascot_rows:
                raw = mascot_rows[i] if i < len(mascot_rows) else " " * self.frames.cols
                try:
                    body.append_text(Text.from_ansi(raw))
                except Exception:
                    body.append(" " * self.frames.cols)
                body.append(" " * gutter)
            if i < len(lines):
                row = lines[i]
                glyph, gstyle, label, lstyle = row[0], row[1], row[2], row[3]
                detail = row[4] if len(row) > 4 else ""
                dur = row[5] if len(row) > 5 else ""
                # Reserve the duration column, then fit label + detail.
                dur_w = len(dur) + 2 if dur else 0
                avail = max(text_budget - len(glyph) - dur_w, 8)
                if detail:
                    lw = min(len(label), max(avail // 2, 10))
                    label_s = label[:lw]
                    detail_s = detail[: max(avail - lw - 3, 0)]
                else:
                    label_s = label[:avail]
                    detail_s = ""
                body.append(glyph, style=gstyle)
                body.append(label_s, style=lstyle)
                if detail_s:
                    body.append(f"   {detail_s}", style=LABEL)
                if dur:
                    body.append(f"  {dur}", style=LABEL)
            if i < height - 1:
                body.append("\n")

        # Title carries waypoint identity + elapsed, so the box header alone
        # answers "where am I and how long has it been".
        if wp is not None:
            # Scan-wide elapsed, not this waypoint's. The deck paints when a
            # waypoint opens, so its own duration is ~0 there and tells the
            # reader nothing; "how long has this scan been going" is the
            # number they actually want in the header.
            try:
                started = self.recorder.waypoints[0].started_at
                elapsed = f"{time.time() - started:.0f}s"
            except Exception:
                elapsed = f"{wp.duration_s:.1f}s"
            title = f"◈ CYPHEX  {wp.num}  {wp.title}"
            border = WARN if wp.derived_status() == FAIL else (
                REF if wp.highlight else PHOS_DIM)
        else:
            elapsed = ""
            title = "◈ CYPHEX"
            border = PHOS_DIM

        if ascii_mode:
            title = title.replace("◈ ", "")

        return Panel(body,
                     title=Text(title, style=f"bold {REF if (wp and wp.highlight) else PHOS}"),
                     subtitle=Text(elapsed, style=LABEL) if elapsed else None,
                     title_align="left", subtitle_align="right",
                     border_style=border, box=box, padding=(0, 1))


def render_trace_summary(recorder, console=None):
    """One-shot static render of the whole recorded trace.

    Printed after a scan (and used by /status for a past scan) so the trace
    is reviewable when the live deck is gone. Same data, no animation.
    """
    from rich.panel import Panel
    from rich.text import Text
    c = console or _soc
    if c is None:
        return
    try:
        from terminal_ui import _box as _ui_box
        box = _ui_box(c)
    except Exception:
        from rich.box import ROUNDED
        box = ROUNDED

    ascii_mode = bool(_ui_ascii(c)) if _UI else True
    body = Text()
    # Hard-truncate to the panel's inner width. A wrapped goal line spills
    # into the border column and makes the whole trace look broken, which
    # is a poor look for the one panel whose job is legibility.
    inner = max(int(getattr(c, "width", 80) or 80) - 8, 40)
    goal_w = inner - 16
    wps = recorder.waypoints if hasattr(recorder, "waypoints") else []
    if not wps:
        body.append("  no waypoints traced\n", style=LABEL)
    for wp in wps:
        status = wp.derived_status()
        glyph = _STATUS_GLYPH.get(status, ("·", "-"))[1 if ascii_mode else 0]
        body.append(f"  {glyph} ", style=f"bold {_status_style(status)}")
        body.append(f"{wp.num:<5}", style=TGT)
        body.append(f"{wp.title}", style=f"bold {READOUT}")
        body.append(f"   {wp.duration_s:.1f}s\n", style=LABEL)
        body.append(f"        goal · {wp.goal[:goal_w]}\n", style=LABEL)
        for st in wp.steps:
            sg = _STATUS_GLYPH.get(st.status, ("·", "-"))[1 if ascii_mode else 0]
            body.append(f"        {sg} ", style=_status_style(st.status))
            body.append(f"{st.label:<22}", style=READOUT)
            if st.detail:
                body.append(f"{st.detail[:34]:<36}", style=LABEL)
            body.append(f"{st.duration_s:5.1f}s\n", style=LABEL)

    c.print(Panel(body, title=Text("◈ WAYPOINT TRACE", style=f"bold {PHOS}"),
                  title_align="left", border_style=PHOS_DIM, box=box, padding=(0, 1)))
