"""
CYPHEX — Trace Deck

The compact view of the waypoint trace: the current goal and its sub-steps,
inside one bordered box that scrolls with the scan output.

    ╭─ ◈ CYPHEX ─ 4/9 DYNAMIC VULNERABILITY SCAN ──────── 12.4s ─╮
    │ goal · Prove which candidates are exploitable              │
    │ ✓ crawler         24 endpoints                      1.2s   │
    │ ✓ api discovery   8 routes                          0.4s   │
    │ ⠋ agent 03 SQLi   probing /api/orders                      │
    ╰────────────────────────────────────────────────────────────╯

THE BUDDY IS NOT IN HERE
It used to sit inside this box, which meant it scrolled away with every
waypoint and a new copy was printed each time. It now lives in the pinned
footer beside the input box (footer_dock.py), exactly one copy, animated in
place. This module still owns the mapping from a waypoint to the buddy's
state — buddy_state() — because that is trace knowledge; the footer only
draws.

WHY IT IS A SEPARATE MODULE
It renders `backend.observability.trace.TraceRecorder`, which is the single
source of truth. This module holds no state a maintainer could disagree
with — it is a pure view. It deliberately does NOT live in terminal_ui.py.

DEGRADATION — two levels, each verified:
  1. Full    — TTY: the live trace box.
  2. No TTY  — CI, pipes: one static line per completed step, no box, no
               escapes. The trace is still fully recorded either way; the
               durable record is the event log, not this view.
"""

import sys
import time

# Colour constants + helpers come from terminal_ui so the deck stays on the
# same palette as every other panel. Imported defensively: a missing/broken
# terminal_ui must degrade this to plain text, never break a scan.
try:
    from terminal_ui import (
        PHOS, PHOS_DIM, REF, CAUT, WARN, LABEL, READOUT, TGT, OK,
        soc as _soc, _tty as _ui_tty, _ascii_mode as _ui_ascii,
    )
    _UI = True
except Exception:  # pragma: no cover - defensive
    PHOS = PHOS_DIM = REF = CAUT = WARN = LABEL = READOUT = TGT = OK = ""
    _soc = None
    _UI = False

    def _ui_tty(console=None):
        return sys.stdout.isatty()

    def _ascii_fallback(console=None):
        return True

    _ui_ascii = _ascii_fallback

from backend.observability.trace import RUNNING, OK as ST_OK, WARN as ST_WARN, FAIL, SKIP


_STATUS_GLYPH = {
    ST_OK: ("✓", "v"),
    ST_WARN: ("▲", "!"),
    FAIL: ("✗", "x"),
    SKIP: ("·", "-"),
}
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_ASCII = "|/-\\"


def _status_style(status):
    return {ST_OK: OK, ST_WARN: CAUT, FAIL: WARN, SKIP: LABEL}.get(status, READOUT)


#: Step rows shown under the goal — the box stays a fixed, glanceable size.
_STEP_TAIL = 3

#: Which buddy state (footer_dock.FACES key) each waypoint drives.
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


def buddy_state(wp):
    """The footer buddy's state for a waypoint: its failure/success outcome
    once finished, else what kind of work it is."""
    if wp is None:
        return "idle"
    status = wp.derived_status() if wp.status != RUNNING else RUNNING
    if status == FAIL:
        return "error"
    if wp.status != RUNNING and status in (ST_OK, ST_WARN):
        return "success"
    key = str(wp.num).split("/")[0].strip()
    return STATE_FOR_WAYPOINT.get(key, "working")


class TraceDeck:
    """
    Live view over a TraceRecorder.

    Subscribes to the recorder, so every waypoint/step transition repaints.
    The spinner frame advances on each repaint, so it moves with real
    pipeline progress rather than a decorative timer.
    """

    def __init__(self, recorder, console=None, width=None, animate=True):
        self.recorder = recorder
        self.console = console or _soc
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

        # Goal first, then the step tail. The goal is
        # deliberately line one — it is the thing that makes this a trace
        # of intent rather than a progress bar.
        lines = []
        if wp is None:
            lines.append(("goal · ", LABEL, "waiting for the first waypoint", READOUT, ""))
        else:
            lines.append(("goal · ", LABEL, wp.goal, REF, ""))
            for st in wp.steps[-_STEP_TAIL:]:
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

        # Every row is hard-truncated to the width budget: a wrapped line
        # silently adds a row and the box height stops being predictable.
        total_w = self._width or max(int(getattr(self.console, "width", 80) or 80), 40)
        text_budget = max(total_w - 6, 20)

        for i, row in enumerate(lines):
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
            if i < len(lines) - 1:
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
