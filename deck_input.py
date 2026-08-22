#!/usr/bin/env python3
"""
CYPHEX — raw-mode single-line input editor for the BORESIGHT command deck.

WHY THIS EXISTS
---------------
The REPL draws its input field as a box. Under plain readline only three
walls can ever be up while the user types: readline redraws the input line
on every edit and clears to end-of-line, which wipes anything painted at a
fixed right column. The box only ever closed *after* Enter, so the field
looked unbounded exactly while it was being used.

Owning the line editing fixes that. This module puts the tty in raw mode,
decodes keys itself, and repaints the input row — left wall, text, right
wall at a fixed column — as one atomic write per keystroke. All four walls
stay up the whole time, and the field is visually identical to the box
terminal_ui.deck_input_box_top/bottom() already produce.

PUBLIC API
----------
    supported(console=None) -> bool
    read_line(session=None, *, completer=None, history=None,
              console=None) -> str
    input_box_top(session=None, console=None)      # no-op while raw is live
    input_box_bottom(session=None, console=None)   # no-op while raw is live
    display_width(text) -> int

read_line() is a drop-in for the REPL's `input(_repl_prompt())`:
  * returns the line WITHOUT its trailing newline and WITHOUT stripping
    (cx.py applies .strip() itself),
  * raises KeyboardInterrupt on Ctrl+C,
  * raises EOFError on Ctrl+D with an empty buffer,
so cx.py's existing `except KeyboardInterrupt` / `except EOFError` arms
keep working untouched.

When raw mode isn't available or isn't wanted (see supported()), read_line()
transparently delegates to input() with terminal_ui.deck_prompt() — i.e.
exactly today's behaviour, nothing regresses.

Standard library only: termios, tty, select, signal, codecs, unicodedata.
No prompt_toolkit, no curses, no wcwidth.
"""
from __future__ import annotations

import codecs
import errno
import fcntl
import os
import select
import signal
import sys
import unicodedata

try:                                     # POSIX-only; absent on Windows
    import termios
    import tty
except ImportError:                      # pragma: no cover - platform gate
    termios = None
    tty = None

try:
    import terminal_ui as ui             # palette, glyphs, prompt segments
except Exception:                        # pragma: no cover - SOC UI absent
    ui = None

__all__ = ["read_line", "supported", "input_box_top", "input_box_bottom",
           "display_width", "cell_widths"]


# ══════════════════════════════════════════════════════════════════════════
#  ANSI vocabulary (raw — no \001/\002 readline markers anywhere in here)
# ══════════════════════════════════════════════════════════════════════════
_CSI      = "\033["
_RST      = "\033[0m"
_HIDE     = "\033[?25l"      # DECTCEM off — hide cursor during a repaint
_SHOW     = "\033[?25h"      # DECTCEM on
_BP_ON    = "\033[?2004h"    # bracketed paste on
_BP_OFF   = "\033[?2004l"    # bracketed paste off
_WRAP_OFF = "\033[?7l"       # DECAWM off — a full-width row can't wrap/scroll
_WRAP_ON  = "\033[?7h"       # DECAWM on
_EL       = "\033[2K"        # erase the whole line (never scrolls)
_ED       = "\033[0J"        # erase cursor..end of screen (never scrolls)
_UP       = "\033[A"         # CUU — clamped at the margin, never scrolls
_DOWN     = "\033[B"         # CUD — clamped at the margin, never scrolls

_ESC_TIMEOUT = 0.06          # s to wait for the tail of an escape sequence
#: Hard cap on the body of a CSI/OSC/DCS/APC sequence before it is treated
#: as runaway junk and discarded outright, so a malformed stream can never
#: wedge the reader or leak its body into the command buffer.
_MAX_STRING_SEQ = 4096
_PASTE_TIMEOUT = 2.0         # s to wait for the end of a bracketed paste
_MAX_COMPLETIONS = 512       # hard stop on a runaway completer
_MAX_CANDIDATE_ROWS = 12     # rows of Tab candidates before we elide
_MIN_WIDTH = 20              # matches terminal_ui.deck_box_width()
_DELIMS = " \t\n"            # == readline.set_completer_delims() in cx.py

# Palette fallbacks — only reachable if terminal_ui vanished, in which case
# supported() is already False and we never paint. Kept so the module is
# importable and unit-testable on its own.
_PHOS_DIM = "#6d2c31"
_LABEL    = "#8e7174"
_READOUT  = "#e1d0d2"


def _pal(name, default):
    return getattr(ui, name, default) if ui is not None else default


def _fg(hex_colour):
    """24-bit truecolor SGR — terminal_ui._fg() when available, so the ramp
    stays in one place."""
    if ui is not None:
        try:
            return ui._fg(hex_colour)
        except Exception:
            pass
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return "\033[38;2;%d;%d;%dm" % (r, g, b)


# ══════════════════════════════════════════════════════════════════════════
#  DISPLAY WIDTH — cells, not codepoints
#  Get this wrong and the right wall lands in the wrong column, which is the
#  entire feature. No wcwidth dependency exists here, so this is built on
#  unicodedata: East Asian Wide/Fullwidth => 2 cells, combining marks and
#  format controls => 0, plus the emoji cases the EAW table alone misses.
# ══════════════════════════════════════════════════════════════════════════
_ZERO_CATS = frozenset(("Mn", "Me", "Cf", "Cc"))
_VS16 = "️"     # emoji presentation selector — promotes base to 2 cells
_VS15 = "︎"     # text presentation selector — base stays 1 cell
_ZWJ  = "‍"     # zero-width joiner — welds the next glyph into the cluster


def _base_width(ch):
    if unicodedata.combining(ch):
        return 0
    if unicodedata.category(ch) in _ZERO_CATS:
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def cell_widths(text):
    """Per-character cell widths, context-aware (VS16 / ZWJ / flag pairs)."""
    out = []
    join = False
    ri = 0
    for ch in text:
        if ch == _VS16 or ch == _VS15:
            if ch == _VS16:
                for k in range(len(out) - 1, -1, -1):
                    if out[k] > 0:
                        out[k] = 2
                        break
            out.append(0)
            continue
        if ch == _ZWJ:
            out.append(0)
            join = True
            continue
        if join:                       # welded into the previous cluster
            out.append(0)
            join = False
            continue
        if 0x1F1E6 <= ord(ch) <= 0x1F1FF:   # regional indicators — flags pair up
            ri += 1
            out.append(2 if ri % 2 == 1 else 0)
            continue
        ri = 0
        out.append(_base_width(ch))
    return out


def display_width(text):
    """Terminal cells `text` occupies."""
    return sum(cell_widths(text))


def _window(text, widths, start, count):
    """Exactly `count` cells of `text` beginning at cell `start`.

    A wide character straddling either edge is rendered as spaces for the
    cells it actually covers, so the window is always precisely `count`
    cells and the right wall never shifts.
    """
    out = []
    used = 0
    col = 0
    stop = start + count
    for ch, w in zip(text, widths):
        s, e = col, col + w
        col = e
        if w == 0:                     # combining mark rides its base char
            if out and start < s <= stop:
                out.append(ch)
            continue
        if e <= start or s >= stop:
            continue
        if s < start or e > stop:      # straddles an edge
            n = min(e, stop) - max(s, start)
            out.append(" " * n)
            used += n
            continue
        out.append(ch)
        used += w
    if used < count:
        out.append(" " * (count - used))
    return "".join(out)


# ══════════════════════════════════════════════════════════════════════════
#  CAPABILITY GATE
# ══════════════════════════════════════════════════════════════════════════
def supported(console=None) -> bool:
    """True when raw-mode editing can be used *right now*.

    False (=> read_line() falls back to input()) when any of:
      * CX_NO_RAW_INPUT is set            — operator escape hatch
      * termios/tty are unimportable      — Windows, stripped POSIX builds
      * os.name == "nt"                   — Windows, incl. VT-less consoles
      * terminal_ui is unimportable       — no deck to match
      * NO_COLOR is set                   — user asked for no decoration
      * TERM is empty / dumb / unknown    — CI logs, serial consoles
      * stdin or stdout is not a tty      — piped, redirected, captured
      * terminal_ui._ascii_mode()         — legacy Windows VT, non-UTF-8 io
      * termios.tcgetattr(stdin) fails    — fd isn't a real terminal
    """
    if os.environ.get("CX_NO_RAW_INPUT"):
        return False
    if termios is None or tty is None or os.name == "nt":
        return False
    if ui is None:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").strip().lower() in ("", "dumb", "unknown"):
        return False
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
    except Exception:
        return False
    try:
        if ui._ascii_mode(console):
            return False
    except Exception:
        return False
    try:
        termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        return False
    return True


class _RawUnavailable(RuntimeError):
    """Raw mode could not be entered — caller should fall back to input()."""


def _fallback_prompt(session=None):
    if ui is not None:
        try:
            return ui.deck_prompt(session)
        except Exception:
            pass
    return "cx > "


def _fallback_read(session=None):
    """Today's behaviour, unchanged: input() raises KeyboardInterrupt /
    EOFError natively, which is exactly the contract cx.py depends on."""
    return input(_fallback_prompt(session))


# ══════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════════
#: Lines left over from a multi-line paste, consumed by later read_line()
#: calls in order. Module level rather than per-editor because the editor that
#: received the paste is torn down the moment it submits its first line.
_pending_lines = []


def _queue_pending_lines(text):
    """Queue the tail of a multi-line paste for subsequent read_line() calls."""
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.strip():
            _pending_lines.append(line)


def pending_lines():
    """How many pasted lines are still queued (for tests and callers)."""
    return len(_pending_lines)


def read_line(session=None, *, completer=None, history=None, console=None):
    """Read one line with all four walls of the input field drawn.

    session   — the cx.py _session dict; only "caret" is read, for the glyph.
    completer — readline-signature completer(text, state) -> str | None, so
                cx.py's _completer can be handed over unchanged.
    history   — mutable list[str] of previously entered lines, navigated with
                Up/Down and appended to on submit. NOTE: cx.py's
                _session["history"] holds scan-record dicts, not input lines —
                pass a separate list. Non-str entries are ignored and never
                appended to, so handing over the wrong list degrades to
                "history disabled" instead of corrupting it.
    console   — Rich console to measure/style against (defaults to
                terminal_ui.soc, the same one the rest of the deck uses).

    Returns the line without its trailing newline (no stripping).
    Raises KeyboardInterrupt on Ctrl+C, EOFError on Ctrl+D at an empty buffer.
    """
    if _pending_lines:
        # Drain a queued line from an earlier multi-line paste before reading
        # any new input, so a pasted block executes in order.
        line = _pending_lines.pop(0)
        if history is not None and isinstance(line, str):
            history.append(line)
        return line
    if not supported(console):
        return _fallback_read(session)
    try:
        editor = _Editor(sys.stdin.fileno(), sys.stdout.fileno(),
                         session=session, completer=completer,
                         history=history, console=console)
    except Exception:
        return _fallback_read(session)
    try:
        sys.stdout.flush()
    except Exception:
        pass
    try:
        return editor.run()
    except _RawUnavailable:
        return _fallback_read(session)


def input_box_top(session=None, console=None):
    """Compatibility shim for cx.py's _input_box_top().

    A no-op when raw editing is live — read_line() paints all three rows of
    the box itself and would otherwise get a duplicate top wall. Falls
    through to the readline-path wall when it isn't.
    """
    if supported(console):
        return
    if ui is not None:
        try:
            ui.deck_input_box_top(console)
        except Exception:
            pass


def input_box_bottom(session=None, console=None):
    """Compatibility shim for cx.py's _input_box_bottom(). See input_box_top()."""
    if supported(console):
        return
    if ui is not None:
        try:
            ui.deck_input_box_bottom(console)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
#  KEY TABLES
# ══════════════════════════════════════════════════════════════════════════
_CTRL = {
    0x01: "home",        # Ctrl+A
    0x02: "left",        # Ctrl+B
    0x03: "interrupt",   # Ctrl+C  -> KeyboardInterrupt
    0x04: "eof-delete",  # Ctrl+D  -> EOFError if empty, else delete-under
    0x05: "end",         # Ctrl+E
    0x06: "right",       # Ctrl+F
    0x08: "backspace",   # Ctrl+H
    0x09: "tab",
    0x0a: "submit",      # LF
    0x0b: "kill-end",    # Ctrl+K
    0x0c: "redraw",      # Ctrl+L
    0x0d: "submit",      # CR
    0x0e: "hist-next",   # Ctrl+N
    0x10: "hist-prev",   # Ctrl+P
    0x15: "kill-start",  # Ctrl+U
    0x17: "kill-word",   # Ctrl+W
    0x7f: "backspace",   # DEL
}

_CSI_FINAL = {"A": "hist-prev", "B": "hist-next", "C": "right", "D": "left",
              "H": "home", "F": "end"}

_CSI_TILDE = {"1": "home", "7": "home", "4": "end", "8": "end", "3": "delete"}


class _Editor:
    """One raw-mode line edit. Owns the tty for its lifetime and restores
    every bit of terminal state it touched in run()'s finally arm."""

    def __init__(self, in_fd, out_fd, session=None, completer=None,
                 history=None, console=None):
        self.in_fd = in_fd
        self.out_fd = out_fd
        self.session = session or {}
        self.completer = completer
        self.console = console
        self.hist = history if isinstance(history, list) else []

        self.buf = []           # list[str] — one entry per codepoint
        self.pos = 0            # cursor index into self.buf
        self.scroll = 0         # first visible cell of the text window

        self.width = _MIN_WIDTH
        self.field = 1          # inner text cells between the two walls
        self.painted = False

        self.pending = b""      # undecoded input bytes
        self.dec = codecs.getincrementaldecoder("utf-8")("replace")

        self._resized = False
        self._saved_tty = None
        self._wake_r = None
        self._wake_w = None
        self._prev_winch = None
        self._prev_wakeup = None
        self._prev_fatal = {}
        self._hidx = None       # index while browsing history, else None
        self._hsaved = ""       # live buffer stashed during a browse
        self._pansi = ""
        self._pcells = 0

    # ── lifecycle ────────────────────────────────────────────────────────
    def run(self):
        # _enter() is INSIDE the try: it does tty.setraw() first, then installs
        # the SIGWINCH handler, then writes the bracketed-paste/wrap sequences.
        # If any step after setraw() raises, the terminal is already in raw
        # mode, so teardown must still run — otherwise the caller falls back to
        # input() on a raw tty and the user's shell is wedged.
        try:
            self._enter()
            self._prompt()
            self._paint_all(initial=True)
            return self._loop()
        finally:
            self._exit()

    def _enter(self):
        try:
            self._saved_tty = termios.tcgetattr(self.in_fd)
            tty.setraw(self.in_fd, termios.TCSADRAIN)
        except Exception as exc:
            self._saved_tty = None
            raise _RawUnavailable(str(exc))
        self._install_winch()
        self._install_fatal()
        # DECAWM off: a row exactly `width` cells wide can then never trip
        # auto-wrap and scroll the screen out from under the box.
        self._w(_BP_ON + _WRAP_OFF)

    def _exit(self):
        """Unconditional teardown — normal return, Enter, Ctrl+C, Ctrl+D,
        or an unexpected exception all land here."""
        try:
            if self.painted:
                # Park below the closed box so command output renders under
                # the field, exactly like the readline path leaves it.
                self._w(_DOWN + "\r\r\n")
        except Exception:
            pass
        for seq in (_WRAP_ON, _BP_OFF, _SHOW, _RST):
            try:
                self._w(seq)
            except Exception:
                pass
        self._restore_winch()
        self._restore_fatal()
        if self._saved_tty is not None:
            try:
                termios.tcsetattr(self.in_fd, termios.TCSADRAIN, self._saved_tty)
            except Exception:
                pass
            self._saved_tty = None

    def _w(self, s):
        if not s:
            return
        data = s.encode("utf-8", "replace")
        while data:
            try:
                n = os.write(self.out_fd, data)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                raise
            data = data[n:]

    # ── SIGWINCH ─────────────────────────────────────────────────────────
    def _install_winch(self):
        """Resize wakeups via a self-pipe: PEP 475 restarts select() around a
        signal, so the handler alone would never break the read. set_wakeup_fd
        is main-thread-only — off the main thread we degrade to noticing the
        resize on the next keystroke instead of failing."""
        sig = getattr(signal, "SIGWINCH", None)     # absent on Windows
        if sig is None:
            return
        try:
            r, w = os.pipe()
            os.set_blocking(r, False)
            os.set_blocking(w, False)
        except Exception:
            return
        try:
            self._prev_wakeup = signal.set_wakeup_fd(w)
        except Exception:
            self._prev_wakeup = None
            for fd in (r, w):
                try:
                    os.close(fd)
                except OSError:
                    pass
            return
        self._wake_r, self._wake_w = r, w
        try:
            self._prev_winch = signal.getsignal(sig)
            signal.signal(sig, self._on_winch)
        except Exception:
            self._prev_winch = None

    def _on_winch(self, signum, frame):
        self._resized = True
        prev = self._prev_winch
        if callable(prev):
            try:
                prev(signum, frame)
            except Exception:
                pass

    def _restore_winch(self):
        sig = getattr(signal, "SIGWINCH", None)
        if sig is not None and self._prev_winch is not None:
            try:
                signal.signal(sig, self._prev_winch)
            except Exception:
                pass
            self._prev_winch = None
        if self._wake_w is not None:
            try:
                signal.set_wakeup_fd(self._prev_wakeup
                                     if self._prev_wakeup is not None else -1)
            except Exception:
                pass
            for fd in (self._wake_r, self._wake_w):
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._wake_r = self._wake_w = None

    # ── fatal-signal safety ──────────────────────────────────────────────
    #
    # SIGTERM and SIGHUP terminate the process by default WITHOUT unwinding
    # the stack, so run()'s finally: never fires and the tty is left in raw
    # mode with bracketed paste on and autowrap off. That wedges the user's
    # shell after the process is gone, and `stty sane` does not fully undo it
    # (it restores the line discipline but sends neither the bracketed-paste
    # nor the autowrap reset). SIGHUP in particular is what a closing terminal
    # window delivers, so this is a routine path, not an exotic one.
    #
    # These handlers restore the terminal, then re-raise the signal with the
    # default disposition restored so the process still dies with the correct
    # status (128+signo) rather than being silently swallowed.
    _FATAL_SIGNALS = ("SIGTERM", "SIGHUP", "SIGQUIT")

    def _install_fatal(self):
        self._prev_fatal = {}
        for name in self._FATAL_SIGNALS:
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                self._prev_fatal[sig] = signal.signal(sig, self._on_fatal)
            except (ValueError, OSError):
                # Not on the main thread, or the platform refuses this signal.
                pass

    def _on_fatal(self, signo, frame):
        # Ordering matters. Restoring termios is the part that actually
        # rescues the user's shell and is a non-blocking syscall, so it goes
        # FIRST. The escape sequences are cosmetic by comparison and a write
        # to a tty whose buffer is full would block forever right here inside
        # the signal handler, so they are attempted afterwards and only on a
        # non-blocking fd.
        if self._saved_tty is not None:
            try:
                termios.tcsetattr(self.in_fd, termios.TCSANOW, self._saved_tty)
            except Exception:
                pass
            self._saved_tty = None
        try:
            self._restore_winch()
        except Exception:
            pass
        self._write_nonblocking(_WRAP_ON + _BP_OFF + _SHOW + _RST + "\r\n")
        try:
            signal.signal(signo, signal.SIG_DFL)
            os.kill(os.getpid(), signo)
        except Exception:
            os._exit(128 + signo)

    def _write_nonblocking(self, s):
        """Best-effort write that can never block — for use in a signal
        handler, where a full tty buffer would otherwise hang the process
        instead of letting it die."""
        try:
            fd = self.out_fd
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            try:
                os.write(fd, s.encode("utf-8", "replace"))
            except (BlockingIOError, OSError):
                pass
            finally:
                try:
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags)
                except OSError:
                    pass
        except Exception:
            pass

    def _restore_fatal(self):
        for sig, prev in list(getattr(self, "_prev_fatal", {}).items()):
            if prev is None:
                continue
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError):
                pass
        self._prev_fatal = {}

    # ── geometry & painting ──────────────────────────────────────────────
    def _prompt(self):
        """Armed caret + left wall, straight from terminal_ui's segments —
        same glyph and same colours as deck_prompt(), minus the \001/\002
        readline markers, which mean nothing outside readline."""
        segs = None
        if ui is not None:
            try:
                segs = ui.deck_prompt_segments(self.session)
            except Exception:
                segs = None
        if not segs:
            segs = [("| ", _PHOS_DIM), ("cx ", _READOUT), ("> ", _PHOS_DIM)]
        self._pansi = "".join(_fg(col) + txt for txt, col in segs) + _RST
        self._pcells = display_width("".join(txt for txt, _ in segs))

    def _glyphs(self):
        if ui is not None:
            try:
                return ui.deck_box_glyphs(self.console)
            except Exception:
                pass
        return {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"}

    def _geometry(self):
        width = None
        if ui is not None:
            try:
                width = ui.deck_box_width(self.console)
            except Exception:
                width = None
        if width is None:
            try:
                width = os.get_terminal_size(self.out_fd).columns
            except Exception:
                width = 80
        self.width = max(int(width), _MIN_WIDTH)
        # inner text cells = width - prompt(left wall included) - pad - right wall
        self.field = max(1, self.width - self._pcells - 2)

    def _wall(self, top):
        g = self._glyphs()
        left, right = (g["tl"], g["tr"]) if top else (g["bl"], g["br"])
        return (_fg(_pal("PHOS_DIM", _PHOS_DIM))
                + left + g["h"] * (self.width - 2) + right + _RST)

    def _row(self):
        """(ansi for the whole input row, 0-based cursor column).

        The row is always exactly self.width cells:
            prompt(+left wall) | [<] window [>] | pad | right wall
        """
        text = "".join(self.buf)
        widths = cell_widths(text)
        total = sum(widths)
        cw = sum(widths[:self.pos])          # cursor offset in cells
        g = self._glyphs()
        ascii_mode = g["v"] == "|"

        if total <= self.field:
            self.scroll = 0
            view = self.field
            gutter = False
        else:
            # Reserve one cell each side for the truncation indicators and
            # keep them reserved even when idle, so the text never jitters
            # sideways as the indicators come and go.
            gutter = True
            view = max(1, self.field - 2)
            if cw < self.scroll:
                self.scroll = cw
            if cw > self.scroll + view - 1:
                self.scroll = cw - (view - 1)
            self.scroll = max(0, min(self.scroll, max(0, total - view + 1)))

        visible = _window(text, widths, self.scroll, view)
        row = [self._pansi]
        if gutter:
            # Subtle truncation indicators: content exists off this edge.
            lo = ("<" if ascii_mode else "‹") if self.scroll > 0 else " "
            hi = ((">" if ascii_mode else "›")
                  if self.scroll + view < total else " ")
            dim = _fg(_pal("LABEL", _LABEL))
            row.append(dim + lo + _RST)
            row.append(visible)
            row.append(dim + hi + _RST)
        else:
            row.append(visible)
        row.append(" " + _fg(_pal("PHOS_DIM", _PHOS_DIM)) + g["v"] + _RST)
        col = self._pcells + (1 if gutter else 0) + (cw - self.scroll)
        return "".join(row), col

    def _paint_row(self):
        """Repaint ONLY the text row — the common case, one keystroke."""
        row, col = self._row()
        self._w(_HIDE + "\r" + _EL + row + _CSI + str(col + 1) + "G" + _SHOW)

    def _paint_all(self, initial=False):
        """Repaint all three rows — first paint, Ctrl+L, resize, post-Tab."""
        self._geometry()
        row, col = self._row()
        if initial or not self.painted:
            self._w(_HIDE + "\r" + _EL + self._wall(True) + "\r\n"
                    + _EL + row + "\r\n"
                    + _EL + self._wall(False))
            self._w(_UP + _CSI + str(col + 1) + "G" + _SHOW)
            self.painted = True
            return
        # In place: cursor movement only, so a repaint can never scroll.
        self._w(_HIDE + _UP + "\r" + _EL + self._wall(True)
                + _DOWN + "\r" + _EL + row
                + _DOWN + "\r" + _EL + self._wall(False)
                + _UP + _CSI + str(col + 1) + "G" + _SHOW)

    # ── input plumbing ───────────────────────────────────────────────────
    def _pump(self, timeout=None):
        """Wait for input; append bytes to self.pending. True if bytes came."""
        fds = [self.in_fd]
        if self._wake_r is not None:
            fds.append(self._wake_r)
        while True:
            try:
                ready, _, _ = select.select(fds, [], [], timeout)
            except (OSError, ValueError) as exc:
                if getattr(exc, "errno", None) == errno.EINTR:
                    continue
                return False
            if self._wake_r is not None and self._wake_r in ready:
                try:
                    os.read(self._wake_r, 4096)
                except OSError:
                    pass
                if self._resized:
                    return False            # let the loop repaint first
                if self.in_fd not in ready:
                    continue                # some other signal — keep waiting
            if self.in_fd in ready:
                try:
                    data = os.read(self.in_fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise EOFError("input stream closed") from exc
                if not data:
                    raise EOFError("input stream closed")
                self.pending += data
                return True
            return False                    # timeout

    def _event(self):
        """One decoded event: ("text", str) | ("key", name) |
        ("paste", str) | ("none", None)."""
        if not self.pending:
            if not self._pump(None):
                return ("none", None)
        b = self.pending[0]
        if b == 0x1b:
            return self._escape()
        if b < 0x20 or b == 0x7f:
            self.pending = self.pending[1:]
            name = _CTRL.get(b)
            return ("key", name) if name else ("none", None)
        return self._text()

    def _text(self):
        """Printable run, decoded incrementally so a UTF-8 sequence split
        across two reads is held in the decoder, never half-inserted."""
        out = []
        while self.pending:
            b = self.pending[0]
            if b == 0x1b or b < 0x20 or b == 0x7f:
                break
            self.pending = self.pending[1:]
            out.append(self.dec.decode(bytes([b])))
        s = "".join(out)
        return ("text", s) if s else ("none", None)

    def _escape(self):
        """Consume a whole escape sequence. Anything unrecognised is eaten
        entirely — never partially inserted as literal junk."""
        while len(self.pending) < 2:
            if not self._pump(_ESC_TIMEOUT):
                self.pending = self.pending[1:]     # lone ESC — ignore
                return ("none", None)
        b1 = self.pending[1]
        if b1 == 0x5b:                              # CSI  ESC [
            i = 2
            while True:
                if i >= len(self.pending):
                    if not self._pump(_ESC_TIMEOUT):
                        self.pending = b""          # truncated — drop it
                        return ("none", None)
                    continue
                c = self.pending[i]
                if 0x40 <= c <= 0x7e:               # final byte
                    break
                i += 1
                if i > _MAX_STRING_SEQ:             # runaway — drop it
                    self.pending = b""
                    return ("none", None)
            params = self.pending[2:i].decode("latin-1", "replace")
            final = chr(self.pending[i])
            self.pending = self.pending[i + 1:]
            return self._csi(params, final)
        if b1 == 0x4f:                              # SS3  ESC O (app cursor)
            while len(self.pending) < 3:
                if not self._pump(_ESC_TIMEOUT):
                    self.pending = b""
                    return ("none", None)
            final = chr(self.pending[2])
            self.pending = self.pending[3:]
            name = _CSI_FINAL.get(final)
            return ("key", name) if name else ("none", None)
        if b1 in (0x5d, 0x50, 0x5f, 0x58):
            # OSC (ESC ]), DCS (ESC P), APC (ESC _) and SOS (ESC X) all carry
            # an arbitrary-length body terminated by ST (ESC \\) or, for OSC,
            # BEL. Eating only two bytes here left the body to be read as
            # ordinary input, so a terminal answering an OSC query (or a
            # pasted title-set sequence) dumped its payload straight into the
            # command buffer as literal text.
            i = 2
            while True:
                if i >= len(self.pending):
                    if not self._pump(_ESC_TIMEOUT):
                        self.pending = b""          # unterminated — drop it
                        return ("none", None)
                    continue
                c = self.pending[i]
                if c == 0x07:                       # BEL terminator
                    self.pending = self.pending[i + 1:]
                    return ("none", None)
                if c == 0x1b and i + 1 < len(self.pending) \
                        and self.pending[i + 1] == 0x5c:   # ST  ESC backslash
                    self.pending = self.pending[i + 2:]
                    return ("none", None)
                i += 1
                if i > _MAX_STRING_SEQ:             # runaway — drop it
                    self.pending = b""
                    return ("none", None)
        self.pending = self.pending[2:]             # ESC <char> (Meta) — eat
        return ("none", None)

    def _csi(self, params, final):
        parts = params.split(";")
        head = parts[0].lstrip("<=>?")
        if final == "~":
            if head == "200":
                return ("paste", self._read_paste())
            if head == "201":
                return ("none", None)
            name = _CSI_TILDE.get(head)
            return ("key", name) if name else ("none", None)
        if final in _CSI_FINAL:
            name = _CSI_FINAL[final]
            mod = 1
            if len(parts) > 1 and parts[1].isdigit():
                mod = int(parts[1])
            if mod > 1 and name in ("left", "right"):   # Ctrl/Alt + arrow
                name = "word-left" if name == "left" else "word-right"
            return ("key", name)
        return ("none", None)

    def _read_paste(self):
        """Payload between ESC[200~ and ESC[201~."""
        end = b"\x1b[201~"
        while end not in self.pending:
            if not self._pump(_PASTE_TIMEOUT):
                break
        idx = self.pending.find(end)
        if idx < 0:
            raw, self.pending = self.pending, b""
        else:
            raw, self.pending = self.pending[:idx], self.pending[idx + len(end):]
        return raw.decode("utf-8", "replace")

    # ── buffer edits ─────────────────────────────────────────────────────
    def _insert(self, text):
        if not text:
            return
        chars = [c for c in text if c >= " " and c != "\x7f"]
        if not chars:
            return
        self.buf[self.pos:self.pos] = chars
        self.pos += len(chars)

    def _backspace(self):
        if self.pos > 0:
            del self.buf[self.pos - 1]
            self.pos -= 1

    def _delete(self):
        if self.pos < len(self.buf):
            del self.buf[self.pos]

    def _word_start(self, idx):
        while idx > 0 and self.buf[idx - 1] in _DELIMS:
            idx -= 1
        while idx > 0 and self.buf[idx - 1] not in _DELIMS:
            idx -= 1
        return idx

    def _word_end(self, idx):
        n = len(self.buf)
        while idx < n and self.buf[idx] in _DELIMS:
            idx += 1
        while idx < n and self.buf[idx] not in _DELIMS:
            idx += 1
        return idx

    def _set(self, text):
        self.buf = list(text)
        self.pos = len(self.buf)
        self.scroll = 0

    # ── history ──────────────────────────────────────────────────────────
    def _entries(self):
        return [e for e in self.hist if isinstance(e, str)]

    def _hist_prev(self):
        entries = self._entries()
        if not entries:
            return
        if self._hidx is None:
            self._hsaved = "".join(self.buf)
            self._hidx = len(entries)
        if self._hidx <= 0:
            return
        self._hidx -= 1
        self._set(entries[self._hidx])

    def _hist_next(self):
        entries = self._entries()
        if self._hidx is None:
            return
        self._hidx += 1
        if self._hidx >= len(entries):
            self._hidx = None
            self._set(self._hsaved)
        else:
            self._set(entries[self._hidx])

    def _remember(self, line):
        """Append to the caller's history list — but only if it really is a
        list of input lines. cx.py's _session["history"] holds scan records;
        handing that over must not corrupt it."""
        if not isinstance(self.hist, list) or not line.strip():
            return
        if self.hist and not isinstance(self.hist[-1], str):
            return
        if self.hist and self.hist[-1] == line:
            return
        self.hist.append(line)

    # ── completion ───────────────────────────────────────────────────────
    def _complete(self):
        """Tab. Delegates to a readline-signature completer(text, state), so
        cx.py's _completer works unchanged."""
        if self.completer is None:
            return
        before = "".join(self.buf[:self.pos])
        start = 0
        for d in _DELIMS:
            start = max(start, before.rfind(d) + 1)
        word = before[start:]
        matches = []
        for state in range(_MAX_COMPLETIONS):
            try:
                m = self.completer(word, state)
            except Exception:
                break
            if m is None:
                break
            m = str(m)
            if m not in matches:
                matches.append(m)
        if not matches:
            return
        if len(matches) == 1:
            repl = matches[0]
            if not repl.endswith(("/", os.sep)):
                repl += " "          # readline's usual "match is settled" cue
        else:
            common = os.path.commonprefix(matches)
            repl = common if len(common) > len(word) else None
        if repl:
            self.buf[start:self.pos] = list(repl)
            self.pos = start + len(repl)
        if len(matches) > 1:
            self._show_candidates(sorted(matches))

    def _show_candidates(self, matches):
        """Print the candidate list without destroying the box: wipe the three
        box rows, emit the list, then repaint a clean box beneath it."""
        self._w(_HIDE + _UP + "\r" + _ED)
        widest = max(display_width(m) for m in matches) + 2
        per_row = max(1, (self.width - 2) // widest)
        rows = []
        for i in range(0, len(matches), per_row):
            chunk = matches[i:i + per_row]
            cells = "".join(m + " " * (widest - display_width(m)) for m in chunk)
            rows.append("  " + cells.rstrip())
        body = "".join(_fg(_pal("READOUT", _READOUT)) + r + _RST + "\r\n"
                       for r in rows[:_MAX_CANDIDATE_ROWS])
        if len(rows) > _MAX_CANDIDATE_ROWS:
            body += (_fg(_pal("LABEL", _LABEL))
                     + "  … %d matches" % len(matches) + _RST + "\r\n")
        self._w(body)
        self.painted = False
        self._paint_all(initial=True)

    # ── main loop ────────────────────────────────────────────────────────
    def _loop(self):
        while True:
            if self._resized:
                self._resized = False
                self._paint_all()
            kind, value = self._event()

            if kind == "none":
                continue

            if kind == "text":
                self._insert(value)

            elif kind == "paste":
                # Literal insert, controls stripped; an embedded newline ends
                # the line rather than being inserted (a single-line field
                # can't hold it, and silently flattening it would be a lie).
                cut = len(value)
                for nl in ("\r", "\n"):
                    idx = value.find(nl)
                    if idx >= 0:
                        cut = min(cut, idx)
                self._insert(value[:cut])
                if cut < len(value):
                    # A multi-line paste is a queue of commands, not one
                    # command plus discarded text. Everything after the first
                    # newline is handed to the module-level pending queue so
                    # the following read_line() calls consume the remaining
                    # lines in order, the way a shell treats a pasted script.
                    # Dropping them silently lost real user input.
                    rest = value[cut:].lstrip("\r\n")
                    if rest:
                        _queue_pending_lines(rest)
                    return self._submit()

            elif kind == "key":
                if value == "submit":
                    return self._submit()
                if value == "interrupt":
                    raise KeyboardInterrupt()
                if value == "eof-delete":
                    if not self.buf:
                        raise EOFError()
                    self._delete()          # readline convention
                elif value == "backspace":
                    self._backspace()
                elif value == "delete":
                    self._delete()
                elif value == "left":
                    self.pos = max(0, self.pos - 1)
                elif value == "right":
                    self.pos = min(len(self.buf), self.pos + 1)
                elif value == "word-left":
                    self.pos = self._word_start(self.pos)
                elif value == "word-right":
                    self.pos = self._word_end(self.pos)
                elif value == "home":
                    self.pos = 0
                elif value == "end":
                    self.pos = len(self.buf)
                elif value == "kill-start":
                    del self.buf[:self.pos]
                    self.pos = 0
                elif value == "kill-end":
                    del self.buf[self.pos:]
                elif value == "kill-word":
                    start = self._word_start(self.pos)
                    del self.buf[start:self.pos]
                    self.pos = start
                elif value == "hist-prev":
                    self._hist_prev()
                elif value == "hist-next":
                    self._hist_next()
                elif value == "tab":
                    self._complete()
                elif value == "redraw":
                    self._paint_all()

            self._paint_row()

    def _submit(self):
        line = "".join(self.buf)
        self.pos = len(self.buf)
        self._paint_row()               # freeze the finished line in the box
        self._remember(line)
        return line


# ══════════════════════════════════════════════════════════════════════════
#  SELF-TEST — drives the editor through a real pty with a scripted byte
#  stream. No human at a keyboard, no terminal required.
#      python3 deck_input.py
# ══════════════════════════════════════════════════════════════════════════
def _selftest():                                    # pragma: no cover
    import fcntl
    import pty
    import re
    import struct
    import threading
    import time

    ESC = b"\x1b"
    UP, DOWN, RIGHT, LEFT = ESC + b"[A", ESC + b"[B", ESC + b"[C", ESC + b"[D"
    HOME, END, DEL = ESC + b"[H", ESC + b"[F", ESC + b"[3~"
    HOME2, END2 = ESC + b"[1~", ESC + b"[4~"
    CR = b"\r"
    C_A, C_C, C_D, C_E = b"\x01", b"\x03", b"\x04", b"\x05"
    C_K, C_L, C_U, C_W = b"\x0b", b"\x0c", b"\x15", b"\x17"
    BS, BS8, TAB = b"\x7f", b"\x08", b"\t"

    def paste(payload):
        return ESC + b"[200~" + payload + ESC + b"[201~"

    _ANSI = re.compile(r"\x1b\[[0-9;?<>=]*[A-Za-z~]")
    _FRAME = re.compile(r"\x1b\[2K((?:(?!\x1b\[2K).)*?)\x1b\[(\d+)G", re.S)

    def plain(s):
        return _ANSI.sub("", s).replace("\r", "").replace("\n", "")

    def frames(out):
        # CHA is 1-based on the wire; report the 0-based screen column.
        return [(plain(body), int(col) - 1) for body, col in _FRAME.findall(out)]

    def last_frame(out, back=1):
        found = frames(out)
        return found[-back] if len(found) >= back else ("", 0)

    def attrs(fd):
        """tty attributes with PENDIN masked out — macOS ORs that kernel
        status bit in on tcsetattr when input is queued; it is not something
        we ever set, so it would make an honest restore look like a leak."""
        a = termios.tcgetattr(fd)
        a[3] &= ~getattr(termios, "PENDIN", 0)
        return a

    def set_winsize(fd, rows, cols):
        try:
            fcntl.ioctl(fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except Exception:
            pass

    def drive(script, history=None, completer=None, cols=80):
        """Run one edit in THIS (main) thread — so the SIGWINCH self-pipe is
        actually installed — while a worker feeds the scripted bytes."""
        os.environ["COLUMNS"] = str(cols)
        master, slave = pty.openpty()
        set_winsize(slave, 24, cols)
        chunks = []
        done = threading.Event()

        def drain():
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data)

        def feed():
            time.sleep(0.10)
            for item in script:
                if done.is_set():
                    break
                try:
                    if callable(item):
                        item()
                    else:
                        os.write(master, item)
                except OSError:
                    break
                time.sleep(0.05)
            if not done.wait(2.5):
                # Never let a bug hang the suite: kill the line, then EOF.
                try:
                    os.write(master, b"\x15\x04")
                except OSError:
                    pass

        dt = threading.Thread(target=drain, daemon=True)
        ft = threading.Thread(target=feed, daemon=True)
        dt.start()
        ft.start()

        before = attrs(slave)
        result = {"line": None, "exc": None, "restored": None}
        try:
            editor = _Editor(slave, slave, session={"caret": "idle"},
                             completer=completer, history=history)
            result["line"] = editor.run()
        except BaseException as exc:
            result["exc"] = exc
        done.set()
        try:
            result["restored"] = (attrs(slave) == before)
        except Exception:
            result["restored"] = None
        ft.join(timeout=3)
        time.sleep(0.08)                   # let drain collect the tail bytes
        # Close the SLAVE first: that EOFs the master read so the drain thread
        # unblocks. Closing an fd another thread is blocked reading deadlocks
        # on macOS, so the order here is load-bearing.
        try:
            os.close(slave)
        except OSError:
            pass
        dt.join(timeout=2)
        try:
            os.close(master)
        except OSError:
            pass
        result["out"] = b"".join(chunks).decode("utf-8", "replace")
        return result

    passed = []
    failed = []

    def check(name, ok, detail=""):
        (passed if ok else failed).append(name)
        print("  %s  %-34s %s" % ("PASS" if ok else "FAIL", name, detail))

    def stub_completer(text, state):
        options = [c for c in ("/scan", "/scandeep", "/deep", "/doctor")
                   if c.startswith(text)]
        return options[state] if state < len(options) else None

    print()
    print("CYPHEX deck_input self-test — scripted pty, no human input")
    print("=" * 72)
    print("terminal_ui:", "loaded" if ui else "MISSING",
          "| supported() here:", supported(), "(stdout is a pipe → fallback)")
    print("-" * 72)

    r = drive([b"scan /tmp/target", CR])
    check("plain typing", r["line"] == "scan /tmp/target", repr(r["line"]))
    check("tty restored after Enter", r["restored"] is True)

    frame, curcol = last_frame(r["out"])
    check("box row is exactly width cells", display_width(frame) == 80,
          "width=%d" % display_width(frame))
    check("left wall + armed caret", frame.startswith("│ ⊕ cx ▸ "), repr(frame[:9]))
    check("RIGHT WALL closed while typing", frame.endswith("│"), repr(frame[-4:]))
    check("top+bottom walls painted",
          "╭" in r["out"] and "╮" in r["out"]
          and "╰" in r["out"] and "╯" in r["out"])
    check("cursor parked inside the field",
          curcol == 9 + display_width("scan /tmp/target"),
          "column=%d" % curcol)
    print("       rendered row: %r" % frame)

    r = drive([b"scanx", BS, CR])
    check("backspace 0x7f", r["line"] == "scan", repr(r["line"]))
    r = drive([b"scanx", BS8, CR])
    check("backspace 0x08", r["line"] == "scan", repr(r["line"]))

    r = drive([b"san", LEFT, LEFT, b"c", CR])
    check("mid-line insert via arrows", r["line"] == "scan", repr(r["line"]))

    r = drive([b"abc", HOME, DEL, CR])
    check("Home + Delete (ESC[3~)", r["line"] == "bc", repr(r["line"]))
    r = drive([b"abc", HOME2, b"X", END2, b"Z", CR])
    check("ESC[1~ / ESC[4~ home+end", r["line"] == "XabcZ", repr(r["line"]))

    r = drive([b"world", C_A, b"hello ", C_E, b"!", CR])
    check("Ctrl+A / Ctrl+E", r["line"] == "hello world!", repr(r["line"]))

    r = drive([b"junk", C_U, b"clean", CR])
    check("Ctrl+U kill to start", r["line"] == "clean", repr(r["line"]))

    r = drive([b"keepdrop", C_A, RIGHT * 4, C_K, CR])
    check("Ctrl+K kill to end", r["line"] == "keep", repr(r["line"]))

    r = drive([b"/scan /tmp/foo", C_W, CR])
    check("Ctrl+W delete prev word", r["line"] == "/scan ", repr(r["line"]))

    r = drive([b"abc", C_L, CR])
    check("Ctrl+L redraw keeps buffer", r["line"] == "abc", repr(r["line"]))

    r = drive([UP, UP, CR], history=["/scan a", "/deep b"])
    check("history Up x2 (oldest)", r["line"] == "/scan a", repr(r["line"]))
    r = drive([UP, UP, DOWN, CR], history=["/scan a", "/deep b"])
    check("history Up/Down", r["line"] == "/deep b", repr(r["line"]))
    r = drive([UP, b"!", CR], history=["/scan a", "/deep b"])
    check("recalled line is editable", r["line"] == "/deep b!", repr(r["line"]))
    hist = ["/scan a", "/deep b"]
    r = drive([b"/new cmd", CR], history=hist)
    check("history appended on submit",
          hist == ["/scan a", "/deep b", "/new cmd"], repr(hist))
    records = [{"cmd": "/scan"}]
    r = drive([b"x", CR], history=records)
    check("record-shaped history left alone", records == [{"cmd": "/scan"}])

    r = drive([b"/dee", TAB, CR], completer=stub_completer)
    check("Tab unique match", r["line"] == "/deep ", repr(r["line"]))

    r = drive([b"/sca", TAB, CR], completer=stub_completer)
    ok = (r["line"] == "/scan" and "/scandeep" in r["out"]
          and r["out"].count("╭") >= 2)
    check("Tab common prefix + candidates", ok, repr(r["line"]))
    frame, _ = last_frame(r["out"])
    check("box intact after candidates",
          frame.startswith("│ ⊕ cx ▸ /scan") and frame.endswith("│"), repr(frame[:22]))

    r = drive([paste(b"/scan /etc\x07\x1b"), CR])
    check("bracketed paste (controls stripped)",
          r["line"] == "/scan /etc", repr(r["line"]))
    check("bracketed paste enabled+disabled",
          "\x1b[?2004h" in r["out"] and "\x1b[?2004l" in r["out"])

    r = drive([paste(b"/scan /tmp\ndropped")])
    check("paste newline ends the line", r["line"] == "/scan /tmp", repr(r["line"]))

    r = drive([b"h\xc3", b"\xa9llo", CR])
    check("multi-byte UTF-8 split across reads",
          r["line"] == "héllo", repr(r["line"]))

    r = drive(["扫描 report".encode(), CR])
    frame, curcol = last_frame(r["out"])
    check("wide CJK buffer", r["line"] == "扫描 report", repr(r["line"]))
    check("wide CJK keeps wall aligned",
          display_width(frame) == 80 and frame.endswith("│"),
          "cells=%d cursor=%d" % (display_width(frame), curcol))
    print("       rendered row: %r" % frame)

    r = drive([b"x" * 200, CR])
    frame, curcol = last_frame(r["out"])
    check("horizontal scroll: no overflow",
          display_width(frame) == 80 and frame.endswith("│"),
          "cells=%d" % display_width(frame))
    check("truncation indicator shown", "‹" in frame, repr(frame[8:12]))
    r2 = drive([b"y" * 200, HOME, CR])
    f2, c2 = last_frame(r2["out"], back=2)      # frame at Home, pre-submit
    check("indicator flips at line start",
          "›" in f2 and "‹" not in f2 and c2 == 10,
          "%r cursor=%d" % (f2[-6:], c2))

    r = drive([b"\x1b[>1;2c", b"\x1bOQ", b"\x1b[999;999R", b"ok", CR])
    check("unknown escapes consumed, not inserted",
          r["line"] == "ok", repr(r["line"]))

    def resize():
        os.environ["COLUMNS"] = "60"
        os.kill(os.getpid(), signal.SIGWINCH)

    r = drive([b"abc", resize, CR])
    frame, _ = last_frame(r["out"])
    check("SIGWINCH resize repaint",
          r["line"] == "abc" and display_width(frame) == 60,
          "cells=%d" % display_width(frame))
    os.environ["COLUMNS"] = "80"

    r = drive([b"abc", C_C])
    check("Ctrl+C raises KeyboardInterrupt",
          isinstance(r["exc"], KeyboardInterrupt), type(r["exc"]).__name__)
    check("tty restored after Ctrl+C", r["restored"] is True)

    r = drive([C_D])
    check("Ctrl+D on empty raises EOFError",
          isinstance(r["exc"], EOFError), type(r["exc"]).__name__)
    check("tty restored after Ctrl+D", r["restored"] is True)
    check("cursor re-shown on exit", r["out"].rstrip().endswith("\x1b[0m")
          and "\x1b[?25h" in r["out"])

    r = drive([b"abc", C_A, C_D, CR])
    check("Ctrl+D non-empty deletes under cursor",
          r["line"] == "bc", repr(r["line"]))

    print("-" * 72)
    print("  %d passed, %d failed" % (len(passed), len(failed)))
    if failed:
        print("  FAILED: " + ", ".join(failed))
    print()
    return 1 if failed else 0


if __name__ == "__main__":                          # pragma: no cover
    if termios is None:
        print("deck_input self-test requires POSIX termios/tty.")
        raise SystemExit(1)
    raise SystemExit(_selftest())
