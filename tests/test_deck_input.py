"""pty-driven keystroke tests for the CYPHEX deck line editor (`deck_input`).

WHY THIS FILE EXISTS
--------------------
The CYPHEX REPL draws its input field as a box. Under plain `input()`/readline
the box is drawn *open*: `terminal_ui.deck_input_box_top()` paints the top rule
and `deck_prompt()` paints the left wall, but the right wall and the bottom wall
are deliberately omitted while typing — readline redraws the input line and
clears to end-of-line on every edit, wiping anything painted at a fixed right
column. `deck_input_box_top`'s own docstring says so. The field therefore looks
unbounded until Enter is pressed, at which point the closed box appears.

`deck_input.read_line()` owns the line editing (termios raw mode + hand-rolled
key decoding) precisely so the box can be *closed while typing*. That is the
defect being fixed, so this suite asserts on two things at once:

  1. the string `read_line()` returns for a scripted keystroke sequence, and
  2. the bytes it painted to the terminal, replayed through a small ANSI screen
     emulator so claims like "the right wall sits at a fixed column" are checked
     against a real rendered grid rather than against a regex on escape codes.

Every test drives a *real* pty: the child is a fresh interpreter whose stdin,
stdout and stderr are a pty slave with a known TIOCSWINSZ window size, so the
editor sees an honest terminal (isatty(), a width, a line discipline) and this
process feeds it honest keystroke bytes.

The whole module skips when `deck_input` is absent or when the platform has no
pty/termios, so it is safe to land before the implementation does.
"""

from __future__ import annotations

import importlib.util
import json
import os
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ── platform / dependency guards ──────────────────────────────────────────────
try:
    import fcntl
    import pty
    import termios

    _PTY_OK = True
    _PTY_WHY = ""
except Exception as exc:  # pragma: no cover - Windows / stripped builds
    fcntl = termios = None  # type: ignore[assignment]
    _PTY_OK = False
    _PTY_WHY = f"pty/termios unavailable: {exc!r}"


def _deck_input_present() -> bool:
    try:
        return importlib.util.find_spec("deck_input") is not None
    except Exception:
        return False


_HAVE_DECK_INPUT = _deck_input_present()

pytestmark = [
    pytest.mark.skipif(
        not _PTY_OK or sys.platform == "win32",
        reason=_PTY_WHY or "pty-driven terminal tests need a POSIX pty",
    ),
    pytest.mark.skipif(
        not _HAVE_DECK_INPUT,
        reason=(
            "deck_input.py not present yet — the pty line-editor suite is "
            "written against read_line(session, *, completer, history, console)"
        ),
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
#  Keystroke vocabulary
# ══════════════════════════════════════════════════════════════════════════════
ENTER = b"\r"
BACKSPACE = b"\x7f"          # what terminals actually send for the Backspace key
LEFT = b"\x1b[D"
RIGHT = b"\x1b[C"
UP = b"\x1b[A"
DOWN = b"\x1b[B"
DELETE = b"\x1b[3~"
TAB = b"\t"
CTRL_A = b"\x01"
CTRL_C = b"\x03"
CTRL_D = b"\x04"
CTRL_E = b"\x05"
CTRL_K = b"\x0b"
CTRL_U = b"\x15"
CTRL_W = b"\x17"

# Home/End have three encodings in the wild and a terminal editor is expected to
# decode all three: xterm normal-cursor mode, xterm application mode, and the
# VT220/linux-console numeric form.
HOME_KEYS = {"csi_H": b"\x1b[H", "ss3_OH": b"\x1bOH", "vt_1tilde": b"\x1b[1~"}
END_KEYS = {"csi_F": b"\x1b[F", "ss3_OF": b"\x1bOF", "vt_4tilde": b"\x1b[4~"}

PASTE_START = b"\x1b[200~"
PASTE_END = b"\x1b[201~"


def paste(payload: bytes) -> bytes:
    """A bracketed-paste burst, exactly as a terminal delivers one."""
    return PASTE_START + payload + PASTE_END


# Glyphs terminal_ui uses for the field. Unicode forms are the default; the "+"
# / "-" / "|" forms are what _ascii_mode() falls back to.
VBARS = ("│", "|")                     # │
TOP_CORNERS = ("╭", "╮", "+")     # ╭ ╮
BOT_CORNERS = ("╰", "╯", "+")     # ╰ ╯
RULE_FILL = ("─", "-")                 # ─


# ══════════════════════════════════════════════════════════════════════════════
#  Minimal ANSI screen emulator
# ══════════════════════════════════════════════════════════════════════════════
def _char_width(ch: str) -> int:
    """Display cells a character occupies (0 for combining, 2 for wide)."""
    if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


_CONT = "\x00"   # sentinel filling the right half of a double-width cell


class Screen:
    """A tiny VT100-ish grid: enough of the escape vocabulary that a line editor
    can be replayed onto it and inspected cell by cell.

    `wraps` records every character that had to spill onto the next row because
    the current row was full — i.e. every place the painted output exceeded the
    terminal width. A well-behaved fixed-width input field never wraps.
    """

    def __init__(self, rows: int, cols: int):
        self.rows = rows
        self.cols = cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.row = 0
        self.col = 0
        self.wraps: list[tuple[int, str]] = []
        self._saved = (0, 0)

    # ── plumbing ─────────────────────────────────────────────────────────────
    def _index(self) -> None:
        if self.row + 1 >= self.rows:
            self.grid.pop(0)
            self.grid.append([" "] * self.cols)
        else:
            self.row += 1

    def _reverse_index(self) -> None:
        if self.row == 0:
            self.grid.pop()
            self.grid.insert(0, [" "] * self.cols)
        else:
            self.row -= 1

    def _set(self, r: int, c: int, ch: str, w: int) -> None:
        self.grid[r][c] = ch
        if w == 2 and c + 1 < self.cols:
            self.grid[r][c + 1] = _CONT

    def put(self, ch: str) -> None:
        w = _char_width(ch)
        if w == 0:
            return
        if self.col + w > self.cols:
            self.wraps.append((self.row, ch))
            self._index()
            self.col = 0
        self._set(self.row, self.col, ch, w)
        self.col += w

    # ── escape handling ──────────────────────────────────────────────────────
    def feed(self, data) -> "Screen":
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8", "replace")
        i, n = 0, len(data)
        while i < n:
            ch = data[i]
            if ch == "\x1b":
                i = self._escape(data, i)
                continue
            i += 1
            if ch == "\r":
                self.col = 0
            elif ch == "\n":
                self._index()
            elif ch == "\b":
                self.col = max(0, self.col - 1)
            elif ch == "\t":
                self.col = min(self.cols - 1, ((self.col // 8) + 1) * 8)
            elif ord(ch) < 32 or ch == "\x7f":
                pass
            else:
                self.put(ch)
        return self

    def _escape(self, data: str, i: int) -> int:
        n = len(data)
        if i + 1 >= n:
            return n
        c = data[i + 1]
        if c == "[":
            j = i + 2
            params = ""
            while j < n and (data[j].isdigit() or data[j] in ";?<>=! "):
                params += data[j]
                j += 1
            if j >= n:
                return n
            final = data[j]
            self._csi(params, final)
            return j + 1
        if c == "]":                                  # OSC … BEL / ST
            j = i + 2
            while j < n:
                if data[j] == "\x07":
                    return j + 1
                if data[j] == "\x1b" and j + 1 < n and data[j + 1] == "\\":
                    return j + 2
                j += 1
            return n
        if c in "()#%":                               # charset designators
            return i + 3
        if c == "7":
            self._saved = (self.row, self.col)
            return i + 2
        if c == "8":
            self.row, self.col = self._saved
            return i + 2
        if c == "M":
            self._reverse_index()
            return i + 2
        if c == "D":
            self._index()
            return i + 2
        if c == "E":
            self._index()
            self.col = 0
            return i + 2
        return i + 2

    def _csi(self, params: str, final: str) -> None:
        if "?" in params or "<" in params or ">" in params:
            return                                    # private modes: no-ops here
        nums = [int(p) if p.strip().isdigit() else 0
                for p in params.split(";")] if params else []

        def p(k: int, default: int = 1) -> int:
            v = nums[k] if k < len(nums) else 0
            return v or default

        mode = nums[0] if nums else 0
        if final == "A":
            self.row = max(0, self.row - p(0))
        elif final == "B":
            self.row = min(self.rows - 1, self.row + p(0))
        elif final == "C":
            self.col = min(self.cols - 1, self.col + p(0))
        elif final == "D":
            self.col = max(0, self.col - p(0))
        elif final == "E":
            self.row = min(self.rows - 1, self.row + p(0))
            self.col = 0
        elif final == "F":
            self.row = max(0, self.row - p(0))
            self.col = 0
        elif final in ("G", "`"):
            self.col = min(self.cols - 1, max(0, p(0) - 1))
        elif final == "d":
            self.row = min(self.rows - 1, max(0, p(0) - 1))
        elif final in ("H", "f"):
            self.row = min(self.rows - 1, max(0, p(0) - 1))
            self.col = min(self.cols - 1, max(0, p(1) - 1))
        elif final == "K":
            self._erase_line(mode)
        elif final == "J":
            self._erase_display(mode)
        elif final == "X":
            for c in range(self.col, min(self.cols, self.col + p(0))):
                self.grid[self.row][c] = " "
        elif final == "P":
            k = p(0)
            row = self.grid[self.row]
            del row[self.col:self.col + k]
            row.extend([" "] * (self.cols - len(row)))
        elif final == "@":
            k = p(0)
            row = self.grid[self.row]
            for _ in range(k):
                row.insert(self.col, " ")
            del row[self.cols:]
        elif final == "L":
            for _ in range(p(0)):
                self.grid.insert(self.row, [" "] * self.cols)
                self.grid.pop()
        elif final == "M":
            for _ in range(p(0)):
                self.grid.pop(self.row)
                self.grid.append([" "] * self.cols)
        elif final == "s":
            self._saved = (self.row, self.col)
        elif final == "u":
            self.row, self.col = self._saved
        # m (SGR), r, h, l, n, t … deliberately ignored

    def _erase_line(self, mode: int) -> None:
        row = self.grid[self.row]
        if mode == 0:
            for c in range(self.col, self.cols):
                row[c] = " "
        elif mode == 1:
            for c in range(0, min(self.col + 1, self.cols)):
                row[c] = " "
        else:
            self.grid[self.row] = [" "] * self.cols

    def _erase_display(self, mode: int) -> None:
        if mode == 0:
            self._erase_line(0)
            for r in range(self.row + 1, self.rows):
                self.grid[r] = [" "] * self.cols
        elif mode == 1:
            self._erase_line(1)
            for r in range(0, self.row):
                self.grid[r] = [" "] * self.cols
        else:
            self.grid = [[" "] * self.cols for _ in range(self.rows)]

    # ── inspection ───────────────────────────────────────────────────────────
    def row_text(self, r: int) -> str:
        return "".join(c for c in self.grid[r] if c != _CONT).rstrip()

    def first_content_col(self, r: int):
        for c, cell in enumerate(self.grid[r]):
            if cell not in (" ", _CONT):
                return c
        return None

    def last_content_col(self, r: int):
        for c in range(self.cols - 1, -1, -1):
            if self.grid[r][c] != " ":
                return c
        return None

    def input_rows(self) -> list[int]:
        """Rows whose first painted cell is the field's left wall."""
        out = []
        for r in range(self.rows):
            c = self.first_content_col(r)
            if c is not None and self.grid[r][c] in VBARS:
                out.append(r)
        return out

    def input_row(self):
        rows = self.input_rows()
        return rows[-1] if rows else None

    def rule_rows(self, corners) -> list[int]:
        """Rows that are a full horizontal rule with the given corner pair."""
        out = []
        left, right = corners[0], corners[1]
        for r in range(self.rows):
            fc = self.first_content_col(r)
            lc = self.last_content_col(r)
            if fc is None or lc is None or lc - fc < 3:
                continue
            if self.grid[r][fc] != left or self.grid[r][lc] != right:
                continue
            middle = self.grid[r][fc + 1:lc]
            if middle and all(m in RULE_FILL for m in middle):
                out.append(r)
        return out

    def right_wall_col(self, r: int):
        """Column of the field's right wall on row `r`, or None if absent."""
        if r is None:
            return None
        lc = self.last_content_col(r)
        if lc is None:
            return None
        return lc if self.grid[r][lc] in VBARS else None

    def dump(self) -> str:
        lines = []
        for r in range(self.rows):
            t = self.row_text(r)
            if t:
                lines.append(f"{r:>3} |{t}|")
        lines.append(f"cursor=({self.row},{self.col}) size={self.rows}x{self.cols}"
                     f" wraps={len(self.wraps)}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  The pty harness
# ══════════════════════════════════════════════════════════════════════════════
_CHILD_SRC = r'''
import json, os, sys

cfg = json.load(open(sys.argv[1]))
sys.path.insert(0, cfg["root"])

import termios, fcntl
try:
    # start_new_session=True made us a session leader with no controlling tty;
    # claim the pty so the editor sees a fully normal terminal.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
except Exception:
    pass

out = {"status": "?", "line": None, "exc": None, "error": None,
       "supported": None, "attr_before": None, "attr_after": None}


def norm(attr):
    ifl, ofl, cfl, lfl, isp, osp, cc = attr
    ncc = [c.hex() if isinstance(c, (bytes, bytearray)) else int(c) for c in cc]
    return [ifl, ofl, cfl, lfl, isp, osp, ncc]


def finish():
    try:
        sys.stdout.flush()
    except Exception:
        pass
    with open(cfg["result"], "w") as fh:
        json.dump(out, fh)
        fh.flush()
        os.fsync(fh.fileno())


try:
    import deck_input
except BaseException as e:
    out["status"] = "missing"
    out["error"] = "%s: %s" % (type(e).__name__, e)
    finish()
    sys.exit(0)

try:
    out["supported"] = bool(deck_input.supported())
except BaseException as e:
    out["error"] = "supported() raised %s: %s" % (type(e).__name__, e)

completer = None
if cfg.get("completions") is not None:
    _words = sorted(cfg["completions"])

    class _StubCompleter(object):
        """Serves both plausible protocols: readline's (text, state) and the
        simpler (text) -> list. Whichever deck_input calls, it gets answers."""
        words = _words

        def __call__(self, text, state=None):
            opts = [w for w in self.words if w.startswith(text)]
            if state is None:
                return opts
            try:
                return opts[state]
            except IndexError:
                return None

        def complete(self, text, state=None):
            return self(text, state)

    completer = _StubCompleter()

history = list(cfg["history"]) if cfg.get("history") is not None else None

try:
    out["attr_before"] = norm(termios.tcgetattr(0))
except Exception as e:
    out["error"] = "tcgetattr(before) failed: %r" % (e,)

try:
    line = deck_input.read_line(cfg.get("session"),
                                completer=completer,
                                history=history)
    out["status"] = "ok"
    out["line"] = line
except KeyboardInterrupt:
    out["status"] = "exc"
    out["exc"] = "KeyboardInterrupt"
except EOFError:
    out["status"] = "exc"
    out["exc"] = "EOFError"
except BaseException as e:
    import traceback
    out["status"] = "exc"
    out["exc"] = type(e).__name__
    out["error"] = traceback.format_exc()[-1500:]

try:
    out["attr_after"] = norm(termios.tcgetattr(0))
except Exception as e:
    out["error"] = (out["error"] or "") + " tcgetattr(after) failed: %r" % (e,)

finish()
'''


@dataclass
class EditorRun:
    """Everything one scripted `read_line()` session produced."""
    line: str | None
    status: str
    exc: str | None
    error: str | None
    supported: bool | None
    attr_before: list | None
    attr_after: list | None
    attr_during: list | None
    parent_attr_before: list | None
    parent_attr_after: list | None
    initial: bytes
    chunks: list[bytes]
    exit_code: int | None
    timed_out: bool
    cols: int
    rows: int
    keys: list[bytes] = field(default_factory=list)

    @property
    def output(self) -> bytes:
        return self.initial + b"".join(self.chunks)

    def screen(self, upto: int | None = None) -> Screen:
        """Replay the paint. `upto=k` stops after the k-th keystroke group, so
        `upto=len(keys)-1` is 'the instant before Enter was pressed'."""
        scr = Screen(self.rows, self.cols)
        scr.feed(self.initial)
        for chunk in (self.chunks if upto is None else self.chunks[:upto]):
            scr.feed(chunk)
        return scr

    def diag(self, upto: int | None = None) -> str:
        return (
            f"\nstatus={self.status!r} line={self.line!r} exc={self.exc!r}"
            f" exit={self.exit_code} timed_out={self.timed_out}"
            f"\nchild error: {self.error}"
            f"\n--- rendered screen ---\n{self.screen(upto).dump()}"
            f"\n--- raw bytes (last 400) ---\n{self.output[-400:]!r}"
        )


_PENDIN = getattr(termios, "PENDIN", 0) if _PTY_OK else 0


def _settings(attr):
    """termios attributes with the kernel's own status bits masked out.

    PENDIN is not a setting the editor controls: BSD/macOS sets it in lflag
    whenever a process switches the tty back out of non-canonical mode, so it
    turns up even after a textbook-correct save/restore. Verified with a
    standalone probe that does nothing but tcgetattr, clear ICANON|ECHO|ISIG,
    read one line and tcsetattr the saved value back — it too returns with
    lflag ^ saved == PENDIN. Masking exactly that one bit (and nothing else)
    keeps this assertion byte-exact about everything the editor is responsible
    for, including every ECHO/ICANON/ISIG/IEXTEN bit and the whole cc array.
    """
    a = list(attr)
    a[3] = a[3] & ~_PENDIN
    return a


def _norm_attr(attr):
    ifl, ofl, cfl, lfl, isp, osp, cc = attr
    ncc = [c.hex() if isinstance(c, (bytes, bytearray)) else int(c) for c in cc]
    return [ifl, ofl, cfl, lfl, isp, osp, ncc]


def _tcget(*fds):
    """termios attributes from the first fd that will answer.

    The master is tried first on purpose: macOS revokes a pty once the session
    leader that claimed it as a controlling terminal exits, which invalidates
    the parent's *slave* fd, while the master keeps answering and reports the
    same attributes (verified: clearing ECHO on the slave is visible through
    the master).
    """
    for fd in fds:
        try:
            return _norm_attr(termios.tcgetattr(fd))
        except Exception:
            continue
    return None


def _drain(master: int, idle: float = 0.09, cap: float = 2.0) -> bytes:
    """Read until the child goes quiet for one `idle` window (or `cap` elapses)."""
    buf = bytearray()
    deadline = time.monotonic() + cap
    while time.monotonic() < deadline:
        try:
            ready, _, _ = select.select([master], [], [], idle)
        except (OSError, ValueError):
            break
        if not ready:
            break
        try:
            data = os.read(master, 65536)
        except OSError:
            break
        if not data:
            break
        buf += data
    return bytes(buf)


def _wait_first_paint(master: int, timeout: float = 8.0) -> bytes:
    """Block until the editor has painted something, then drain that paint.

    This is the readiness handshake: the first paint means read_line() is past
    its termios setup, so keystrokes fed afterwards cannot be swallowed by the
    line discipline or echoed back before raw mode engaged.
    """
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ready, _, _ = select.select([master], [], [], 0.05)
        except (OSError, ValueError):
            break
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if data:
                buf += data
                break
    buf += _drain(master)
    return bytes(buf)


def run_editor(
    keys,
    *,
    cols: int = 80,
    rows: int = 24,
    session=None,
    completions=None,
    history=None,
    timeout: float = 20.0,
    probe_after: int | None = None,
    idle: float = 0.09,
    cap: float = 2.0,
) -> EditorRun:
    """Drive `deck_input.read_line()` in a child process over a real pty.

    `keys` is a list of byte strings; each element is written as one burst and
    drained separately, so `EditorRun.chunks` lines up one-to-one with the
    keystroke script and the paint can be replayed keystroke by keystroke.

    `probe_after=k` snapshots the *slave's* termios from this process after the
    k-th burst — i.e. while read_line() is still running — which is how the
    raw-mode assertion observes the terminal mid-flight.

    The child is always reaped: on timeout its whole process group is SIGKILLed
    so a hung editor fails one test instead of wedging pytest.
    """
    keys = [bytes(k) for k in keys]
    master, slave = pty.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    parent_attr_before = _tcget(master, slave)

    fd, cfg_path = tempfile.mkstemp(prefix="deckcfg_", suffix=".json")
    os.close(fd)
    fd, res_path = tempfile.mkstemp(prefix="deckres_", suffix=".json")
    os.close(fd)
    fd, src_path = tempfile.mkstemp(prefix="deckchild_", suffix=".py")
    os.close(fd)

    Path(src_path).write_text(_CHILD_SRC, encoding="utf-8")
    Path(cfg_path).write_text(
        json.dumps({
            "root": str(REPO_ROOT),
            "result": res_path,
            "session": session if session is not None else {"caret": "idle"},
            "completions": completions,
            "history": history,
        }),
        encoding="utf-8",
    )

    env = dict(os.environ)
    env.update({
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "TERM": "xterm-256color",
        "COLORTERM": "truecolor",
        "COLUMNS": str(cols),      # Rich and shutil both honour these; keeping
        "LINES": str(rows),        # them in step with TIOCSWINSZ makes every
        "LC_ALL": "en_US.UTF-8",   # width probe agree on one number.
        "LANG": "en_US.UTF-8",
    })
    for noisy in ("NO_COLOR", "CYPHEX_ASCII", "TERM_PROGRAM"):
        env.pop(noisy, None)

    proc = None
    initial = b""
    chunks: list[bytes] = []
    attr_during = None
    timed_out = False
    try:
        proc = subprocess.Popen(
            [sys.executable, src_path, cfg_path],
            stdin=slave, stdout=slave, stderr=slave,
            cwd=str(REPO_ROOT), env=env,
            start_new_session=True, close_fds=True,
        )

        initial = _wait_first_paint(master)

        for idx, key in enumerate(keys):
            if proc.poll() is not None:
                chunks.append(b"")
                continue
            try:
                os.write(master, key)
            except OSError:
                chunks.append(b"")
                continue
            chunks.append(_drain(master, idle=idle, cap=cap))
            if probe_after is not None and idx == probe_after:
                attr_during = _tcget(master, slave)

        deadline = time.monotonic() + timeout
        tail = bytearray()
        while True:
            if proc.poll() is not None:
                tail += _drain(master, idle=0.05, cap=0.5)
                break
            if time.monotonic() > deadline:
                timed_out = True
                break
            try:
                ready, _, _ = select.select([master], [], [], 0.05)
            except (OSError, ValueError):
                break
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if data:
                    tail += data
        if tail:
            if chunks:
                chunks[-1] += bytes(tail)
            else:
                initial += bytes(tail)
    finally:
        if proc is not None and proc.poll() is None:
            for sig in (signal.SIGKILL,):
                try:
                    os.killpg(os.getpgid(proc.pid), sig)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                proc.wait(timeout=5)
            except Exception:  # pragma: no cover - child refused to die
                pass

        parent_attr_after = _tcget(master, slave)

        for f in (master, slave):
            try:
                os.close(f)
            except Exception:
                pass

        payload = {}
        try:
            raw = Path(res_path).read_text(encoding="utf-8")
            if raw.strip():
                payload = json.loads(raw)
        except Exception:
            payload = {}
        for p in (cfg_path, res_path, src_path):
            try:
                os.unlink(p)
            except Exception:
                pass

    if timed_out:
        pytest.fail(
            "deck_input.read_line() never returned — the editor hung after the "
            f"scripted keys {keys!r}. Killed after {timeout}s.\n"
            f"--- rendered screen ---\n"
            f"{Screen(rows, cols).feed(initial + b''.join(chunks)).dump()}"
        )

    return EditorRun(
        line=payload.get("line"),
        status=payload.get("status", "crashed"),
        exc=payload.get("exc"),
        error=payload.get("error"),
        supported=payload.get("supported"),
        attr_before=payload.get("attr_before"),
        attr_after=payload.get("attr_after"),
        attr_during=attr_during,
        parent_attr_before=parent_attr_before,
        parent_attr_after=parent_attr_after,
        initial=initial,
        chunks=chunks,
        exit_code=proc.returncode if proc is not None else None,
        timed_out=timed_out,
        cols=cols,
        rows=rows,
        keys=keys,
    )


def typed(text: str) -> bytes:
    return text.encode("utf-8")


def per_char(text: str) -> list[bytes]:
    """One keystroke burst per character — needed when the paint has to be
    inspected between keystrokes."""
    return [c.encode("utf-8") for c in text]


def _guard(res: EditorRun) -> None:
    """Skip (don't fail) when the module is present but declines this platform;
    fail loudly on anything else that isn't a clean return."""
    if res.status == "missing":
        pytest.skip(f"deck_input import failed in the child: {res.error}")
    if res.supported is False:
        pytest.skip("deck_input.supported() is False on this terminal")


def returned(res: EditorRun) -> str:
    _guard(res)
    assert res.status == "ok", (
        "read_line() did not return a string." + res.diag()
    )
    assert isinstance(res.line, str), f"read_line() returned {type(res.line)}"
    return res.line


def raised(res: EditorRun) -> str:
    _guard(res)
    assert res.status == "exc", (
        "read_line() returned normally where an exception was expected."
        + res.diag()
    )
    return res.exc or ""


# ══════════════════════════════════════════════════════════════════════════════
#  1. Behaviour — asserted on the RETURNED STRING
# ══════════════════════════════════════════════════════════════════════════════
def test_supported_reports_true_on_a_real_pty():
    res = run_editor([typed("x"), ENTER])
    _guard(res)
    assert res.supported is True, (
        "supported() must be True when stdin/stdout are a genuine pty — the "
        "REPL uses it to decide whether to take over line editing." + res.diag()
    )


def test_plain_typing_then_enter():
    res = run_editor([typed("/scan ./src"), ENTER])
    assert returned(res) == "/scan ./src"


def test_backspace_mid_word():
    # "scanx" + BS + "ner"  →  "scanner"
    res = run_editor([typed("scanx"), BACKSPACE, typed("ner"), ENTER])
    assert returned(res) == "scanner"


def test_left_arrow_then_insert():
    # "helo", one Left (cursor between l and o), insert "l"
    res = run_editor([typed("helo"), LEFT, typed("l"), ENTER])
    assert returned(res) == "hello"


@pytest.mark.parametrize("name,key", sorted(HOME_KEYS.items()))
def test_home_then_insert(name, key):
    res = run_editor([typed("world"), key, typed("hello "), ENTER])
    assert returned(res) == "hello world", f"Home encoding {name} ({key!r})"


@pytest.mark.parametrize("name,key", sorted(END_KEYS.items()))
def test_end_then_append(name, key):
    # Ctrl+A first so End has somewhere to travel back from.
    res = run_editor([typed("hello"), CTRL_A, key, typed(" world"), ENTER])
    assert returned(res) == "hello world", f"End encoding {name} ({key!r})"


def test_ctrl_a_and_ctrl_e_movement():
    res = run_editor([typed("world"), CTRL_A, typed("hello "), CTRL_E,
                      typed("!"), ENTER])
    assert returned(res) == "hello world!"


def test_ctrl_u_kills_to_line_start():
    # cursor parked before "world"; Ctrl+U discards everything to its left
    res = run_editor([typed("hello world"), LEFT * 5, CTRL_U, ENTER])
    assert returned(res) == "world"


def test_ctrl_k_kills_to_line_end():
    res = run_editor([typed("hello world"), CTRL_A, RIGHT * 5, CTRL_K, ENTER])
    assert returned(res) == "hello"


def test_ctrl_w_deletes_previous_word():
    res = run_editor([typed("hello world"), CTRL_W, ENTER])
    line = returned(res)
    # unix-word-rubout leaves the separating space behind ("hello "); some
    # editors trim it. Both are fine — swallowing more than one word is not.
    assert line.rstrip() == "hello", f"Ctrl+W produced {line!r}"
    assert "world" not in line


def test_delete_key_removes_char_under_cursor():
    res = run_editor([typed("hello"), CTRL_A, DELETE, ENTER])
    assert returned(res) == "ello"


def test_history_up_recalls_most_recent_entry():
    res = run_editor([UP, ENTER], history=["/scan alpha", "/deep bravo"])
    assert returned(res) == "/deep bravo", (
        "one Up must recall the newest history entry (chronological list, "
        "walked backwards from the end — readline/bash/zsh convention)"
    )


def test_history_up_then_down_restores_draft():
    res = run_editor([typed("draft"), UP, DOWN, ENTER], history=["/scan alpha"])
    assert returned(res) == "draft", (
        "Down after Up must come back to the line being typed, not leave the "
        "recalled entry in the buffer"
    )


def test_tab_completion_unique_match():
    res = run_editor([typed("/benc"), TAB, ENTER], completions=["/benchmark"])
    line = returned(res)
    assert line.rstrip() == "/benchmark", (
        f"a single candidate must complete outright; got {line!r}" + res.diag()
    )


def test_tab_completion_ambiguous_match():
    words = ["/deepscan", "/deepnet"]
    res = run_editor([typed("/dee"), TAB, ENTER], completions=words)
    line = returned(res).rstrip()
    # Either behaviour is defensible for two candidates: extend to the longest
    # common prefix ("/deep"), or cycle onto one full candidate. Doing nothing,
    # or mangling what was typed, is not.
    assert line in {"/deep", *words}, (
        f"ambiguous Tab left the buffer at {line!r}; expected the common "
        f"prefix '/deep' or one of {words}" + res.diag()
    )
    assert line.startswith("/deep"), f"Tab did not advance past {line!r}"


def test_bracketed_paste_inserts_literal_text():
    res = run_editor([paste(b"/scan /var/log"), typed("!"), ENTER])
    assert returned(res) == "/scan /var/log!"


def test_bracketed_paste_containing_a_newline():
    """A newline inside a bracketed paste has two defensible readings and the
    repo has picked one, so this pins the invariants rather than the convention:

      (a) literal data — the paste becomes one line ("alpha bravo!"), which is
          what zsh/bash/prompt_toolkit do; or
      (b) end of line — read_line() returns "alpha" and discards the remainder,
          which is what deck_input currently implements and self-tests.

    Either is fine. What is never fine: leaking the ESC[200~/ESC[201~ markers or
    raw control bytes into the buffer, mangling the first segment, reordering
    the halves, or letting the tail arrive as a *separate* command.
    """
    res = run_editor([paste(b"alpha\nbravo"), typed("!"), ENTER])
    line = returned(res)

    # Unconditional, and the assertion most likely to catch a real bug: the
    # paste framing is protocol, never text.
    for marker in ("\x1b[200~", "\x1b[201~", "[200~", "[201~", "\x1b"):
        assert marker not in line, (
            f"bracketed-paste framing leaked into the buffer as {marker!r}: "
            f"{line!r}" + res.diag()
        )
    assert "\n" not in line and "\r" not in line, (
        f"a raw newline survived into the returned line: {line!r}"
    )

    literal = (line.startswith("alpha") and "bravo" in line
               and line.index("alpha") < line.index("bravo")
               and line.rstrip().endswith("!"))
    ends_at_newline = (line == "alpha")
    assert literal or ends_at_newline, (
        "a multi-line paste produced neither of the two accepted results — "
        f"expected 'alpha' (line ends at the newline) or 'alpha…bravo…!' "
        f"(newline inserted as literal data); got {line!r}" + res.diag()
    )


def test_multibyte_utf8_character_round_trips():
    whole = run_editor([typed("café"), ENTER])
    assert returned(whole) == "café"

    # Same text delivered one byte at a time, which is what a slow link does:
    # the decoder must hold the lead byte until the continuation byte lands.
    split = run_editor([bytes([b]) for b in "café".encode()] + [ENTER])
    assert returned(split) == "café", (
        "a UTF-8 sequence split across reads was mangled" + split.diag()
    )


def test_wide_cjk_character_round_trips():
    res = run_editor([typed("漢字 ok"), ENTER])
    assert returned(res) == "漢字 ok"


def test_typing_past_terminal_width_scrolls_horizontally():
    cols = 40
    long = "".join(str(i % 10) for i in range(90))   # 90 chars into a 40-col field
    res = run_editor([typed(long), ENTER], cols=cols)
    assert returned(res) == long, (
        "the buffer must keep every character typed past the right edge"
        + res.diag()
    )
    scr = res.screen(upto=1)
    assert scr.wraps == [], (
        "the input field wrapped onto another row instead of scrolling "
        f"horizontally within {cols} columns" + res.diag(upto=1)
    )


def test_enter_on_empty_buffer_returns_empty_string():
    res = run_editor([ENTER])
    assert returned(res) == ""


def test_ctrl_c_raises_keyboard_interrupt():
    res = run_editor([typed("half typed"), CTRL_C])
    assert raised(res) == "KeyboardInterrupt", (
        "Ctrl+C must reach the REPL as KeyboardInterrupt so cx.py's handler "
        "can redraw the prompt instead of exiting" + res.diag()
    )


def test_ctrl_d_on_empty_buffer_raises_eof_error():
    res = run_editor([CTRL_D])
    assert raised(res) == "EOFError", (
        "Ctrl+D on an empty line must surface as EOFError — that is cx.py's "
        "quit path" + res.diag()
    )


# ══════════════════════════════════════════════════════════════════════════════
#  2. Appearance — asserted on the PAINTED BYTES
# ══════════════════════════════════════════════════════════════════════════════
def test_headline_input_box_is_closed_while_typing_not_only_after_enter():
    """THE DEFECT THIS FEATURE EXISTS TO FIX.

    Under readline the field is painted open while typing: top rule + left wall
    only, no right wall, no bottom rule, so the input area reads as unbounded
    until Enter closes it. Here the screen is inspected at the instant *before*
    Enter is pressed. It must already show a closed box:

        ╭──────────────────────────────╮
        │ ⊕ cx ▸ /scan ./src           │   ← right wall, present, fixed column
        ╰──────────────────────────────╯   ← bottom wall, present

    If this test fails with "no right wall", the regression is exactly the old
    behaviour coming back.
    """
    cols = 72
    keys = per_char("/scan ./src") + [ENTER]
    res = run_editor(keys, cols=cols)
    returned(res)                                    # editor must still work
    pre_enter = res.screen(upto=len(keys) - 1)       # <- before Enter

    row = pre_enter.input_row()
    assert row is not None, (
        "no input row found: nothing painted the field's left wall while "
        "typing" + res.diag(upto=len(keys) - 1)
    )

    typed_text = pre_enter.row_text(row)
    assert "/scan ./src" in typed_text, (
        f"the typed text is not on the input row (row {row} reads "
        f"{typed_text!r})" + res.diag(upto=len(keys) - 1)
    )

    wall = pre_enter.right_wall_col(row)
    assert wall is not None, (
        "THE DEFECT: no RIGHT WALL on the input row while typing — the field "
        "is still being painted open. Row {} reads {!r}".format(row, typed_text)
        + res.diag(upto=len(keys) - 1)
    )

    tops = pre_enter.rule_rows(TOP_CORNERS)
    assert tops, "no top rule painted" + res.diag(upto=len(keys) - 1)
    top_right = pre_enter.last_content_col(tops[-1])
    assert wall == top_right, (
        f"the right wall sits at column {wall} but the top rule closes at "
        f"column {top_right} — the box is painted crooked"
        + res.diag(upto=len(keys) - 1)
    )
    assert wall == cols - 1, (
        f"the field should span the full terminal ({cols} columns), so the "
        f"right wall belongs at column {cols - 1}, not {wall}"
        + res.diag(upto=len(keys) - 1)
    )

    bottoms = pre_enter.rule_rows(BOT_CORNERS)
    assert bottoms, (
        "THE DEFECT: no BOTTOM WALL while typing — the field is only closed "
        "after Enter" + res.diag(upto=len(keys) - 1)
    )
    assert any(b > row for b in bottoms), (
        f"a bottom rule exists at rows {bottoms} but none of them is below the "
        f"input row ({row}), so the field is not enclosed"
        + res.diag(upto=len(keys) - 1)
    )


def test_right_wall_column_is_constant_across_keystrokes():
    cols = 68
    text = "abcdefgh"
    keys = per_char(text) + [ENTER]
    res = run_editor(keys, cols=cols)
    returned(res)

    seen = []
    for k in range(1, len(text) + 1):
        scr = res.screen(upto=k)
        row = scr.input_row()
        assert row is not None, (
            f"input row vanished after keystroke {k}" + res.diag(upto=k)
        )
        wall = scr.right_wall_col(row)
        assert wall is not None, (
            f"right wall missing after keystroke {k} ({text[:k]!r} typed)"
            + res.diag(upto=k)
        )
        seen.append(wall)

    assert len(set(seen)) == 1, (
        "the right wall drifted while typing — per-keystroke columns were "
        f"{seen}. It must be pinned to a fixed column regardless of how much "
        "text the buffer holds." + res.diag()
    )
    assert seen[0] == cols - 1, f"right wall parked at {seen[0]}, expected {cols - 1}"


def test_wide_cjk_characters_do_not_shift_the_right_wall():
    cols = 64
    ascii_run = run_editor([typed("abcd"), ENTER], cols=cols)
    cjk_run = run_editor([typed("漢字測試"), ENTER], cols=cols)
    returned(ascii_run)
    assert returned(cjk_run) == "漢字測試"

    a_scr, c_scr = ascii_run.screen(upto=1), cjk_run.screen(upto=1)
    a_row, c_row = a_scr.input_row(), c_scr.input_row()
    assert a_row is not None and c_row is not None, (
        "input row missing" + ascii_run.diag(upto=1) + cjk_run.diag(upto=1)
    )
    a_wall = a_scr.right_wall_col(a_row)
    c_wall = c_scr.right_wall_col(c_row)
    assert a_wall is not None and c_wall is not None, (
        "right wall missing in one of the runs" + cjk_run.diag(upto=1)
    )
    assert a_wall == c_wall == cols - 1, (
        "double-width characters moved the right wall: ascii closed at "
        f"{a_wall}, CJK at {c_wall} (both should be {cols - 1}). The field is "
        "measuring characters instead of display cells." + cjk_run.diag(upto=1)
    )
    assert c_scr.wraps == [], (
        "wide characters pushed the field past the right edge"
        + cjk_run.diag(upto=1)
    )


def test_no_painted_line_exceeds_the_terminal_width():
    cols = 46
    text = "/scan " + "z" * 70          # far wider than the field
    keys = per_char("/scan ") + [typed("z" * 70), ENTER]
    res = run_editor(keys, cols=cols)
    assert returned(res) == text

    scr = res.screen()
    assert scr.wraps == [], (
        f"{len(scr.wraps)} character(s) spilled past column {cols - 1} and "
        f"wrapped onto the next row; first offender {scr.wraps[:3]}"
        + res.diag()
    )
    for r in range(scr.rows):
        painted = scr.row_text(r)
        width = sum(_char_width(ch) for ch in painted)
        assert width <= cols, (
            f"row {r} paints {width} display cells into a {cols}-column "
            f"terminal: {painted!r}" + res.diag()
        )


# ══════════════════════════════════════════════════════════════════════════════
#  3. The terminal must be handed back exactly as it was found
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize(
    "label,keys,expect_exc",
    [
        ("enter", [typed("/status"), ENTER], None),
        ("ctrl_c", [typed("/status"), CTRL_C], "KeyboardInterrupt"),
        ("ctrl_d", [CTRL_D], "EOFError"),
    ],
)
def test_termios_restored_byte_for_byte(label, keys, expect_exc):
    """A terminal left in raw mode is the worst regression this feature can
    ship: the user's shell stops echoing and stops handling Ctrl+C. Checked on
    the normal return path and on both exception paths, from inside the child
    *and* independently from the parent."""
    res = run_editor(keys)
    _guard(res)

    if expect_exc is None:
        assert res.status == "ok", "expected a clean return" + res.diag()
    else:
        assert res.exc == expect_exc, (
            f"expected {expect_exc}, saw {res.exc!r}" + res.diag()
        )

    assert res.attr_before is not None and res.attr_after is not None, (
        "child could not read termios attributes" + res.diag()
    )
    assert _settings(res.attr_after) == _settings(res.attr_before), (
        f"[{label}] termios attributes differ after read_line().\n"
        f"before: {res.attr_before}\n after: {res.attr_after}" + res.diag()
    )
    assert res.parent_attr_before is not None and res.parent_attr_after is not None
    assert _settings(res.parent_attr_after) == _settings(res.parent_attr_before), (
        f"[{label}] the pty was left modified as seen from outside the child.\n"
        f"before: {res.parent_attr_before}\n after: {res.parent_attr_after}"
        + res.diag()
    )
    # Spelled out separately so a failure names the bit that matters rather
    # than making the reader diff two long integers.
    for flag in ("ICANON", "ECHO", "ISIG"):
        bit = getattr(termios, flag)
        assert bool(res.attr_after[3] & bit) == bool(res.attr_before[3] & bit), (
            f"[{label}] {flag} was not restored — the terminal is left in raw "
            "mode and the user's shell will stop echoing" + res.diag()
        )


def test_terminal_is_actually_raw_while_read_line_is_active():
    """The mirror image of the restoration test: prove the editor really did
    take the terminal over, so 'restored' isn't trivially true because nothing
    was ever changed."""
    res = run_editor([typed("abc"), ENTER], probe_after=0)
    _guard(res)
    returned(res)
    assert res.attr_during is not None, (
        "could not sample the pty while read_line() was running" + res.diag()
    )
    lflag = res.attr_during[3]
    assert not (lflag & termios.ICANON), (
        "ICANON was still set during read_line(): the kernel line discipline is "
        "still buffering lines, so the editor is not driving the keystrokes"
    )
    assert not (lflag & termios.ECHO), (
        "ECHO was still set during read_line(): the terminal is echoing "
        "keystrokes on top of whatever the editor paints"
    )
