"""Terminal-safety regressions for deck_input's raw-mode editor.

These cover four defects found by an adversarial audit of the first
implementation. Each one is the kind of bug that survives a green test suite
because it only shows up on a path nobody exercises by hand:

  D1  SIGTERM/SIGHUP mid-edit killed the process without unwinding, leaving
      the user's shell in raw mode with no echo. `stty sane` does not fully
      undo it, because it restores the line discipline but sends neither the
      bracketed-paste nor the autowrap reset.
  D2  _enter() ran outside run()'s try/finally, so any failure after
      tty.setraw() succeeded leaked raw mode to the caller.
  D3  OSC/DCS/APC sequence bodies were inserted into the command buffer as
      literal text, contradicting _escape()'s own docstring.
  D4  A multi-line paste silently discarded every line after the first.
"""

import os
import select
import signal
import struct
import sys
import time

import pytest

pty = pytest.importorskip("pty")
termios = pytest.importorskip("termios")
fcntl = pytest.importorskip("fcntl")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pytest.importorskip("deck_input")

ENV = dict(os.environ, TERM="xterm-256color", COLORTERM="truecolor")
ENV.pop("NO_COLOR", None)

LFLAGS = ("ICANON", "ECHO", "ISIG", "IEXTEN")


def _spawn(code, rows=24, cols=80):
    """Run code in a child on a real pty. Returns (pid, master_fd, slave_fd)."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    pid = os.fork()
    if pid == 0:                                    # pragma: no cover - child
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.execve(sys.executable, [sys.executable, "-c", code], ENV)
    return pid, master, slave


def _drain(fd, seconds):
    out = b""
    end = time.time() + seconds
    while time.time() < end:
        try:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if ready:
                out += os.read(fd, 65536)
        except OSError:
            break
    return out


def _reap(pid, master, timeout=6.0):
    status = None
    end = time.time() + timeout
    while time.time() < end:
        _drain(master, 0.05)
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
    hung = status is None
    if hung:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    return status, hung


def _lflags(value):
    return {name for name in LFLAGS if value & getattr(termios, name)}


READ_ONE = (
    "import sys;sys.path.insert(0, %r);import deck_input;"
    "deck_input.read_line({'caret':'idle'})" % REPO
)


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGHUP"])
def test_fatal_signal_restores_termios(signame):
    """D1: the shell must not be left in raw mode when the editor is killed."""
    pid, master, slave = _spawn(READ_ONE)
    try:
        before = termios.tcgetattr(slave)
        _drain(master, 1.4)
        os.write(master, b"half typed")
        _drain(master, 0.5)

        os.kill(pid, getattr(signal, signame))
        status, hung = _reap(pid, master)
        _drain(master, 0.3)
        after = termios.tcgetattr(slave)

        assert not hung, f"{signame} left the editor hung instead of exiting"
        assert os.WIFSIGNALED(status), "process should still die by the signal"
        assert _lflags(after[3]) == _lflags(before[3]), (
            f"{signame} left the tty in raw mode: "
            f"before={sorted(_lflags(before[3]))} after={sorted(_lflags(after[3]))}"
        )
    finally:
        os.close(master)
        os.close(slave)


def test_enter_is_inside_the_try_so_raw_mode_cannot_leak():
    """D2: a failure after setraw() must still run teardown."""
    import inspect

    import deck_input

    src = inspect.getsource(deck_input._Editor.run)
    body = src.split("try:", 1)
    assert len(body) == 2, "run() no longer has a try block"
    assert "self._enter()" not in body[0], (
        "_enter() is called before run()'s try: — a raise after tty.setraw() "
        "would leak raw mode to the caller"
    )
    assert "self._enter()" in body[1]
    assert "finally:" in src and "self._exit()" in src


READ_N = (
    "import sys;sys.path.insert(0, %r);import deck_input\n"
    "out=[]\n"
    "for _ in range(%%d): out.append(deck_input.read_line({'caret':'idle'}))\n"
    "print('RESULT:'+repr(out))" % REPO
)


def _collect(feed, nlines=1):
    pid, master, slave = _spawn(READ_N % nlines)
    try:
        _drain(master, 1.4)
        os.write(master, feed)
        out = _drain(master, 1.8)
        _reap(pid, master, timeout=1.0)
        for line in out.decode("utf-8", "replace").splitlines():
            if "RESULT:" in line:
                return eval(line.split("RESULT:", 1)[1])  # noqa: S307 - our own repr
        return None
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.parametrize("payload,label", [
    (b"\x1b]0;a terminal title\x07ok\r", "OSC"),
    (b"\x1bPsome dcs body\x1b\\ok\r", "DCS"),
    (b"\x1b_apc payload\x1b\\ok\r", "APC"),
])
def test_string_sequence_bodies_are_not_injected_as_text(payload, label):
    """D3: an OSC/DCS/APC body must be eaten whole, not typed into the buffer."""
    assert _collect(payload) == ["ok"], f"{label} body leaked into the buffer"


def test_multiline_paste_keeps_every_line():
    """D4: a pasted block is a queue of commands, not one command plus loss."""
    assert _collect(b"\x1b[200~one\ntwo\nthree\x1b[201~", nlines=3) == \
        ["one", "two", "three"]


def test_pending_queue_drains_in_order_and_is_observable():
    import deck_input

    deck_input._pending_lines.clear()
    deck_input._queue_pending_lines("two\nthree\n\n  \nfour")
    assert deck_input.pending_lines() == 3
    assert deck_input._pending_lines == ["two", "three", "four"]
    deck_input._pending_lines.clear()
