#!/usr/bin/env python3
"""
CYPHEX Mascot Companion — standalone loop script
════════════════════════════════════════════════════════════════════════════
This is the process that runs INSIDE the dedicated companion terminal window
spawned by mascot_companion.open_companion_window() (see that module's
docstring — this script is never launched on its own by anything else in
the codebase). It has no dependency on the CLI process that spawned it: it
just polls a small state file and redraws a frame in place, ANSI-style,
until the window is closed or the user hits Ctrl+C.

Rendering, in preference order:
  1. mascot.render_and_print_state_loop(state_file_path) — the REAL, landed
     integration point. mascot.py exports this: it polls the state file and
     drives the exact same tiered real-pixel-art rendering (Kitty/iTerm2
     inline images, truecolor/256-color half-block art, or the plain Tier-0
     fallback — whichever the companion window's own terminal actually
     supports) that the integrated mascot's background thread uses. Since
     mascot.py always ships in this repo, this layer is always reachable;
     the two layers below only ever fire if `import mascot` itself somehow
     fails (e.g. run outside this repo) or the landed function is removed.
  2. A best-effort import of a pixel/half-block rendering backend exposing
     a *single-state-argument* `render_frame(state: str) -> list[str]`.
     Kept only as a defensive placeholder for some future/alternate
     backend shaped that way — the real, shipped backends
     (mascot_backend_image / mascot_backend_halfblock) take a PIL image +
     target_cols instead, so this layer is expected to no-op against them
     today; that's fine, it just falls through to layer 3.
  3. Reuse the animation frame table directly (mascot_anim.frames_for),
     rendering the raw PIL frames as plain lines — a degraded but
     non-crashing text approximation, not real pixel art. Only reached if
     layer 1 is somehow unavailable.
  4. A tiny built-in plain-text spinner, used only if even mascot.py
     itself somehow can't be imported (e.g. run outside this repo).

Every layer prints with the exact same ANSI cursor-redraw idiom mascot.py's
own render loop uses: hide the cursor once, then repeatedly rewrite the
last frame in place via cursor-up + line-clear, and always restore the
cursor on the way out (hide at start, show in a finally/atexit — never
left hidden, whether we exit via Ctrl+C, the window closing, or a crash).

Usage (normally launched by mascot_companion.py, not run by hand):
    python3 mascot_companion_loop.py [--state-file PATH]
"""

import argparse
import atexit
import os
import signal
import sys
import time

# So `import mascot` (and any future mascot_backend_* module) resolves the
# same way it would from an integrated run, regardless of what directory
# the companion terminal window happens to start in.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

STATE_FILE_DEFAULT = os.path.expanduser("~/.cyphex/mascot_state")
POLL_INTERVAL = 0.3  # seconds — 300ms, per spec
DEFAULT_STATE = "idle"

_cursor_hidden = False


# ── cursor safety: hide once at start, ALWAYS shown again on the way out ──
def _hide_cursor():
    global _cursor_hidden
    try:
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
        _cursor_hidden = True
    except Exception:
        pass


def _show_cursor():
    global _cursor_hidden
    if not _cursor_hidden:
        return
    try:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
    except Exception:
        pass
    _cursor_hidden = False


atexit.register(_show_cursor)


def _handle_terminating_signal(signum, frame):
    # Window-close (SIGHUP) / SIGTERM: raise SystemExit so the normal
    # try/finally cursor-restore path below runs instead of the process
    # dying mid-frame with the cursor left hidden.
    raise SystemExit(0)


for _sig_name in ("SIGHUP", "SIGTERM"):
    try:
        signal.signal(getattr(signal, _sig_name), _handle_terminating_signal)
    except Exception:
        pass  # not available on this platform — best effort only


# ── state file polling ─────────────────────────────────────────────────
def _read_state(path):
    try:
        with open(path, "r") as f:
            line = f.readline().strip()
        return line or DEFAULT_STATE
    except Exception:
        # Missing file, permission error, race with a writer, etc. — the
        # spec calls for defaulting to "idle", not raising.
        return DEFAULT_STATE


# ── renderer selection (defensive, layered — see module docstring) ────
#
# NOTE ON DEFENSIVENESS: mascot_backend_image.py / mascot_backend_halfblock.py
# had not landed at all when this script was first written, so the only
# failure mode anticipated for them was ImportError. In practice they can
# land (or change shape) at any time out from under this script — indeed
# they appeared in this repo, with a *lower-level* rasterizer contract
# (render_frame(img: PIL.Image, target_cols, ...) -> str, driven by a
# future higher-level orchestrator that picks/loads the right PNG for a
# state) rather than the simple render_frame(state: str) this loop expects.
# So every layer below is re-attempted, and re-guarded with a broad
# `except Exception`, on EVERY poll rather than cached once at startup —
# a signature mismatch (TypeError), a partially-implemented module, or any
# other runtime error just falls through to the next layer instead of
# crashing the loop, exactly like a missing module would.
def _render_via_backend(state):
    """Best-effort: use mascot_backend_image / mascot_backend_halfblock's
    render_frame(state) ONLY if a module actually exposes that simple
    single-state-argument shape. Returns None (never raises) if neither
    module is importable, neither exposes a usable render_frame, or
    calling it fails for any reason (e.g. it turns out to require a
    PIL.Image + target_cols instead, as the modules observed at edit time
    do) — that's this function's whole job: never let an evolving/
    not-yet-settled backend contract crash the companion loop."""
    for modname in ("mascot_backend_image", "mascot_backend_halfblock"):
        try:
            mod = __import__(modname)
            fn = getattr(mod, "render_frame", None)
            if not callable(fn):
                continue
            result = fn(state)
        except Exception:
            continue
        if result:
            return result.splitlines() if isinstance(result, str) else list(result)
    return None


def _render_via_mascot_frames(state, tick):
    """Degraded (text, not real pixel art) fallback: reach into the
    animation frame table directly and render each frame's size as a single
    line. Only ever reached if layer 1 (mascot.render_and_print_state_loop)
    is somehow unavailable -- normal runs never get here. None (never
    raises) if the module can't be imported or doesn't expose what we
    expect.

    This used to read `mascot._STATE_FRAMES`, a per-state list mascot.py
    composed itself. mascot.py no longer owns frames -- `mascot_anim` does,
    and it hands them out per (state, width, mode) via `frames_for` -- so
    this layer asks that module instead. `frames_for` degrades an unknown
    state to `idle` on its own, which is exactly what this layer wanted the
    DEFAULT_STATE lookup for."""
    try:
        import mascot_anim as _anim

        frames = _anim.frames_for(state or DEFAULT_STATE)
        if not frames:
            return None
        img = frames[tick % len(frames)]
        return [f"  [{state}] {getattr(img, 'size', '?')} (pixel-art fallback)"]
    except Exception:
        return None


def _render_frame(state, tick):
    """Plain lines to draw for this poll — tries progressively simpler,
    fully-guarded fallbacks; the last one is a hardcoded built-in that
    can never fail (no imports, no I/O)."""
    return (
        _render_via_backend(state)
        or _render_via_mascot_frames(state, tick)
        or [f"  [{'|/-\\\\'[tick % 4]}] cyphex mascot — {state}"]
    )


# ── the fallback loop itself (used when mascot.render_and_print_state_loop
#    hasn't landed yet) ─────────────────────────────────────────────────
def _run_fallback_loop(state_file_path):
    lines_drawn = 0
    tick = 0
    _hide_cursor()
    try:
        while True:
            state = _read_state(state_file_path)
            try:
                frame_lines = _render_frame(state, tick) or [f"  cyphex — {state}"]
            except Exception:
                frame_lines = [f"  cyphex — {state}"]

            out = []
            if lines_drawn:
                out.append(f"\033[{lines_drawn}A\r")
            for ln in frame_lines:
                out.append(str(ln) + "\033[K\n")
            try:
                sys.stdout.write("".join(out))
                sys.stdout.flush()
            except Exception:
                pass
            lines_drawn = len(frame_lines)

            tick += 1
            time.sleep(POLL_INTERVAL)
    except (KeyboardInterrupt, SystemExit):
        pass  # Ctrl+C or window-close — quiet, no traceback spam
    finally:
        if lines_drawn:
            try:
                n = lines_drawn
                sys.stdout.write(f"\033[{n}A\r" + ("\033[K\n" * n) + f"\033[{n}A")
                sys.stdout.flush()
            except Exception:
                pass
        _show_cursor()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="CYPHEX mascot companion window — standalone render loop."
    )
    parser.add_argument(
        "--state-file",
        default=STATE_FILE_DEFAULT,
        help=f"Path to the mascot state file to poll (default: {STATE_FILE_DEFAULT})",
    )
    args = parser.parse_args(argv)

    # 1) the eventual landed API, if mascot.py has it by the time this runs.
    render_and_print_state_loop = None
    try:
        from mascot import render_and_print_state_loop as _rapsl
        render_and_print_state_loop = _rapsl
    except ImportError:
        pass
    except Exception:
        pass

    if callable(render_and_print_state_loop):
        _hide_cursor()
        try:
            render_and_print_state_loop(args.state_file)
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception:
            pass
        finally:
            _show_cursor()
        return

    _run_fallback_loop(args.state_file)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        _show_cursor()
