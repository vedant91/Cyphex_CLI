"""Pinned footer (footer_dock) + the editor's anchored mode.

Pins the three things the on-screen checks relied on: the buddy is exactly
the box's height and a fixed width (so it never grows the footer or shoves
the box), an anchored editor paints at absolute rows without erasing the
buddy's gutter, and with no terminal every footer call is a no-op that tells
the caller to keep its inline behaviour.
"""
import os
import re

from rich.console import Console

import deck_input
import footer_dock

_SGR = re.compile(r"\x1b\[[0-9;]*m")


def test_buddy_fits_the_footer_and_fixed_width_in_every_state():
    states = list(footer_dock.FACES) + list(footer_dock.ALIASES)
    for ascii_mode in (False, True):
        faces = footer_dock.FACES_ASCII if ascii_mode else footer_dock.FACES
        for state in states:
            for frame in range(len(faces[footer_dock.expression(state)])):
                rows = footer_dock.buddy_rows(state, frame, ascii_mode)
                # antenna rides the rail row; the head is the input box's height
                assert len(rows) == footer_dock.ROWS, state
                for r in rows:
                    assert len(_SGR.sub("", r)) == footer_dock.BUDDY_W, (state, r)


def test_faces_are_the_sprite_expressions():
    face = lambda s: _SGR.sub("", footer_dock.buddy_rows(s)[2])[2:-1].strip()
    assert face("alert") == "!"            # assets/mascot/expr_alert.png
    assert face("error") == "x_x"          # expr_error.png
    assert face("idle") == "CYPHEX"        # expr_neutral.png
    assert face("working") == "> <"        # expr_hacking.png
    assert "✓" in footer_dock.buddy_rows("success")[0]   # success.png bubble


def test_no_terminal_means_noop_and_inline_fallback(monkeypatch):
    monkeypatch.delenv(footer_dock.ENV, raising=False)
    monkeypatch.setattr(footer_dock, "available", lambda: False)
    assert footer_dock.reserve() is False
    assert footer_dock.set_state("working") is False    # mascot.py falls back
    assert footer_dock.start_task("x") is False
    assert footer_dock.begin_input() is None            # editor stays inline
    assert not footer_dock.active()


def test_anchored_editor_paints_absolute_rows_and_spares_gutter():
    r, w = os.pipe()
    try:
        ed = deck_input._Editor(0, w, anchor=lambda: (10, 11, 60))
        ed._prompt()
        ed.buf = list("/scan")
        ed.pos = len(ed.buf)
        ed._paint_all()
        ed._paint_row()
        out = os.read(r, 65536).decode()
    finally:
        os.close(r)
        os.close(w)
    for row in (10, 11, 12):                      # top wall, text, bottom wall
        assert f"\x1b[{row};12H" in out           # column = gutter + 1
    assert "\x1b[2K" not in out                   # whole-line erase would wipe the buddy
    assert "\r\n" not in out                      # nothing may scroll the footer
    assert "/scan" in out


def test_image_buddy_animates_only_expressions_with_motion(monkeypatch):
    """WezTerm/iTerm2: the slot shows the real sprite, sized to the slot.
    A still expression is sent once; an animated one flips a frame per
    tick; a full repaint always redraws."""
    monkeypatch.setattr(footer_dock, "image_protocol", lambda: True)
    monkeypatch.setattr(footer_dock, "_ascii", lambda: False)
    monkeypatch.setitem(footer_dock._st, "size", (30, 100))
    monkeypatch.setitem(footer_dock._st, "drawn", None)
    monkeypatch.setitem(footer_dock._st, "frame", 0)
    for expr in footer_dock.ART:
        frames = footer_dock.art_frames(expr)
        assert frames, expr                                # every face has art
        assert (len(frames) > 1) == (expr in footer_dock.EFFECT), expr
    monkeypatch.setitem(footer_dock._st, "state", "neutral")
    first = footer_dock._paint_buddy()
    assert "\x1b]1337;File=" in first
    assert f"width={footer_dock.BUDDY_W};height={footer_dock.ROWS}" in first
    assert "doNotMoveCursor=1" in first     # else the last-row image scrolls the screen
    monkeypatch.setitem(footer_dock._st, "frame", 5)
    assert footer_dock._paint_buddy() == ""               # still face: no resend
    assert "1337" in footer_dock._paint_buddy(force=True)  # full repaint redraws it
    monkeypatch.setitem(footer_dock._st, "state", "alert")
    assert "1337" in footer_dock._paint_buddy()           # new face: resend
    assert footer_dock._paint_buddy() == ""               # same frame: nothing
    monkeypatch.setitem(footer_dock._st, "frame", 6)
    assert "1337" in footer_dock._paint_buddy()           # next frame: the flash


def test_status_line_spins_a_verb_with_elapsed_and_hands_the_row_back(monkeypatch):
    out = []
    monkeypatch.setattr(footer_dock, "_raw", out.append)
    monkeypatch.setattr(footer_dock, "_ascii", lambda: False)
    monkeypatch.setattr(footer_dock, "image_protocol", lambda: False)
    monkeypatch.setitem(footer_dock._st, "active", True)
    monkeypatch.setitem(footer_dock._st, "owner", False)
    monkeypatch.setitem(footer_dock._st, "size", (30, 100))
    monkeypatch.setitem(footer_dock._st, "rail", "")
    monkeypatch.setitem(footer_dock._st, "started", 0.0)
    assert footer_dock.start_task("4/9  DAST", animate=False)
    status = _SGR.sub("", footer_dock._paint_status())
    assert "\x1b[27;12H" in status                        # rail row, right of the buddy
    assert any(v + "…" in status for v in footer_dock.VERBS)
    assert "s · ctrl+c to stop)" in status
    assert "4/9  DAST" in _SGR.sub("", "".join(out))       # the box still says what runs
    out.clear()
    footer_dock.stop_task()
    assert "".join(out) == "\x1b7\x1b[?25l\x1b[27;12H\x1b[K\x1b8\x1b[?25h"  # row blanked for the REPL


def test_image_protocol_detection(monkeypatch):
    for k in ("TMUX", "TERM_PROGRAM", "WEZTERM_EXECUTABLE", "WEZTERM_PANE", "CYPHEX_BUDDY"):
        monkeypatch.delenv(k, raising=False)
    assert not footer_dock.image_protocol()
    monkeypatch.setenv("TERM_PROGRAM", "WezTerm")
    assert footer_dock.image_protocol()
    monkeypatch.setenv("TMUX", "/tmp/tmux-1/default,1,0")      # tmux eats the OSC
    assert not footer_dock.image_protocol()
    monkeypatch.setenv("CYPHEX_BUDDY", "image")
    assert footer_dock.image_protocol()
    monkeypatch.setenv("CYPHEX_BUDDY", "glyph")
    monkeypatch.delenv("TMUX")
    assert not footer_dock.image_protocol()


def test_region_is_footer_only_so_scrollback_is_preserved():
    """The scroll region starts at row 1 (top margin unchanged): lines that
    scroll off the top reach the terminal's scrollback. Only the bottom ROWS
    are reserved for the footer — nothing is pinned at the top."""
    assert footer_dock._region_seq(40) == "\x1b[1;36r"     # rows 1..(40-ROWS)
    assert footer_dock._region_bottom(40) == 40 - footer_dock.ROWS
    assert not hasattr(footer_dock, "pin_header")           # header feature removed
    assert not hasattr(footer_dock, "_region_top")


def test_set_context_shows_scan_id_and_target_on_the_status_line(monkeypatch):
    """The hero's key facts live on the footer status line for the whole run,
    so they stay visible while the hero panel itself scrolls into scrollback."""
    out = []
    monkeypatch.setattr(footer_dock, "_write", out.append)
    monkeypatch.setattr(footer_dock, "_size", lambda: (40, 100))
    monkeypatch.setattr(footer_dock, "_ascii", lambda: False)
    monkeypatch.setitem(footer_dock._st, "active", True)
    monkeypatch.setitem(footer_dock._st, "size", (40, 100))
    monkeypatch.setitem(footer_dock._st, "task", "4/9  DYNAMIC SCAN")
    monkeypatch.setitem(footer_dock._st, "started", 0.0)
    assert footer_dock.set_context("cli_640932ed",
                                   "/Users/x/Documents/CYPHEX_CLI/vibemart/src/")
    painted = _SGR.sub("", "".join(out))
    assert "cli_640932ed" in painted                        # scan id
    assert "vibemart/src/" in painted                       # target tail (clipped left)
    assert footer_dock._st["target"].startswith("…")        # deep prefix dropped


def test_render_hero_is_inline_and_sets_footer_context(monkeypatch):
    import terminal_ui as tu
    seen = {}
    monkeypatch.setattr(footer_dock, "set_context",
                        lambda sid, tgt="": seen.update(sid=sid, tgt=tgt))
    c = Console(record=True, width=100, theme=tu.HUD_THEME)
    monkeypatch.setattr(tu, "soc", c)
    tu.render_hero("cli_1", "demo/vibemart")
    out = _SGR.sub("", c.export_text())
    assert "SCAN ID" in out and "cli_1" in out and "vibemart" in out   # printed inline
    assert seen == {"sid": "cli_1", "tgt": "demo/vibemart"}            # facts to footer
