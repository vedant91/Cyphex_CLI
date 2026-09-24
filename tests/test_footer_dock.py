"""Pinned footer (footer_dock) + the editor's anchored mode.

Pins the three things the on-screen checks relied on: the buddy is exactly
the box's height and a fixed width (so it never grows the footer or shoves
the box), an anchored editor paints at absolute rows without erasing the
buddy's gutter, and with no terminal every footer call is a no-op that tells
the caller to keep its inline behaviour.
"""
import os
import re

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


def test_image_buddy_is_the_real_sprite_sent_once_per_expression(monkeypatch):
    """WezTerm/iTerm2: the slot shows the actual PNG, sized to the slot, and
    is resent only when the expression changes — never on animator ticks."""
    monkeypatch.setattr(footer_dock, "image_protocol", lambda: True)
    monkeypatch.setattr(footer_dock, "_ascii", lambda: False)
    monkeypatch.setitem(footer_dock._st, "size", (30, 100))
    monkeypatch.setitem(footer_dock._st, "drawn", None)
    for expr in footer_dock.ART:
        assert footer_dock.art_png(expr), expr            # every face has art
    monkeypatch.setitem(footer_dock._st, "state", "alert")
    first = footer_dock._paint_buddy()
    assert "\x1b]1337;File=" in first
    assert f"width={footer_dock.BUDDY_W};height={footer_dock.ROWS}" in first
    assert "doNotMoveCursor=1" in first     # else the last-row image scrolls the screen
    monkeypatch.setitem(footer_dock._st, "frame", 5)
    assert footer_dock._paint_buddy() == ""               # same face: no resend
    assert "1337" in footer_dock._paint_buddy(force=True)  # full repaint redraws it
    monkeypatch.setitem(footer_dock._st, "state", "error")
    assert "1337" in footer_dock._paint_buddy()           # new face: resend


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


def test_pinned_header_sits_on_the_footer_and_is_handed_back(monkeypatch):
    """The scan hero pins directly above the rail (bottom-anchored, so the
    region still starts at row 1 and scrolled lines reach scrollback),
    shrinks the region by its height, and release() gives the rows back."""
    out = []
    monkeypatch.setattr(footer_dock, "_raw", out.append)
    monkeypatch.setattr(footer_dock, "_size", lambda: (40, 100))
    monkeypatch.setitem(footer_dock._st, "active", True)
    monkeypatch.setitem(footer_dock._st, "owner", False)
    monkeypatch.setitem(footer_dock._st, "size", (40, 100))
    monkeypatch.setitem(footer_dock._st, "head_rows", [])
    seen = []
    render = lambda cols, rows: seen.append((cols, rows)) or ["HERO1", "HERO2", "HERO3"]
    assert footer_dock.pin_header(render)
    assert seen == [(100, 40 - footer_dock.ROWS - footer_dock.MIN_OUTPUT)]
    paint = "".join(out)
    assert "\x1b[1;33r" in paint                     # 40 - 4 footer - 3 header
    assert "\x1b[34;1H" in paint and "HERO1" in paint  # right above the rail (row 37)
    assert footer_dock.box_anchor()[3] == 33           # popups stop above it too
    assert not footer_dock.pin_header(render)          # one header per run
    out.clear()
    footer_dock.release()
    assert "\x1b[1;36r" in "".join(out)                # region back to the footer's
    assert footer_dock._st["head_rows"] == []


def test_header_too_tall_prints_inline(monkeypatch):
    monkeypatch.setattr(footer_dock, "_raw", lambda s: None)
    monkeypatch.setitem(footer_dock._st, "active", True)
    monkeypatch.setitem(footer_dock._st, "size", (20, 100))
    monkeypatch.setitem(footer_dock._st, "head_rows", [])
    assert not footer_dock.pin_header(lambda cols, rows: ["x"] * (rows + 1))
    assert not footer_dock.pin_header(lambda cols, rows: 1 / 0)   # never raises


def test_hero_lines_degrade_full_compact_none():
    import terminal_ui as tu
    full = tu.hero_lines("cli_1", "/t", 100, 40)
    compact = tu.hero_lines("cli_1", "/t", 100, len(full) - 1)
    assert len(compact) < len(full) and "SCAN ID" in _SGR.sub("", "".join(compact))
    assert tu.hero_lines("cli_1", "/t", 100, 2) == []
    long = tu.hero_lines("cli_1", "/" + "x" * 400, 80, 40)
    assert len(long) == len(full)                      # long target cut, not wrapped
    assert all(len(_SGR.sub("", l)) <= 80 for l in long)
