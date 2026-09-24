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


def test_buddy_is_box_height_and_fixed_width_in_every_state():
    for ascii_mode in (False, True):
        faces = footer_dock.FACES_ASCII if ascii_mode else footer_dock.FACES
        for state, frames in faces.items():
            for frame in range(len(frames)):
                rows = footer_dock.buddy_rows(state, frame, ascii_mode)
                assert len(rows) == 3, state          # == input box height
                for r in rows:
                    assert len(_SGR.sub("", r)) == footer_dock.BUDDY_W, (state, r)


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
        ed = deck_input._Editor(0, w, anchor=lambda: (10, 8, 60))
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
        assert f"\x1b[{row};9H" in out            # column = gutter + 1
    assert "\x1b[2K" not in out                   # whole-line erase would wipe the buddy
    assert "\r\n" not in out                      # nothing may scroll the footer
    assert "/scan" in out
