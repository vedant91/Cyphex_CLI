"""Regression tests for the mascot renderer.

The bug these exist to prevent: frames within a single animation state used to
render to *different* terminal row counts (`thinking` measured {14, 19}). The
redraw loop cursor-ups by the height it last drew, so a mid-state height change
left the taller frame's leftover rows on screen and drew the next frame below
them — on screen that reads as half a robot with a second robot appended.

The fix is structural (one shared bottom-anchored canvas for every frame of
every state), which makes the bug impossible rather than unlikely — but only as
long as the invariant is actually enforced. That is what these assert.
"""

import pytest

mascot_anim = pytest.importorskip("mascot_anim")
subcell = pytest.importorskip("mascot_backend_subcell")
halfblock = pytest.importorskip("mascot_backend_halfblock")

# Widths the shrink ladder can actually select, so a regression at any rung is
# caught rather than only at the default.
COLS = (16, 18, 20, 22, 24, 28)


def _rendered_rows(text):
    return text.count("\n") + 1


@pytest.mark.parametrize("state", sorted(mascot_anim.STATES))
@pytest.mark.parametrize("cols", COLS)
@pytest.mark.parametrize("mode", ["halfblock", "quadrant", "sextant"])
def test_every_frame_in_a_state_renders_the_same_height(state, cols, mode):
    """The invariant the redraw loop depends on."""
    frames = mascot_anim.frames_for(state, cols, mode=mode)
    assert frames, f"{state} produced no frames at {cols} cols"

    heights = {_rendered_rows(subcell.render_frame(f, cols, mode=mode)) for f in frames}
    assert len(heights) == 1, (
        f"{state} @ {cols} cols ({mode}) renders at multiple heights {sorted(heights)} — "
        "this is the 'cuts in half and another robot appends' bug"
    )


@pytest.mark.parametrize("cols", COLS)
def test_all_states_share_one_canvas_height(cols):
    """States must also agree with each other, or transitions drift."""
    heights = set()
    for state in mascot_anim.STATES:
        for frame in mascot_anim.frames_for(state, cols, mode="quadrant"):
            heights.add(_rendered_rows(subcell.render_frame(frame, cols, mode="quadrant")))
    assert len(heights) == 1, f"states disagree on canvas height at {cols} cols: {sorted(heights)}"


@pytest.mark.parametrize("cols", COLS)
def test_canvas_rows_matches_what_actually_renders(cols):
    """The reservation and cursor-up maths are sized from canvas_rows(), so a
    mismatch there desynchronises the redraw even with a uniform canvas."""
    declared = mascot_anim.canvas_rows(cols)
    frame = mascot_anim.frames_for("idle", cols, mode="halfblock")[0]
    assert _rendered_rows(halfblock.render_frame(frame, cols)) == declared


def test_erase_region_never_walks_off_a_shrunken_terminal():
    """A terminal that shrank mid-animation must not be erased using the old,
    now-too-large height: the cursor-up would clamp at the top of the screen and
    strand sprite rows in scrollback where nothing can reach them."""
    import io
    import re
    import shutil
    import os

    import mascot

    m = mascot.Mascot.__new__(mascot.Mascot)
    buf = io.StringIO()
    m._stream = buf
    m._write = buf.write
    m._drawn_rows = 14
    m._active_kind = "text"
    m._cursor_hidden = False
    m._region_open = True

    original = shutil.get_terminal_size
    shutil.get_terminal_size = lambda *a, **k: os.terminal_size((80, 10))
    try:
        m._erase_region()
    finally:
        shutil.get_terminal_size = original

    distances = [int(n) for n in re.findall(r"\x1b\[(\d+)A", buf.getvalue())]
    assert distances, "expected at least one cursor-up"
    assert max(distances) < 10, f"cursor-up {max(distances)} exceeds the 10-row terminal"


def test_unknown_state_degrades_instead_of_raising():
    frames = mascot_anim.frames_for("no-such-state", 24, mode="quadrant")
    assert frames, "an unknown state should fall back to a real animation, not empty"
