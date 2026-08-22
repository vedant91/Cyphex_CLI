# `assets/`

Source art for the terminal mascot, plus the QA render corpus used to check that
it still looks right after a renderer change.

| Path | Holds |
|---|---|
| `mascot/` | Source PNGs — one per pose/expression, plus `size_16/32/64.png` reference sheets and `hero.png` |
| `mascot/remastered/` | Output of the repair pass (see below). What actually gets rendered |
| `qa/` | Rendered PNGs, one per `state × column-width`, for visual diffing |
| `mascot_qa_halfblock_*.png` | Half-block backend spot checks |

Nothing here is imported at scan time. The mascot is decorative and every
loading path is defensive — a missing asset or a missing Pillow drops a render
tier rather than failing.

---

## Why there is a "remaster" step

The source PNGs are JPEG-damaged: ringing around edges, and a palette smeared
well past the six colours the character was designed in. Rendered straight to a
terminal cell grid, that reads as mud.

`mascot_remaster.py` repairs them: **BOX downsample → saturate → snap to the
designed six-colour palette**. Snapping is what makes the art crisp at terminal
resolution — an unsnapped near-black and a true black land in different cells
and the silhouette breaks up.

`mascot_remaster_qa.py` regenerates `assets/qa/`.

## Render tiers

`mascot.py` picks the best backend the terminal supports and falls back
downward, never sideways:

| Tier | Backend | Needs |
|---|---|---|
| 3 | Inline images (Kitty / iTerm protocols) | a terminal that speaks one of them |
| 2 | Sextant / quadrant subcells (`mascot_backend_subcell.py`) | Unicode block glyphs |
| 1 | Half-blocks (`mascot_backend_halfblock.py`) | `▀` and truecolor |
| 0 | Plain glyphs | nothing |

More subpixels per cell is what makes a **smaller** mascot look **finer** rather
than chunkier — which is why the subcell backend exists rather than just scaling
the half-block one.

Pillow is a declared dependency but is imported defensively everywhere; without
it the render drops to tier 0 instead of raising.

## States

`mascot_anim.py` owns *what* the mascot does — the per-state frame lists and the
**fixed-canvas guarantee** the redraw loop's cursor-up arithmetic depends on. If
frames in one state have different row counts, the redraw scrolls the terminal
instead of overdrawing. The module docstring records exactly this bug for the
`thinking` state.

States: `idle`, `searching`, `thinking`, `working`, `uploading`, `success`,
`error`.

## Public API

```python
import mascot
mascot.thinking("indexing repo", flourish=True)
mascot.success("8 findings patched")
mascot.error("sandbox deploy failed")
mascot.stop()                     # always stops and erases cleanly
mascot.render_hero(size=64)
mascot.open_companion_window()    # opt-in: the mascot in its own terminal
```

`cx.py`'s `_spinner()` is the main consumer, and it fully stops and erases the
mascot before returning — the status line must never be left half-drawn.

Colour across the whole UI is a single hue, **MONO SIGNAL RED**; severity and
hierarchy are carried by brightness inside that hue rather than by different
colours.

## Regenerating

```bash
python3 mascot_remaster.py       # rebuild assets/mascot/remastered/
python3 mascot_remaster_qa.py    # rebuild assets/qa/
pytest tests/test_mascot_render.py -q
```

Commit regenerated QA renders alongside the renderer change that caused them —
they are the diff that shows what a change actually did.
