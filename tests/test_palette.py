"""ui_palette is the only place a UI colour is defined.

The palette used to be hand-copied into fourteen places and drifted; and a
single-hue theme rendered PASS and FAIL in the same colour. These tests pin
both fixes.
"""
import pathlib
import re

import ui_palette as P

ROOT = pathlib.Path(__file__).resolve().parent.parent
# a quoted hex colour, or a literal truecolor escape with baked-in numbers
_HEX = re.compile(r"""["']#[0-9a-fA-F]{6}["']|[34]8;2;\d""")
# modules that paint the terminal and must take colours from ui_palette
_CONSUMERS = ("terminal_ui.py", "cx.py", "deck_input.py", "mascot.py",
              "cli_engine.py", "trace_deck.py", "cyphex_cli.py",
              "demo_immune_system.py", "cyphex/cli.py", "cyphex/daemon.py",
              "cyphex/github_hook.py", "cyphex/onboarder.py",
              "backend/backend/agents/terminal.py")


def test_no_hex_colour_literals_outside_palette():
    offenders = [f"{name}:{i}" for name in _CONSUMERS
                 for i, line in enumerate((ROOT / name).read_text().splitlines(), 1)
                 if _HEX.search(line)]
    assert not offenders, f"hard-coded colours (use ui_palette): {offenders}"


def test_outcome_and_severity_hues_are_distinct():
    # pass vs fail vs brand must never collapse to one colour again
    assert len({P.OK, P.WARN, P.PHOS}) == 3
    # each severity rank gets its own hue so rows scan without reading
    assert len({P.WARN, P.HIGH, P.CAUT, P.LOW}) == 4


def test_help_keeps_bracketed_args():
    from rich.console import Console
    import terminal_ui as tu
    c = Console(record=True, width=120, theme=tu.HUD_THEME)
    tu.render_help(console=c)
    out = c.export_text()
    for arg in ("[path]", "[host]", "[corpus]", "[N]", "--watch [s]"):
        assert arg in out, arg
