"""The "/" command and "@" file popups (Claude Code style).

Covers the provider in cx.py (what is offered, and what Enter / Tab insert)
and the editor's menu keys in deck_input (select, accept, run, dismiss).
"""
import os

import cx
import deck_input


def _labels(text):
    res = cx._suggest(text, len(text))
    return [i.label for i in res[2]] if res else None


def test_slash_lists_commands_and_filters_by_prefix():
    assert len(_labels("/")) > 10
    assert _labels("/he")[0] == "/help"
    assert _labels("/sc")[0].startswith("/scan")
    assert _labels("hello") is None            # plain text: no popup


def test_command_with_required_arg_inserts_instead_of_running():
    _, _, items = cx._suggest("/sca", 4)
    scan = items[0]
    assert scan.insert == "/scan " and scan.submit is False
    _, _, items = cx._suggest("/hel", 4)
    assert items[0].insert == "/help" and items[0].submit is True


def test_path_argument_and_at_token_offer_files(tmp_path, monkeypatch):
    (tmp_path / "vibemart" / "src").mkdir(parents=True)
    (tmp_path / "vibemart" / "app.js").write_text("")
    (tmp_path / "node_modules").mkdir()
    monkeypatch.chdir(tmp_path)
    cx._index_cache.update(cwd=None)
    assert "vibemart/" in _labels("/scan vib")
    at = cx._suggest("look @vib", 9)[2][0]
    assert at.label == "vibemart/"
    assert at.insert == "vibemart/ "           # Enter: plain path, "@" dropped
    assert at.drill == "@vibemart/"            # Tab: step into the directory
    assert "vibemart/app.js" in _labels("@vibemart/")
    assert "node_modules/" not in _labels("@")  # tooling dirs are not offered
    assert _labels("/scan ./app --n") is None    # flags are not paths


def _editor(text):
    r, w = os.pipe()
    ed = deck_input._Editor(0, w, anchor=lambda: (20, 11, 80, 18),
                            suggest=cx._suggest)
    ed._prompt()
    ed._geometry()
    ed.buf, ed.pos = list(text), len(text)
    ed._refresh_menu()
    return ed, r, w


def test_editor_menu_select_accept_run_and_dismiss():
    ed, r, w = _editor("/he")
    try:
        assert ed._menu and ed._menu[2][0].label == "/help"
        assert ed._lifted > 0                  # made room by scrolling, not overwriting
        assert ed._menu_key("submit") == ("submit", "/help")   # Enter runs it

        ed.buf, ed.pos = list("/"), 1
        ed._refresh_menu()
        ed._menu_key("hist-next")              # Down moves the highlight
        assert ed._sel == 1
        ed._menu_key("escape")                 # Esc closes it...
        assert ed._menu is None
        ed._refresh_menu()                     # ...and it stays closed for this text
        assert ed._menu is None
    finally:
        os.close(r)
        os.close(w)
