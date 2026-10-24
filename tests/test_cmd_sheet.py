"""cx.py's /sheet command: setup prints the Apps Script + remembers the
secret, a bare URL connects using that pending secret, status/remove mirror
/webhook's own shape.

cx._sheets() loads cyphex/sheets.py by file path into its own sys.modules
entry (same trick _notify() uses for notify.py, to dodge backend/backend
shadowing the top-level cyphex package) — a distinct object from
`from cyphex import sheets`, so these tests patch cx._sheets() itself
rather than cyphex.sheets, or the real module (and this machine's real
~/.cyphex/ files) gets touched instead of the mock.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fcntl", reason="cx.py is POSIX-only")

import cx

URL = "https://script.google.com/macros/s/AKfycbxEXAMPLE/exec"


def _fake_sheets(**overrides):
    fake = SimpleNamespace(
        start_setup=MagicMock(return_value="generated-secret"),
        setup_script=MagicMock(return_value="// script\n"),
        pending_secret=MagicMock(return_value=""),
        clear_pending=MagicMock(),
        connect=MagicMock(return_value={"ok": True, "label": "Google Sheet · x"}),
        disconnect=MagicMock(return_value=0),
        saved=MagicMock(return_value=[]),
        label=MagicMock(return_value="Google Sheet · x"),
    )
    for k, v in overrides.items():
        setattr(fake, k, v)
    return fake


def test_setup_prints_script_and_saves_a_pending_secret(capsys):
    fake = _fake_sheets()
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet("setup")
    fake.start_setup.assert_called_once()
    assert "/sheet <that url>" in capsys.readouterr().out


def test_bare_url_without_setup_first_is_rejected(capsys):
    fake = _fake_sheets(pending_secret=MagicMock(return_value=""))
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet(URL)
    fake.connect.assert_not_called()
    assert "run /sheet setup first" in capsys.readouterr().out


def test_bare_url_after_setup_connects_with_the_pending_secret(capsys):
    fake = _fake_sheets(pending_secret=MagicMock(return_value="generated-secret"))
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet(URL)
    fake.connect.assert_called_once_with(URL, "generated-secret")
    fake.clear_pending.assert_called_once()
    assert "Connected" in capsys.readouterr().out


def test_connect_failure_keeps_the_pending_secret_for_a_retry(capsys):
    fake = _fake_sheets(pending_secret=MagicMock(return_value="generated-secret"),
                        connect=MagicMock(return_value={"ok": False, "error": "nope"}))
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet(URL)
    fake.clear_pending.assert_not_called()
    assert "nope" in capsys.readouterr().out


def test_status_lists_connections(capsys):
    fake = _fake_sheets(saved=MagicMock(return_value=[{"url": URL, "secret": "s"}]))
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet("")
    assert "Google Sheet · x" in capsys.readouterr().out


def test_status_with_nothing_connected(capsys):
    with patch.object(cx, "_sheets", return_value=_fake_sheets()):
        cx._cmd_sheet("")
    assert "Nothing connected yet" in capsys.readouterr().out


def test_remove_reports_count(capsys):
    fake = _fake_sheets(disconnect=MagicMock(return_value=1))
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet("remove 1")
    fake.disconnect.assert_called_once_with("1")
    assert "Disconnected 1 sheet" in capsys.readouterr().out


def test_remove_all(capsys):
    fake = _fake_sheets(disconnect=MagicMock(return_value=2))
    with patch.object(cx, "_sheets", return_value=fake):
        cx._cmd_sheet("remove")
    fake.disconnect.assert_called_once_with("all")
