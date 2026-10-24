"""cyphex/sheets.py: connect an Apps Script web app (validated by a ping the
script must accept with the shared secret), then append one row per call.
Every network call is mocked; every test uses its own temp store."""
import json
import stat
import sys
from unittest.mock import patch

import pytest

from cyphex import sheets

URL = "https://script.google.com/macros/s/AKfycbxEXAMPLE/exec"


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("CYPHEX_SHEETS_FILE", str(tmp_path / "sheets.json"))


def test_connect_saves_only_after_the_script_accepts_the_secret():
    with patch("cyphex.sheets._post_now", return_value="ok") as post:
        res = sheets.connect(URL, "s3cret")
    assert res["ok"] is True
    post.assert_called_once_with(URL, {"type": "ping", "secret": "s3cret"})
    assert sheets.saved() == [{"url": URL, "secret": "s3cret"}]


def test_connect_rejects_a_non_apps_script_url_without_any_request():
    with patch("cyphex.sheets._post_now") as post:
        res = sheets.connect("https://evil.example/exec", "s3cret")
    assert res["ok"] is False
    post.assert_not_called()
    assert sheets.saved() == []


def test_connect_requires_a_secret():
    with patch("cyphex.sheets._post_now") as post:
        assert sheets.connect(URL, "  ")["ok"] is False
    post.assert_not_called()


def test_wrong_secret_in_the_script_is_not_saved():
    with patch("cyphex.sheets._post_now", return_value="forbidden"):
        res = sheets.connect(URL, "wrong")
    assert res["ok"] is False
    assert "secret" in res["error"]
    assert sheets.saved() == []


def test_unreachable_script_is_not_saved():
    with patch("cyphex.sheets._post_now", side_effect=OSError("down")):
        assert sheets.connect(URL, "s3cret")["ok"] is False
    assert sheets.saved() == []


def test_reconnecting_the_same_url_replaces_instead_of_duplicating():
    with patch("cyphex.sheets._post_now", return_value="ok"):
        sheets.connect(URL, "old")
        sheets.connect(URL, "new")
    assert sheets.saved() == [{"url": URL, "secret": "new"}]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_store_is_owner_only():
    with patch("cyphex.sheets._post_now", return_value="ok"):
        sheets.connect(URL, "s3cret")
    mode = stat.S_IMODE(sheets._store().stat().st_mode)
    assert mode == 0o600


def test_disconnect_by_number_and_all():
    other = "https://script.google.com/macros/s/OTHER/exec"
    with patch("cyphex.sheets._post_now", return_value="ok"):
        sheets.connect(URL, "a")
        sheets.connect(other, "b")
    assert sheets.disconnect("1") == 1
    assert [c["url"] for c in sheets.saved()] == [other]
    assert sheets.disconnect("all") == 1
    assert sheets.saved() == []


def test_log_row_posts_the_row_with_the_secret_to_every_connection():
    other = "https://script.google.com/macros/s/OTHER/exec"
    with patch("cyphex.sheets._post_now", return_value="ok"):
        sheets.connect(URL, "a")
        sheets.connect(other, "b")
    row = {c: "x" for c in sheets.COLUMNS}
    with patch("cyphex.sheets._pool.submit", side_effect=lambda fn, *a: fn(*a)), \
         patch("cyphex.sheets._post_now") as post:
        sheets.log_row(row)
    sent = {call.args[0]: call.args[1] for call in post.call_args_list}
    assert sent[URL] == {"type": "row", "secret": "a", "row": row}
    assert sent[other] == {"type": "row", "secret": "b", "row": row}


def test_log_row_with_nothing_connected_does_nothing():
    with patch("cyphex.sheets._pool.submit") as submit:
        sheets.log_row({"Endpoint": "/x"})
    submit.assert_not_called()


def test_log_row_never_raises_when_the_sheet_is_down():
    with patch("cyphex.sheets._post_now", return_value="ok"):
        sheets.connect(URL, "a")
    with patch("cyphex.sheets._pool.submit", side_effect=lambda fn, *a: fn(*a)), \
         patch("cyphex.sheets._post_now", side_effect=OSError("down")):
        sheets.log_row({"Endpoint": "/x"})  # must not raise


def test_label_never_exposes_the_full_url():
    assert "AKfycbxEXAMPLE" not in sheets.label(URL)


def test_setup_script_embeds_the_secret_and_the_exact_columns():
    script = sheets.setup_script("s3cret")
    assert "const SECRET = 's3cret';" in script
    assert json.dumps(sheets.COLUMNS) in script
    assert "__SECRET__" not in script and "__COLUMNS__" not in script
    assert "d.secret !== SECRET" in script  # the script refuses writes without it
