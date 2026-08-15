"""Phase 1 patch-pipeline tests: resolver + range-accurate applier."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch import resolve, PatchApplier  # noqa: E402


class _V:
    def __init__(self, endpoint, payload="", evidence="", attack_chain=""):
        self.endpoint = endpoint
        self.payload = payload
        self.evidence = evidence
        self.attack_chain = attack_chain


# ── resolver ──────────────────────────────────────────────────────────────
def test_resolve_dynamic_url_infers_method():
    loc = resolve(_V("http://localhost:3000/login", evidence="POST /login"), None)
    assert loc is not None
    assert loc.kind == "url"
    assert loc.method == "POST"
    assert loc.url == "http://localhost:3000/login"


def test_resolve_static_file():
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "app.js")
    with open(fp, "w") as f:
        f.write("a\nb\nVULN\nd\n")
    loc = resolve(_V("app.js:3"), d)
    assert loc is not None
    assert loc.kind == "file"
    assert loc.line == 3
    assert loc.file == fp
    assert loc.rel == "app.js"
    assert loc.key == "app.js:3"


def test_resolve_missing_file_returns_none():
    d = tempfile.mkdtemp()
    assert resolve(_V("ghost.js:5"), d) is None


def test_resolve_no_line_returns_none():
    assert resolve(_V("just-a-path-no-colon"), None) is None


# ── applier ───────────────────────────────────────────────────────────────
def _mkfile(text):
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "app.js")
    with open(fp, "w") as f:
        f.write(text)
    return fp


def test_apply_range_multiline_replacement():
    fp = _mkfile("a\nb\nVULN\nd\ne\n")
    res = PatchApplier(fp).apply_range(2, 3, "FIXED_1\nFIXED_2")
    assert res.ok, res.error
    assert open(fp).read() == "a\nb\nFIXED_1\nFIXED_2\nd\ne\n"


def test_apply_range_does_not_blank_neighbours():
    # The R2 bug blanked the whole window and dumped code on line 1.
    fp = _mkfile("keep1\nVULN_A\nVULN_B\nkeep2\n")
    res = PatchApplier(fp).apply_range(1, 3, "SAFE")
    assert res.ok, res.error
    assert open(fp).read() == "keep1\nSAFE\nkeep2\n"


def test_rollback_restores_original():
    fp = _mkfile("a\nb\nc\n")
    ap = PatchApplier(fp)
    ap.apply_range(1, 2, "X")
    assert ap.rollback() is True
    assert open(fp).read() == "a\nb\nc\n"


def test_python_parse_failure_auto_rolls_back():
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "x.py")
    with open(fp, "w") as f:
        f.write("def f():\n    return 1\n")
    res = PatchApplier(fp).apply_range(1, 2, "    return (")  # broken syntax
    assert not res.ok
    assert open(fp).read() == "def f():\n    return 1\n"


def test_bracket_balance_mismatch_rejects():
    """Replacement that closes more braces than the original snippet is rejected.

    Simulates the Missing Auth bug: the 5-line snippet opens a route handler
    but the model generates a complete handler with closing `});` — orphaning
    the remaining handler body.
    """
    fp = _mkfile(
        "// comment\n"
        "app.get('/admin', (req, res) => {\n"
        "  const notice = req.query.notice || '';\n"
        "\n"
        "  // rest of handler continues...\n"
        "  res.send('ok');\n"
        "});\n"
    )
    # Original snippet covers lines 1-4 (0-based): opens `{` without closing
    # Replacement closes the handler — net balance differs
    replacement = (
        "app.get('/admin', (req, res) => {\n"
        "  if (!req.isAuthenticated()) return res.status(403).send('denied');\n"
        "  res.render('admin');\n"
        "});\n"
    )
    res = PatchApplier(fp).apply_range(1, 4, replacement)
    assert not res.ok
    assert "bracket-balance" in res.error
