"""Patch-pipeline tests: resolver + range-accurate applier.

An earlier version of this file imported `resolve, PatchApplier` from
`backend.patch`, whose __init__.py is docstring-only and re-exports nothing.
There is also no `PatchApplier` class anywhere — the applier is functional:

    apply_patch(file_path, start_line, end_line, fixed_code, source_dir=None)
        -> ApplyResult(success, file_path, backup_content, error, parse_valid)
    rollback(file_path, backup_content, source_dir=None) -> bool

Note `.success`, not `.ok`. The old file therefore failed at import and every
test in it was silently skipped.
"""

import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch.applier import apply_patch, rollback  # noqa: E402
from backend.patch.resolver import resolve  # noqa: E402


class _V:
    def __init__(self, endpoint, payload="", evidence="", attack_chain=""):
        self.endpoint = endpoint
        self.payload = payload
        self.evidence = evidence
        self.attack_chain = attack_chain


def _mkfile(text, name="app.js"):
    d = tempfile.mkdtemp()
    fp = os.path.join(d, name)
    with open(fp, "w", encoding="utf-8") as f:
        f.write(text)
    return fp


def _read(fp):
    with open(fp, encoding="utf-8") as f:
        return f.read()


# ── resolver ──────────────────────────────────────────────────────────

def test_resolve_dynamic_url():
    loc = resolve(_V("http://localhost:3000/login"), None)
    assert loc is not None
    assert loc.kind == "url"
    assert loc.url == "http://localhost:3000/login"


def test_resolve_method_from_curl_flag():
    """_extract_method reads curl's `-X METHOD`, not a bare 'POST /login' line."""
    loc = resolve(_V("http://localhost:3000/login", evidence="curl -X POST /login"), None)
    assert loc.method == "POST"


def test_resolve_method_defaults_to_get():
    loc = resolve(_V("http://localhost:3000/login", evidence="POST /login"), None)
    assert loc.method == "GET", "a bare 'POST /login' is not the documented form"


def test_resolve_static_file():
    # realpath: on macOS /var is a symlink to /private/var and the resolver
    # normalises, so compare against the resolved root.
    d = os.path.realpath(tempfile.mkdtemp())
    fp = os.path.join(d, "app.js")
    with open(fp, "w", encoding="utf-8") as f:
        f.write("a\nb\nVULN\nd\n")

    loc = resolve(_V("app.js:3"), d)
    assert loc is not None
    assert loc.kind == "file"
    assert loc.line == 3
    assert os.path.realpath(loc.file) == fp
    assert loc.rel == "app.js"
    # Location has no `.key`; rel + line are the identity used downstream.
    assert f"{loc.rel}:{loc.line}" == "app.js:3"


def test_resolve_missing_file_returns_none():
    assert resolve(_V("ghost.js:5"), tempfile.mkdtemp()) is None


def test_resolve_no_line_returns_none():
    assert resolve(_V("just-a-path-no-colon"), None) is None


def test_resolve_refuses_path_outside_source_dir():
    """Containment guard: a traversal endpoint must not resolve to a real file."""
    d = tempfile.mkdtemp()
    outside = os.path.join(tempfile.mkdtemp(), "secret.js")
    with open(outside, "w", encoding="utf-8") as f:
        f.write("token = 1\n")

    assert resolve(_V(f"../{os.path.basename(outside)}:1"), d) is None


# ── applier ───────────────────────────────────────────────────────────

def test_apply_range_multiline_replacement():
    fp = _mkfile("a\nb\nVULN\nd\ne\n")
    res = apply_patch(fp, 3, 3, "FIXED_1\nFIXED_2")
    assert res.success, res.error
    assert _read(fp) == "a\nb\nFIXED_1\nFIXED_2\nd\ne\n"


def test_apply_range_does_not_blank_neighbours():
    """Guards the regression where the whole window was blanked and the
    replacement dumped on line 1."""
    fp = _mkfile("keep1\nVULN_A\nVULN_B\nkeep2\n")
    res = apply_patch(fp, 2, 3, "SAFE")
    assert res.success, res.error
    assert _read(fp) == "keep1\nSAFE\nkeep2\n"


def test_apply_single_line():
    fp = _mkfile("a\nVULN\nc\n")
    res = apply_patch(fp, 2, 2, "SAFE")
    assert res.success, res.error
    assert _read(fp) == "a\nSAFE\nc\n"


def test_rollback_restores_original():
    original = "a\nb\nc\n"
    fp = _mkfile(original)

    res = apply_patch(fp, 1, 2, "X")
    assert res.success, res.error
    assert _read(fp) != original

    assert rollback(fp, res.backup_content) is True
    assert _read(fp) == original


def test_backup_content_is_captured_even_on_failure():
    """Rollback is only possible if the pre-patch bytes survive the failure."""
    original = "def f():\n    return 1\n"
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "x.py")
    with open(fp, "w", encoding="utf-8") as f:
        f.write(original)

    res = apply_patch(fp, 1, 2, "    return (")  # broken syntax
    assert not res.success
    assert res.backup_content == original


def test_python_parse_failure_auto_rolls_back():
    original = "def f():\n    return 1\n"
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "x.py")
    with open(fp, "w", encoding="utf-8") as f:
        f.write(original)

    res = apply_patch(fp, 1, 2, "    return (")  # broken syntax
    assert not res.success
    assert res.parse_valid is False
    assert _read(fp) == original, "file must be restored to its pre-patch bytes"


def test_missing_file_is_rejected():
    res = apply_patch(os.path.join(tempfile.mkdtemp(), "nope.js"), 1, 1, "X")
    assert not res.success
    assert "not found" in (res.error or "").lower()


def test_write_outside_source_dir_is_refused():
    """Second containment guard, independent of the resolver."""
    target = _mkfile("a\nb\n")
    other_root = tempfile.mkdtemp()

    res = apply_patch(target, 1, 1, "X", source_dir=other_root)
    assert not res.success
    assert "outside source directory" in (res.error or "").lower()
    assert _read(target) == "a\nb\n"


def test_unknown_file_type_leaves_parse_valid_none():
    """Tri-state: an unvalidatable type must report None, never a bare True —
    the Verify Gate turns that None into UNVERIFIABLE rather than PASS."""
    fp = _mkfile("some text\nmore text\n", name="notes.rst")
    res = apply_patch(fp, 1, 1, "changed")
    assert res.success
    assert res.parse_valid is None


@pytest.mark.skipif(not shutil.which("node"), reason="node required for JS syntax check")
def test_orphaned_brace_patch_is_rejected_and_rolled_back():
    """A replacement that closes a block the original snippet left open orphans
    the rest of the handler.

    `patch_council.py` instructs the model to preserve net brace depth, but
    nothing enforces that — there is no bracket-balance guard in the applier.
    The damage is caught one step later, by `node --check`, which then
    auto-rolls-back. This pins that backstop.
    """
    original = (
        "// comment\n"
        "app.get('/admin', (req, res) => {\n"
        "  const notice = req.query.notice || '';\n"
        "\n"
        "  // rest of handler continues...\n"
        "  res.send('ok');\n"
        "});\n"
    )
    fp = _mkfile(original)

    replacement = (
        "app.get('/admin', (req, res) => {\n"
        "  if (!req.isAuthenticated()) return res.status(403).send('denied');\n"
        "  res.render('admin');\n"
        "});\n"
    )
    res = apply_patch(fp, 1, 4, replacement)

    assert not res.success
    assert res.parse_valid is False
    assert _read(fp) == original
