"""Patch memory and regression-test generation.

An earlier version of this file imported `emit_dynamic_regression_test` and
`emit_static_regression_note` from `backend.patch.regression`. Neither has ever
existed under any name, so the module failed at import and every test in it was
silently skipped.

The real API is two-step:

    generate_regression_test(vuln, location, framework="jest") -> str | None
    write_regression_tests([(name, content), ...], output_dir) -> [paths]
"""

import json
import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch.patch_memory import PatchMemory, semantic_hash  # noqa: E402
from backend.patch.regression import (  # noqa: E402
    generate_regression_test,
    write_regression_tests,
)


def _vuln(name="SQL Injection", cwe="CWE-89", payload="id=1 OR 1=1"):
    return SimpleNamespace(name=name, cwe=cwe, payload=payload, evidence="GET /users")


def _url_loc(url="http://localhost:3000/users", method="GET"):
    return SimpleNamespace(kind="url", url=url, method=method, file=None, rel=None, line=None)


def _file_loc(rel="app.py", line=12):
    return SimpleNamespace(kind="file", url=None, method="GET", file=f"/tmp/{rel}", rel=rel, line=line)


# ── semantic hashing ──────────────────────────────────────────────────

def test_semantic_hash_ignores_whitespace_and_comments():
    a = "def f(x):\n    return x + 1\n"
    b = "def f(x): # comment\n\n    return x+1\n"
    assert semantic_hash(a) == semantic_hash(b)


def test_semantic_hash_distinguishes_real_changes():
    """Whitespace-insensitivity must not blur an actual behaviour change."""
    a = "def f(x):\n    return x + 1\n"
    b = "def f(x):\n    return x - 1\n"
    assert semantic_hash(a) != semantic_hash(b)


# ── patch memory ──────────────────────────────────────────────────────

def test_patch_memory_store_and_recall_exact():
    root = tempfile.mkdtemp()
    fn = "def q(user):\n    return db.query(user)\n"
    fixed = "def q(user):\n    return db.query('SELECT 1', [user])\n"

    pm = PatchMemory(root)
    pm.store_verified(fn, "CWE-89", fixed)
    pm.save()

    reloaded = PatchMemory(root)  # must survive a round-trip to disk
    rec = reloaded.recall_exact(fn, "CWE-89")
    assert rec is not None
    assert rec["verified"] is True


def test_patch_memory_recall_is_whitespace_insensitive():
    """The cache keys on semantic hash, so reformatting must still hit."""
    root = tempfile.mkdtemp()
    pm = PatchMemory(root)
    pm.store_verified("def q(u):\n    return db.query(u)\n", "CWE-89", "fixed")

    assert pm.recall_exact("def q(u):  # reformatted\n\n    return db.query(u)\n", "CWE-89") is not None


def test_patch_memory_miss_on_different_cwe():
    root = tempfile.mkdtemp()
    fn = "def q(u):\n    return db.query(u)\n"
    pm = PatchMemory(root)
    pm.store_verified(fn, "CWE-89", "fixed")

    assert pm.recall_exact(fn, "CWE-79") is None


def test_patch_memory_empty_on_fresh_root():
    assert PatchMemory(tempfile.mkdtemp()).recall_exact("anything", "CWE-89") is None


def test_patch_memory_pattern_round_trip():
    root = tempfile.mkdtemp()
    pm = PatchMemory(root)
    pm.add_pattern("CWE-89", "express", "parameterized-query")
    pm.save()

    rec = PatchMemory(root).get_pattern("CWE-89", "express")
    assert rec is not None


# ── regression test generation ────────────────────────────────────────

def test_generate_dynamic_regression_test():
    content = generate_regression_test(_vuln(), _url_loc())
    assert content
    # The jest/mocha output drives supertest against the app object, so only
    # the URL *path* is embedded — not the host.
    assert '"/users"' in content
    assert "CWE-89" in content
    assert "supertest" in content


def test_generate_dynamic_regression_test_escapes_payload():
    """Payloads are attacker-controlled text landing in a generated source file,
    so the quote must be escaped rather than allowed to close the literal and
    run as code."""
    nasty = '"; process.exit(1); //'
    content = generate_regression_test(_vuln(payload=nasty), _url_loc())

    assert json.dumps(nasty) in content          # embedded as a closed literal
    assert f'= {nasty}' not in content           # never spliced raw
    assert 'payload = "";' not in content        # and not truncated at the quote


def test_generate_static_regression_test():
    content = generate_regression_test(_vuln(), _file_loc())
    assert content
    assert "CWE-89" in content


def test_generate_returns_none_without_location():
    assert generate_regression_test(_vuln(), None) is None


def test_generate_returns_none_for_unknown_location_kind():
    loc = SimpleNamespace(kind="mystery", url=None, method="GET", file=None, rel=None, line=None)
    assert generate_regression_test(_vuln(), loc) is None


def test_write_regression_tests_creates_files():
    out = tempfile.mkdtemp()
    dyn = generate_regression_test(_vuln(), _url_loc())
    sta = generate_regression_test(_vuln(), _file_loc())

    written = write_regression_tests([("sqli-dynamic", dyn), ("sqli-static", sta)], out)

    assert len(written) == 2
    for path in written:
        assert os.path.exists(path)
        assert os.path.dirname(path).endswith(os.path.join("tests", "security"))


def test_write_regression_tests_skips_empty_content():
    out = tempfile.mkdtemp()
    written = write_regression_tests([("real", "console.log(1);"), ("empty", None)], out)
    assert len(written) == 1


def test_write_regression_tests_sanitises_names():
    """A test name must not be able to escape the output directory."""
    out = tempfile.mkdtemp()
    written = write_regression_tests([("../../escape", "content")], out)

    assert len(written) == 1
    security_dir = os.path.realpath(os.path.join(out, "tests", "security"))
    assert os.path.realpath(written[0]).startswith(security_dir)
