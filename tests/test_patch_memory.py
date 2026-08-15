"""Phase 6 tests for patch memory and regression emitters."""

import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch.patch_memory import PatchMemory, semantic_hash  # noqa: E402
from backend.patch.regression import (  # noqa: E402
    emit_dynamic_regression_test,
    emit_static_regression_note,
)


def test_semantic_hash_ignores_whitespace_and_comments():
    a = "def f(x):\n    return x + 1\n"
    b = "def f(x): # comment\n\n    return x+1\n"
    assert semantic_hash(a) == semantic_hash(b)


def test_patch_memory_store_and_recall_exact():
    root = tempfile.mkdtemp()
    pm = PatchMemory(root)
    fn = "def q(user):\n    return db.query(user)\n"
    pm.store_verified(fn, "CWE-89", "def q(user):\n    return db.query('SELECT 1', [user])\n")
    pm.save()

    pm2 = PatchMemory(root)
    rec = pm2.recall_exact(fn, "CWE-89")
    assert rec is not None
    assert rec["verified"] is True


def test_regression_emitters_write_files():
    root = tempfile.mkdtemp()
    vuln = SimpleNamespace(name="SQL Injection", cwe="CWE-89", evidence="GET /users")
    dyn = emit_dynamic_regression_test(root, vuln, "http://localhost:3000/users", "id=1")
    sta = emit_static_regression_note(root, "app.py", "CWE-89", 12)
    assert dyn is not None and os.path.exists(dyn)
    assert sta is not None and os.path.exists(sta)
