"""Phase 3 tests for RAG context extraction and KB/index lookup."""

import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# backend/rag/__init__.py is docstring-only and re-exports nothing, so these
# come from the submodules that actually define them — the same way production
# code (cli_engine.py) imports them.
from backend.rag.code_indexer import CodeIndexer  # noqa: E402
from backend.rag.context import (  # noqa: E402
    detect_language,
    extract_function,
    extract_imports,
)
from backend.rag.security_kb import load_security_kb  # noqa: E402


def test_detect_language_and_import_extraction_python():
    content = "import os\nfrom x import y\n\n\ndef f():\n    return 1\n"
    assert detect_language("x.py") == "python"
    imports = extract_imports(content, "python")
    assert "import os" in imports
    assert "from x import y" in imports


def test_extract_function_python_prefers_def_block():
    content = (
        "import os\n\n"
        "def a():\n"
        "    return 1\n\n"
        "def b():\n"
        "    x = 2\n"
        "    return x\n\n"
        "z = 3\n"
    )
    snippet, quality = extract_function(content, 6, "python")
    assert quality == "function"
    assert "def b():" in snippet
    assert "return x" in snippet


def test_extract_function_js_falls_back_on_unbalanced_block():
    content = (
        "const x = 1;\n"
        "app.get('/u', (req, res) => {\n"
        "  const y = req.query.y;\n"
        "  if (y) {\n"
        "    res.send(y);\n"
        "\n"
        "// missing braces\n"
    )
    snippet, quality = extract_function(content, 4, "javascript")
    assert quality == "window"
    assert "res.send(y)" in snippet


def test_code_indexer_and_kb_strategy_lookup():
    root = tempfile.mkdtemp()
    fp = os.path.join(root, "routes.js")
    with open(fp, "w", encoding="utf-8") as f:
        f.write(
            "const express = require('express');\n"
            "router.get('/users', async (req, res) => {\n"
            "  const q = 'SELECT * FROM users WHERE id=' + req.query.id;\n"
            "  return db.query(q);\n"
            "});\n"
        )

    idx = CodeIndexer(root)
    assert idx.build_index() == 1  # find_for_vuln reads self.files — empty until built

    vuln = SimpleNamespace(cwe="CWE-89", payload="id=1 OR 1=1", endpoint="http://localhost:3000/users")
    loc = SimpleNamespace(rel="routes.js", url="http://localhost:3000/users")
    matches = idx.find_for_vuln(vuln, loc)
    assert matches
    # Returns ranked dicts — {path, abs_path, score, content} — not bare paths.
    assert matches[0]["path"] == "routes.js"
    assert matches[0]["score"] > 0


def test_code_indexer_find_for_vuln_empty_before_build():
    """Guards the trap this test itself fell into: an unbuilt index matches nothing."""
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "routes.js"), "w", encoding="utf-8") as f:
        f.write("router.get('/users', (req, res) => db.query('SELECT 1'));\n")

    idx = CodeIndexer(root)
    vuln = SimpleNamespace(cwe="CWE-89", payload="", endpoint="http://localhost:3000/users")
    assert idx.find_for_vuln(vuln, None) == []


def test_kb_primary_strategy_for_sqli():
    kb = load_security_kb()
    strategy = kb.primary_strategy("CWE-89")

    assert strategy is not None
    # .pattern is example code; the prose lives in .name / .description.
    assert "?" in strategy.pattern or "$1" in strategy.pattern
    assert "parameter" in f"{strategy.name} {strategy.description}".lower()


def test_kb_unknown_cwe_returns_none():
    assert load_security_kb().primary_strategy("CWE-00000") is None
