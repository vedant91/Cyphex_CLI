"""Phase 3 tests for RAG context extraction and KB/index lookup."""

import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.rag import (  # noqa: E402
    CodeIndexer,
    detect_language,
    extract_function,
    extract_imports,
    load_security_kb,
)


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
    vuln = SimpleNamespace(cwe="CWE-89", payload="id=1 OR 1=1", endpoint="http://localhost:3000/users")
    loc = SimpleNamespace(rel="routes.js", url="http://localhost:3000/users")
    matches = idx.find_for_vuln(vuln, loc)
    assert matches
    assert matches[0] == "routes.js"

    kb = load_security_kb()
    strategy = kb.primary_strategy("CWE-89")
    assert strategy is not None
    assert "placeholder" in strategy.pattern.lower() or "parameter" in strategy.pattern.lower()
