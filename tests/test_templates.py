"""Phase 5 deterministic template transform tests."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch import templates  # noqa: E402


def test_template_xss_innerhtml_to_textcontent():
    snippet = "element.innerHTML = userInput;"
    out = templates.apply("CWE-79", "x.js", snippet)
    assert out is not None
    assert ".textContent" in out["fixed_code"]


def test_template_sqli_returns_parameterized_pattern():
    snippet = "const q = `SELECT * FROM users WHERE id=${id}`"
    out = templates.apply("CWE-89", "x.js", snippet)
    assert out is not None
    assert "?" in out["fixed_code"]


def test_template_returns_none_when_not_applicable():
    snippet = "const x = 1;"
    out = templates.apply("CWE-89", "x.js", snippet)
    assert out is None
