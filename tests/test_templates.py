"""Deterministic template transforms — the zero-model patch path.

An earlier version of this file called `templates.apply(cwe, path, snippet)`
and read `out["fixed_code"]`. The real entry point is:

    apply_template(cwe, code, framework="") -> str | None

It returns the fixed code directly, and only for the four CWEs that have a
transform: 89, 78, 798, 942. There is no CWE-79 (XSS) template, so the old
`innerHTML -> textContent` test asserted a feature that has never existed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from backend.patch.templates import TRANSFORMS, apply_template  # noqa: E402


# ── SQLi (CWE-89) ─────────────────────────────────────────────────────

def test_sqli_template_literal_becomes_parameterised():
    out = apply_template("CWE-89", "const rows = db.query(`SELECT * FROM users WHERE id=${id}`);")
    assert out == 'const rows = db.query("SELECT * FROM users WHERE id=?", [id]);'


def test_sqli_string_concatenation_becomes_parameterised():
    out = apply_template("CWE-89", 'const rows = db.query("SELECT * FROM users WHERE id=" + id);')
    assert out == 'const rows = db.query("SELECT * FROM users WHERE id=?", [id]);'


# ── Command injection (CWE-78) ────────────────────────────────────────

def test_cmdi_template_literal_becomes_execfilesync():
    """The fix is argument-vector exec, which removes the shell entirely."""
    out = apply_template("CWE-78", "execSync(`ping ${host}`);")
    assert out == 'execFileSync("ping", [host]);'
    assert "execSync(" not in out


def test_cmdi_concatenation_becomes_execfilesync():
    out = apply_template("CWE-78", 'execSync("ping " + host);')
    assert out == 'execFileSync("ping", [host]);'


# ── Hardcoded secret (CWE-798) ────────────────────────────────────────

def test_hardcoded_secret_moves_to_env():
    out = apply_template("CWE-798", 'const password = "hunter2secret";')
    assert out == "const password = process.env.PASSWORD;"
    assert "hunter2secret" not in out


# ── Wildcard CORS (CWE-942) ───────────────────────────────────────────

@pytest.mark.parametrize("code", [
    'app.use(cors({ origin: "*" }));',
    "app.use(cors({ origin: '*' }));",
    'res.header("Access-Control-Allow-Origin", "*");',
])
def test_wildcard_cors_is_replaced(code):
    """Regression: detect and transform once accepted disjoint input sets, so
    this template returned None for every possible input."""
    out = apply_template("CWE-942", code)
    assert out is not None, "wildcard CORS template must fire"
    assert out != code
    assert '"*"' not in out and "'*'" not in out
    assert "ALLOWED_ORIGIN" in out


def test_every_declared_template_is_reachable():
    """Guards the class of bug above across all CWEs: a template whose detect
    never overlaps its transform is dead weight that silently patches nothing."""
    samples = {
        "CWE-89": "const rows = db.query(`SELECT * FROM users WHERE id=${id}`);",
        "CWE-78": "execSync(`ping ${host}`);",
        "CWE-798": 'const password = "hunter2secret";',
        "CWE-942": 'app.use(cors({ origin: "*" }));',
    }
    assert set(samples) == set(TRANSFORMS), "a CWE gained/lost a template — add a sample"

    for cwe, code in samples.items():
        assert apply_template(cwe, code) is not None, f"{cwe} template never fires"


# ── Non-applicable input ──────────────────────────────────────────────

def test_returns_none_when_pattern_absent():
    assert apply_template("CWE-89", "const x = 1;") is None


def test_returns_none_for_cwe_without_a_template():
    """No XSS template exists — the caller must fall through to the LLM path."""
    assert apply_template("CWE-79", "element.innerHTML = userInput;") is None


def test_never_returns_unchanged_code():
    """A template that 'fixes' nothing must report None, not echo the input —
    otherwise the pipeline records a patch that changed nothing."""
    code = "const safe = db.query('SELECT 1', []);"
    out = apply_template("CWE-89", code)
    assert out is None or out != code
