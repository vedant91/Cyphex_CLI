"""
CYPHEX — Proof-Carrying Regression Test Generator

For each verified fix, generate a security regression test that:
  - Dynamic: replays the exploit payload and asserts it fails
  - Static: checks the scanner rule at the patched location

Tests are committed alongside the fix.
If someone reintroduces the vulnerability, the test breaks.

SECURITY NOTE: every field interpolated below (name, cwe, file_path, path,
payload, ...) can be influenced by the scanner or an LLM, and the generated
text is source code that later gets *executed* in CI. Every interpolated
string value is therefore JSON-encoded the same way `payload` always was
(json.dumps produces a syntactically-safe string literal in both JS and
Python), `cwe` is validated against a strict pattern before it's ever used
unescaped inside an identifier/filename, and the output filename is
sanitized to remove path separators and traversal sequences.
"""

import json
import os
import re
from typing import Optional
from datetime import datetime, timezone


_CWE_RE = re.compile(r'^CWE-\d+$')


def _safe_cwe(cwe: str) -> str:
    """
    Validate that cwe matches the expected "CWE-<digits>" format.

    cwe gets spliced *unescaped* into Python/JS identifiers and comments
    below (e.g. `test_{cwe.lower()...}`), so anything other than digits and
    a hyphen there could inject arbitrary code into the generated test file.
    Falls back to a safe placeholder if the value doesn't match.
    """
    cwe = (cwe or "").strip()
    return cwe if _CWE_RE.match(cwe) else "CWE-0"


def _comment_safe(value: str) -> str:
    """
    Make a string safe to embed inside a JS block comment (/* ... */).

    Even though the risky contexts below use json.dumps() for anything that
    ends up as an executable string literal, the human-readable header
    comment also interpolates raw text (e.g. the vuln name) — an attacker
    supplying "*/" there could prematurely close the comment and turn the
    rest of the header into live code. Neutralize that sequence.
    """
    return (value or "").replace("*/", "*\\/")


def generate_regression_test(vuln, location, framework: str = "jest") -> Optional[str]:
    """
    Generate a security regression test for a verified fix.

    Args:
        vuln: The original Vuln
        location: Resolved Location
        framework: Test framework to generate for ("jest", "mocha", "pytest")

    Returns:
        Test file content as string, or None if no test can be generated
    """
    if location is None:
        return None

    vuln_name = getattr(vuln, "name", "Unknown Vulnerability")
    cwe = _safe_cwe(getattr(vuln, "cwe", ""))
    payload = getattr(vuln, "payload", "") or ""

    # Clean the vuln name for use as test description
    clean_name = vuln_name.replace("[STATIC] ", "").replace("[DYNAMIC] ", "")

    if location.kind == "url":
        return _generate_dynamic_test(clean_name, cwe, location, payload, framework)
    elif location.kind == "file":
        return _generate_static_test(clean_name, cwe, location, framework)

    return None


def _generate_dynamic_test(name: str, cwe: str, location, payload: str, framework: str) -> str:
    """Generate a test that replays the exploit and asserts it fails."""
    url = location.url or "http://localhost:3000/"
    method = (location.method or "GET").upper()

    # Extract path from URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or "/"

    # Escape every interpolated value for its string-literal context. json.dumps
    # produces output that's a valid string literal in both JS and Python, so
    # it's safe to reuse for path/name/etc, not just payload.
    escaped_payload = json.dumps(payload)
    escaped_path = json.dumps(path)
    name_comment = _comment_safe(name)

    if framework in ("jest", "mocha"):
        describe_str = json.dumps(f"Security Regression: {name}")
        it_block_str = json.dumps(f"should block {cwe} exploit payload on {method} {path}")
        it_alive_str = json.dumps(f"{path} endpoint should still work for benign requests")

        return f'''/**
 * CYPHEX Security Regression Test
 * Vulnerability: {name_comment} ({cwe})
 * Generated: {datetime.now(timezone.utc).isoformat()}
 *
 * DO NOT DELETE — this test prevents reintroduction of {cwe}
 * If this test fails, a previously-fixed vulnerability has been reintroduced.
 */

const request = require('supertest');
const app = require('../app'); // Adjust path to your app

describe({describe_str}, () => {{
  it({it_block_str}, async () => {{
    const payload = {escaped_payload};

    const response = await request(app)
      .{method.lower()}({escaped_path})
      {f".send(payload)" if method == "POST" else f".query({{ q: payload }})"}
      .set('Content-Type', 'application/json');

    // The exploit payload must NOT succeed
    // Status 400 (bad request) or 403 (forbidden) = correctly blocked
    expect(response.status).toBeGreaterThanOrEqual(400);
  }});

  it({it_alive_str}, async () => {{
    const response = await request(app)
      .get({escaped_path})
      .set('Content-Type', 'application/json');

    // Endpoint must still be alive (not deleted to "fix" the vuln)
    expect(response.status).toBeLessThan(500);
  }});
}});
'''
    elif framework == "pytest":
        # cwe is validated by _safe_cwe() to match ^CWE-\d+$, so this identifier
        # splice is safe (digits/hyphen only → e.g. "cwe_89").
        test_slug = cwe.lower().replace("-", "_")

        return f'''"""
CYPHEX Security Regression Test
Vulnerability: {name_comment} ({cwe})
Generated: {datetime.now(timezone.utc).isoformat()}

DO NOT DELETE — this test prevents reintroduction of {cwe}
"""

import requests
import pytest


BASE_URL = "http://localhost:3000"


def test_{test_slug}_exploit_blocked():
    """The exploit payload must be blocked after the fix."""
    payload = {escaped_payload}

    response = requests.{method.lower()}(
        BASE_URL + {escaped_path},
        {"json=payload" if method == "POST" else f"params={{'q': payload}}"},
        timeout=10,
    )

    assert response.status_code >= 400, (
        f"Exploit still works! Status {{response.status_code}}"
    )


def test_{test_slug}_endpoint_alive():
    """The endpoint must still respond to benign requests."""
    response = requests.get(BASE_URL + {escaped_path}, timeout=10)
    assert response.status_code < 500, (
        f"Endpoint broken! Status {{response.status_code}}"
    )
'''

    return None


def _generate_static_test(name: str, cwe: str, location, framework: str) -> str:
    """Generate a test that checks the scanner rule at the patched location."""
    file_path = location.rel or location.file or "unknown"
    line = location.line or 0

    name_comment = _comment_safe(name)
    file_path_comment = _comment_safe(file_path)

    describe_str = json.dumps(f"Security Regression: {name}")
    it_str = json.dumps(f"should not contain {cwe} pattern in {file_path}")
    resolve_arg = json.dumps("../" + file_path)
    fail_msg = json.dumps(f"{cwe} pattern found near line {line} in {file_path}")

    return f'''/**
 * CYPHEX Security Regression Test (Static)
 * Vulnerability: {name_comment} ({cwe})
 * Location: {file_path_comment}:{line}
 * Generated: {datetime.now(timezone.utc).isoformat()}
 *
 * DO NOT DELETE — this test prevents reintroduction of {cwe}
 */

const fs = require('fs');
const path = require('path');

describe({describe_str}, () => {{
  it({it_str}, () => {{
    const filePath = path.resolve(__dirname, {resolve_arg});
    const content = fs.readFileSync(filePath, 'utf-8');

    // Check that the vulnerable pattern is no longer present
    // Adjust the pattern below based on the specific vulnerability
    const dangerousPatterns = [
      /\\$\\{{.*?\\}}/,  // Template literal injection
      /dangerouslySetInnerHTML/,  // XSS via React
    ];

    dangerousPatterns.forEach(pattern => {{
      const nearLine = content.split('\\n').slice({max(0, line - 3)}, {line + 2}).join('\\n');
      // Only flag if the pattern is near the originally-vulnerable line
      if (pattern.test(nearLine)) {{
        fail({fail_msg});
      }}
    }});
  }});
}});
'''


def _safe_test_filename(name: str) -> str:
    """
    Sanitize a name for safe use as a filename component.

    Collapses anything that isn't a conservative [a-z0-9_-] charset into '_'.
    This already strips '/' and '\\' (both are directory separators — on
    Windows '\\' is one too, and the old implementation only stripped '/')
    and eliminates '.' entirely, so a "../../etc/passwd"-style traversal
    payload can't survive as a run of literal ".." characters either.
    """
    base = (name or "unnamed").lower().replace(" ", "_")
    base = re.sub(r"[^a-z0-9_-]+", "_", base)
    base = base.strip("_") or "unnamed"
    return base[:50]


def write_regression_tests(tests: list, output_dir: str) -> list:
    """
    Write generated regression tests to the test directory.

    Args:
        tests: List of (test_name, test_content) tuples
        output_dir: Directory to write tests into

    Returns:
        List of written file paths
    """
    test_dir = os.path.join(output_dir, "tests", "security")
    os.makedirs(test_dir, exist_ok=True)

    written = []
    for name, content in tests:
        if not content:
            continue
        safe_name = _safe_test_filename(name)
        filename = f"test_regression_{safe_name}.js"
        filepath = os.path.join(test_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        written.append(filepath)

    return written
