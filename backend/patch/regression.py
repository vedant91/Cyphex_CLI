"""
CYPHEX — Proof-Carrying Regression Test Generator

For each verified fix, generate a security regression test that:
  - Dynamic: replays the exploit payload and asserts it fails
  - Static: checks the scanner rule at the patched location

Tests are committed alongside the fix.
If someone reintroduces the vulnerability, the test breaks.
"""

import json
import os
from typing import Optional
from datetime import datetime, timezone


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
    vuln_name = getattr(vuln, "name", "Unknown Vulnerability")
    cwe = getattr(vuln, "cwe", "")
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

    # Escape payload for string literal
    escaped_payload = json.dumps(payload)

    if framework in ("jest", "mocha"):
        return f'''/**
 * CYPHEX Security Regression Test
 * Vulnerability: {name} ({cwe})
 * Generated: {datetime.now(timezone.utc).isoformat()}
 *
 * DO NOT DELETE — this test prevents reintroduction of {cwe}
 * If this test fails, a previously-fixed vulnerability has been reintroduced.
 */

const request = require('supertest');
const app = require('../app'); // Adjust path to your app

describe('Security Regression: {name}', () => {{
  it('should block {cwe} exploit payload on {method} {path}', async () => {{
    const payload = {escaped_payload};
    
    const response = await request(app)
      .{method.lower()}('{path}')
      {f".send(payload)" if method == "POST" else f".query({{ q: payload }})"}
      .set('Content-Type', 'application/json');
    
    // The exploit payload must NOT succeed
    // Status 400 (bad request) or 403 (forbidden) = correctly blocked
    expect(response.status).toBeGreaterThanOrEqual(400);
  }});
  
  it('{path} endpoint should still work for benign requests', async () => {{
    const response = await request(app)
      .get('{path}')
      .set('Content-Type', 'application/json');
    
    // Endpoint must still be alive (not deleted to "fix" the vuln)
    expect(response.status).toBeLessThan(500);
  }});
}});
'''
    elif framework == "pytest":
        return f'''"""
CYPHEX Security Regression Test
Vulnerability: {name} ({cwe})
Generated: {datetime.now(timezone.utc).isoformat()}

DO NOT DELETE — this test prevents reintroduction of {cwe}
"""

import requests
import pytest


BASE_URL = "http://localhost:3000"


def test_{cwe.lower().replace("-", "_")}_exploit_blocked():
    """The exploit payload must be blocked after the fix."""
    payload = {escaped_payload}
    
    response = requests.{method.lower()}(
        f"{{BASE_URL}}{path}",
        {"json=payload" if method == "POST" else f"params={{'q': payload}}"},
        timeout=10,
    )
    
    assert response.status_code >= 400, (
        f"Exploit still works! Status {{response.status_code}}"
    )


def test_{cwe.lower().replace("-", "_")}_endpoint_alive():
    """The endpoint must still respond to benign requests."""
    response = requests.get(f"{{BASE_URL}}{path}", timeout=10)
    assert response.status_code < 500, (
        f"Endpoint broken! Status {{response.status_code}}"
    )
'''

    return None


def _generate_static_test(name: str, cwe: str, location, framework: str) -> str:
    """Generate a test that checks the scanner rule at the patched location."""
    file_path = location.rel or location.file or "unknown"
    line = location.line or 0

    return f'''/**
 * CYPHEX Security Regression Test (Static)
 * Vulnerability: {name} ({cwe})
 * Location: {file_path}:{line}
 * Generated: {datetime.now(timezone.utc).isoformat()}
 *
 * DO NOT DELETE — this test prevents reintroduction of {cwe}
 */

const fs = require('fs');
const path = require('path');

describe('Security Regression: {name}', () => {{
  it('should not contain {cwe} pattern in {file_path}', () => {{
    const filePath = path.resolve(__dirname, '../{file_path}');
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
        fail(`{cwe} pattern found near line {line} in {file_path}`);
      }}
    }});
  }});
}});
'''


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
        safe_name = name.lower().replace(" ", "_").replace("/", "_")[:50]
        filename = f"test_regression_{safe_name}.js"
        filepath = os.path.join(test_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        written.append(filepath)

    return written
