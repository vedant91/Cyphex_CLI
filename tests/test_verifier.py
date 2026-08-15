"""Phase 2 verifier tests: static re-scan, dynamic replay, and anti-gaming guards."""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch.verifier import (  # noqa: E402
    PASS,
    FAIL,
    UNVERIFIABLE,
    verify_static,
    verify_dynamic,
    check_suppression,
    check_blast_radius,
)


class _V:
    def __init__(self, name="SQL Injection", cwe="CWE-89", payload="id=1 OR 1=1"):
        self.name = name
        self.cwe = cwe
        self.payload = payload
        self.dumped_data = ""
        self.rce_output = ""


def test_check_suppression_detects_added_markers():
    ok, evidence = check_suppression("return x\n", "# nosemgrep\nreturn x\n")
    assert not ok
    assert "suppression_added" in evidence


def test_check_blast_radius_over_cap_fails():
    original = "\n".join([f"line{i}" for i in range(1, 5)]) + "\n"
    patched = "\n".join([f"line{i}" for i in range(1, 60)]) + "\n"
    ok, evidence = check_blast_radius(original, patched, cap=10)
    assert not ok
    assert evidence["changed_lines"] > 10


def test_blast_radius_rewrite_not_double_counted():
    """A pure N-line rewrite must count as N changed lines, not 2N.

    Guards against the regression where ndiff summed '+' and '-' lines, doubling
    every rewrite and falsely rejecting legitimate multi-line fixes.
    """
    original = "\n".join([f"old{i}" for i in range(1, 21)]) + "\n"   # 20 lines
    patched = "\n".join([f"new{i}" for i in range(1, 21)]) + "\n"    # 20 lines, all changed
    ok, evidence = check_blast_radius(original, patched, cap=25)
    assert ok                              # 20 <= 25, would FAIL under old 2N counting (40)
    assert evidence["changed_lines"] == 20



def test_verify_static_pass_when_finding_removed(monkeypatch):
    vuln = _V()
    loc = SimpleNamespace(kind="file", file="/tmp/app.py", line=10)

    monkeypatch.setattr("cyphex.scanner.scan_single_file", lambda _f, _s=None: [])

    res = verify_static(vuln, loc, ".", "x = 1\n", "x = safe(1)\n")
    assert res.verdict == PASS
    assert res.finding_gone is True


def test_verify_static_fail_when_same_cwe_still_present(monkeypatch):
    vuln = _V()
    loc = SimpleNamespace(kind="file", file="/tmp/app.py", line=10)
    finding = SimpleNamespace(cwe="CWE-89", line_number=10, name="SQL Injection")

    monkeypatch.setattr("cyphex.scanner.scan_single_file", lambda _f, _s=None: [finding])

    res = verify_static(vuln, loc, ".", "x = 1\n", "x = safe(1)\n")
    assert res.verdict == FAIL
    assert res.finding_gone is False


@pytest.mark.asyncio
async def test_verify_dynamic_unverifiable_without_url():
    vuln = _V()
    loc = SimpleNamespace(url=None, method="GET")
    res = await verify_dynamic(vuln, loc, base_url=None)
    assert res.verdict == UNVERIFIABLE


@pytest.mark.asyncio
async def test_verify_dynamic_pass_and_fail_with_mock_httpx(monkeypatch):
    vuln = _V(name="SQL Injection", cwe="CWE-89", payload="id=1 OR 1=1")
    loc = SimpleNamespace(url="http://localhost:3000/login", method="GET")

    class _Resp:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    class _Client:
        def __init__(self, responses):
            self._responses = responses
            self._i = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, _method, _url, content=None):
            _ = content
            r = self._responses[self._i]
            self._i += 1
            return r

        async def get(self, _url):
            r = self._responses[self._i]
            self._i += 1
            return r

    class _HttpxPass:
        class AsyncClient:
            def __init__(self, timeout=10.0, follow_redirects=True):
                _ = (timeout, follow_redirects)

            async def __aenter__(self):
                self._client = _Client([
                    _Resp(200, "request rejected"),  # exploit replay
                    _Resp(200, "ok"),               # liveness
                ])
                return self._client

            async def __aexit__(self, exc_type, exc, tb):
                return False

    monkeypatch.setitem(sys.modules, "httpx", _HttpxPass)
    pass_res = await verify_dynamic(vuln, loc, base_url="http://localhost:3000")
    assert pass_res.verdict == PASS

    class _HttpxFail:
        class AsyncClient:
            def __init__(self, timeout=10.0, follow_redirects=True):
                _ = (timeout, follow_redirects)

            async def __aenter__(self):
                self._client = _Client([
                    _Resp(200, "SQL syntax error near OR 1=1"),  # exploit still works
                    _Resp(200, "ok"),
                ])
                return self._client

            async def __aexit__(self, exc_type, exc, tb):
                return False

    monkeypatch.setitem(sys.modules, "httpx", _HttpxFail)
    fail_res = await verify_dynamic(vuln, loc, base_url="http://localhost:3000")
    assert fail_res.verdict == FAIL
