"""Verifier tests: verdict algebra, static re-scan, dynamic replay, anti-gaming guards.

These exercise the real `backend.patch.verifier` API. An earlier version of this
file was written against an API that no longer exists (module-level PASS/FAIL/
UNVERIFIABLE constants, public check_suppression/check_blast_radius returning
`(ok, evidence)` tuples, and (vuln, location) argument order), so it failed at
import and every test in it was silently skipped.

The verdict is a plain string — "PASS" | "FAIL" | "UNVERIFIABLE" — so that is
what these assert against.
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch import verifier as V  # noqa: E402
from backend.patch.verifier import (  # noqa: E402
    VerifyResult,
    verify_static,
    verify_dynamic,
    _check_no_suppression,
    _check_blast_radius,
)


class _V:
    """Stand-in for a Vuln."""

    def __init__(self, name="SQL Injection", cwe="CWE-89", payload="id=1 OR 1=1"):
        self.name = name
        self.cwe = cwe
        self.payload = payload
        self.dumped_data = ""
        self.rce_output = ""


def _loc(rel="app.py", line=10, file="/tmp/app.py"):
    """Stand-in for a Location (static path)."""
    return SimpleNamespace(kind="file", file=file, rel=rel, line=line)


# ── Verdict algebra ───────────────────────────────────────────────────

def test_all_checks_pass_is_pass():
    assert VerifyResult.compute_verdict(True, True, True, True, True) == "PASS"


@pytest.mark.parametrize("finding_gone,builds", [(False, True), (True, False)])
def test_a_check_that_ran_and_failed_is_fail(finding_gone, builds):
    assert VerifyResult.compute_verdict(finding_gone, builds, True, True, True) == "FAIL"


@pytest.mark.parametrize("flag", ["endpoint_alive", "no_suppression", "blast_ok"])
def test_boolean_guard_failure_is_fail(flag):
    kwargs = {"endpoint_alive": True, "no_suppression": True, "blast_ok": True}
    kwargs[flag] = False
    assert VerifyResult.compute_verdict(True, True, **kwargs) == "FAIL"


@pytest.mark.parametrize("finding_gone,builds", [(None, True), (True, None), (None, None)])
def test_unrun_check_is_unverifiable_never_pass(finding_gone, builds):
    """None means 'could not be measured' and must never be coerced into a PASS."""
    assert VerifyResult.compute_verdict(finding_gone, builds, True, True, True) == "UNVERIFIABLE"


def test_real_failure_outranks_unverifiable():
    """A check that ran and failed decides the verdict even if another never ran."""
    assert VerifyResult.compute_verdict(False, None, True, True, True) == "FAIL"


# ── Anti-gaming guards ────────────────────────────────────────────────

def test_added_suppression_marker_is_rejected():
    assert _check_no_suppression("return x\n", "# nosemgrep\nreturn x\n") is False


def test_pre_existing_suppression_marker_is_allowed():
    """The guard is about markers the patch *adds*, not ones already there."""
    src = "# nosemgrep\nreturn x\n"
    assert _check_no_suppression(src, src) is True


def test_gutting_the_file_is_rejected():
    """Deleting >70% of non-blank lines reads as 'fixed by deletion'."""
    original = "\n".join(f"line{i}" for i in range(1, 21)) + "\n"
    assert _check_no_suppression(original, "line1\n") is False


def test_blast_radius_over_cap_fails():
    original = "\n".join(f"line{i}" for i in range(1, 5)) + "\n"
    patched = "\n".join(f"line{i}" for i in range(1, 60)) + "\n"
    assert _check_blast_radius(original, patched, cap=10) is False


def test_blast_radius_rewrite_not_double_counted():
    """A pure N-line rewrite must count as N changed lines, not 2N.

    Guards the regression where ndiff summed '+' and '-' lines, doubling every
    rewrite and falsely rejecting legitimate multi-line fixes. Bracketing the
    cap at exactly 20 pins the count without needing an evidence dict.
    """
    original = "\n".join(f"old{i}" for i in range(1, 21)) + "\n"   # 20 lines
    patched = "\n".join(f"new{i}" for i in range(1, 21)) + "\n"    # 20 lines, all changed

    assert _check_blast_radius(original, patched, cap=20) is True   # exactly 20 → fits
    assert _check_blast_radius(original, patched, cap=19) is False  # 20 > 19 → rejected
    # Under the old 2N counting this would have been 40 and failed at cap=25.
    assert _check_blast_radius(original, patched, cap=25) is True


# ── Static verification ───────────────────────────────────────────────

def test_verify_static_pass_when_finding_removed(monkeypatch):
    monkeypatch.setattr("cyphex.scanner.run_static_analysis", lambda _d, **_kw: [])

    res = verify_static(
        _loc(), _V(), ".",
        parse_valid=True, original_content="x = 1\n", patched_content="x = safe(1)\n",
    )
    assert res.finding_gone is True
    assert res.verdict == "PASS"


def test_verify_static_fail_when_same_cwe_still_present(monkeypatch):
    finding = SimpleNamespace(
        file_path="app.py", line_number=10, cwe="CWE-89", name="SQL Injection",
    )
    monkeypatch.setattr("cyphex.scanner.run_static_analysis", lambda _d, **_kw: [finding])

    res = verify_static(
        _loc(), _V(), ".",
        parse_valid=True, original_content="x = 1\n", patched_content="x = safe(1)\n",
    )
    assert res.finding_gone is False
    assert res.verdict == "FAIL"


def test_verify_static_unverifiable_when_scanner_unavailable(monkeypatch):
    """A scanner that blows up must yield UNVERIFIABLE, never a PASS."""
    def _boom(*_a, **_kw):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr("cyphex.scanner.run_static_analysis", _boom)

    res = verify_static(
        _loc(), _V(), ".",
        parse_valid=True, original_content="x = 1\n", patched_content="x = safe(1)\n",
    )
    assert res.finding_gone is None
    assert res.verdict == "UNVERIFIABLE"


@pytest.mark.parametrize("other_path", ["other/module.py", "other/app.py"])
def test_verify_static_ignores_finding_in_a_different_file(monkeypatch, other_path):
    """Same CWE and line, different file — must not count as 'still present'.

    The second case is the one that matters: `other/app.py` shares a basename
    with the target. _paths_match deliberately refuses basename-only matching,
    because two files can share a name in different directories and matching on
    it would let an unrelated file's finding decide this file's verdict.
    """
    finding = SimpleNamespace(
        file_path=other_path, line_number=10, cwe="CWE-89", name="SQL Injection",
    )
    monkeypatch.setattr("cyphex.scanner.run_static_analysis", lambda _d, **_kw: [finding])

    res = verify_static(
        _loc(), _V(), ".",
        parse_valid=True, original_content="x = 1\n", patched_content="x = safe(1)\n",
    )
    assert res.finding_gone is True


def test_verify_static_syntax_failure_is_fail(monkeypatch):
    monkeypatch.setattr("cyphex.scanner.run_static_analysis", lambda _d, **_kw: [])

    res = verify_static(
        _loc(), _V(), ".",
        parse_valid=False, original_content="x = 1\n", patched_content="x = safe(1\n",
    )
    assert res.verdict == "FAIL"


def test_rescan_hides_nothing_from_the_verifier(monkeypatch):
    """The re-scan must ask the scanner to keep comment matches.

    Ordinary scans treat a match inside a comment as a false positive. If the
    re-scan did the same, a patch that merely comments the vulnerable line out
    would register as 'finding gone' and PASS.
    """
    seen = {}

    def _spy(_source_dir, **kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr("cyphex.scanner.run_static_analysis", _spy)
    verify_static(_loc(), _V(), ".", parse_valid=True)

    assert seen.get("flag_comments") is False


# ── Dynamic verification ──────────────────────────────────────────────

class _Resp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Serves queued responses; one AsyncClient() per verifier call site."""

    def __init__(self, responses):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    def _next(self):
        return self._responses.pop(0) if self._responses else _Resp(200, "ok")

    async def request(self, _method, _url, **_kwargs):
        return self._next()

    async def get(self, _url, **_kwargs):
        return self._next()


def _fake_httpx(monkeypatch, replay: _Resp, liveness: _Resp = None):
    """Patch the httpx bound inside verifier (module-level import, not sys.modules)."""
    liveness = liveness or _Resp(200, "ok")
    queues = iter([[replay], [liveness]])

    class _Httpx:
        @staticmethod
        def AsyncClient(**_kwargs):
            return _FakeClient(next(queues))

    monkeypatch.setattr(V, "httpx", _Httpx)
    monkeypatch.setattr(V, "HAS_HTTPX", True)


@pytest.mark.asyncio
async def test_verify_dynamic_unverifiable_without_httpx(monkeypatch):
    monkeypatch.setattr(V, "HAS_HTTPX", False)
    res = await verify_dynamic(SimpleNamespace(url=None, method="GET"), _V())
    assert res.verdict == "UNVERIFIABLE"


@pytest.mark.asyncio
async def test_verify_dynamic_pass_when_exploit_blocked(monkeypatch):
    _fake_httpx(monkeypatch, replay=_Resp(200, "request rejected"))

    res = await verify_dynamic(
        SimpleNamespace(url="http://localhost:3000/login", method="GET"), _V()
    )
    assert res.finding_gone is True
    assert res.verdict == "PASS"


@pytest.mark.asyncio
async def test_verify_dynamic_fail_when_exploit_still_works(monkeypatch):
    _fake_httpx(monkeypatch, replay=_Resp(200, "SQL syntax error near OR 1=1"))

    res = await verify_dynamic(
        SimpleNamespace(url="http://localhost:3000/login", method="GET"), _V()
    )
    assert res.finding_gone is False
    assert res.verdict == "FAIL"


@pytest.mark.asyncio
async def test_verify_dynamic_fail_when_endpoint_broken(monkeypatch):
    """Blocking the exploit by breaking the endpoint is not a fix."""
    _fake_httpx(
        monkeypatch,
        replay=_Resp(500, "internal server error"),
        liveness=_Resp(500, "internal server error"),
    )

    res = await verify_dynamic(
        SimpleNamespace(url="http://localhost:3000/login", method="GET"), _V()
    )
    assert res.endpoint_alive is False
    assert res.verdict == "FAIL"


@pytest.mark.asyncio
async def test_verify_dynamic_unverifiable_on_network_error(monkeypatch):
    """A replay that never completed is inconclusive, never 'fixed'."""
    class _Boom:
        @staticmethod
        def AsyncClient(**_kwargs):
            raise ConnectionError("connection refused")

    monkeypatch.setattr(V, "httpx", _Boom)
    monkeypatch.setattr(V, "HAS_HTTPX", True)

    res = await verify_dynamic(
        SimpleNamespace(url="http://localhost:3000/login", method="GET"), _V()
    )
    assert res.finding_gone is None
    assert res.verdict in ("UNVERIFIABLE", "FAIL")
