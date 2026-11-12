"""Live, read-only view of a running scan, derived from the job record (like narrate.py).

banner(job)   one line added to every scan tool result as `status_line`, so the person sees where the
              scan is even when the host model does not narrate (Claude Desktop shows tool results raw).
serve         a localhost-only page, /status/<job_id>, that refreshes itself: keep it open in a browser tab.

Nothing here writes to the job or the disk. Everything shown comes from agents, so it is HTML-escaped.
"""
from __future__ import annotations

import html
import inspect
import os
import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import ledger, narrate

_ID = re.compile(r"[0-9a-f]{12}")
_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MARK = "Cyphex status"  # how a second MCP process recognises the first one's page on the same port


def stages(job: dict) -> list[tuple[str, str]]:
    """The eight steps of a run with their state: done | running | waiting | skipped."""
    steps, roster = job.get("steps", []), job.get("roster") or {}
    by = lambda role: [s for s in steps if s["role"] == role]  # noqa: E731
    pend = [n for n, r in roster.items() if r.get("deployed") and not r.get("reported")]
    pending = lambda role, rev=None: any(  # noqa: E731
        roster[n].get("role") == role and (rev is None or ("reviewer" in n) == rev) for n in pend)
    patch = by("patch_crew")
    is_rev = lambda s: "reviewer" in s["summary"]  # noqa: E731
    proved = any((f.get("patch") or {}).get("verify") for f in job.get("findings", {}).values())
    rows = [
        ("Map the app", bool(by("recon")), pending("recon")),
        ("Read the code, one agent per bug class", bool(by("deep_sast")) and not pending("deep_sast"), pending("deep_sast")),
        ("Attack the running app", bool(by("deep_dast")), pending("deep_dast")),
        ("Independent second opinion", bool(by("council")) and not pending("council"), pending("council")),
        ("Write fixes", any(not is_rev(s) for s in patch), pending("patch_crew", False)),
        ("Review the fixes", any(is_rev(s) for s in patch) and not pending("patch_crew", True), pending("patch_crew", True)),
        ("Prove the fixes", proved, False),
        ("Check the agents themselves", bool(job.get("agent_security")), pending("agent_security")),
    ]
    skip = (job.get("decisions") or {}).get("sandbox") == "skip"
    return [(n, "skipped" if i == 2 and skip and not d else "done" if d else "running" if r else "waiting")
            for i, (n, d, r) in enumerate(rows)]


def _current(st: list[tuple[str, str]]) -> int | None:
    """Index of the step in progress: the first running one, else the one after the furthest done step."""
    run = [i for i, (_, s) in enumerate(st) if s == "running"]
    if run:
        return run[0]
    last = max((i for i, (_, s) in enumerate(st) if s == "done"), default=-1)
    return next((i for i in range(last + 1, len(st)) if st[i][1] != "skipped"), None)


def banner(job: dict) -> str:
    st = stages(job)
    cur = _current(st)
    fs = list(job.get("findings", {}).values())
    lvl = [ledger.proof_level(f) for f in fs]
    ros = [r for r in (job.get("roster") or {}).values() if r.get("deployed")]
    where = "all steps done" if cur is None else f"step {cur + 1} of 8, {st[cur][0].lower()} ({st[cur][1]})"
    agents = f" · agents {sum(1 for r in ros if r.get('reported'))}/{len(ros)} reported" if ros else ""
    sandbox = (job.get("decisions") or {}).get("sandbox") or "not chosen"
    return (f"Cyphex job {job['job_id']} · {where}{agents} · {len(fs)} findings "
            f"({lvl.count('confirmed') + lvl.count('proven')} confirmed, {lvl.count('proven')} proven by attack, "
            f"{sum(1 for f in fs if ledger.patch_status(f) == 'verified fixed')} verified fixed) · sandbox: {sandbox}")


def with_banner(out, fn, args: tuple, kw: dict, remote: bool = False):
    """Put `status_line` (and `status_url`) first in a tool result that belongs to a scan. Never raises:
    a cosmetic line must not be able to break a tool."""
    if not isinstance(out, dict) or "status_line" in out:
        return out
    try:
        jid = str(out.get("job_id") or inspect.signature(fn).bind_partial(*args, **kw).arguments.get("job_id") or "")
        if not _ID.fullmatch(jid):
            return out
        extra = {"status_line": banner(ledger.load_job(jid))}
        u = "" if remote else url(jid)
        if u:
            extra["status_url"] = u
        return {**extra, **out}
    except Exception:
        return out


# ---------------------------------------------------------------- the page

_CSS = """
:root{--bg:#fff;--fg:#1a1d21;--mut:#5d6672;--line:#d9dde3;--ok:#1a7f4b;--run:#a15c00;--card:#f6f7f9}
@media(prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e6e8eb;--mut:#9aa3ae;--line:#2c323a;--ok:#4cc38a;--run:#f0b04a;--card:#1b1f24}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:920px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}
.mut{color:var(--mut)}ol,ul{list-style:none;padding:0;margin:0}
li.step{display:flex;justify-content:space-between;padding:8px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:6px;background:var(--card)}
li.done span{color:var(--ok)}li.running span{color:var(--run);font-weight:600}li.skipped,li.waiting{color:var(--mut)}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{padding:2px 9px;border:1px solid var(--line);border-radius:12px;font-size:13px}
.chip.done{border-color:var(--ok)}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
li.ev{padding:4px 0;border-bottom:1px solid var(--line)}li.ev time{color:var(--mut);margin-right:8px}
"""


def page(job: dict) -> str:
    e = html.escape
    st = stages(job)
    badge = {"done": "done", "running": "running now", "waiting": "waiting", "skipped": "skipped"}
    steps = "".join(f'<li class="step {s}"><b>{i}. {e(n)}</b><span>{badge[s]}</span></li>' for i, (n, s) in enumerate(st, 1))
    chips = "".join(f'<span class="chip {"done" if r.get("reported") else ""}">{e(n.replace("cyphex-", ""))}'
                    f'{" ✔" if r.get("reported") else " …"}</span>'
                    for n, r in (job.get("roster") or {}).items() if r.get("deployed"))
    fs = sorted(job.get("findings", {}).values(), key=lambda f: (_SEV.get(f.get("severity"), 9), str(f.get("id", ""))))
    rows = "".join(
        f"<tr><td>{e(str(f.get('id', '')))}</td><td>{e(str(f.get('severity', '')))}</td><td>{e(ledger.proof_level(f))}</td>"
        f"<td>{e(ledger.patch_status(f))}</td><td>{e(str(f.get('file', '')))}:{e(str(f.get('line', '')))}</td></tr>" for f in fs)
    feed = "".join(f'<li class="ev"><time>{e(x["time"])}</time>{e(x["say"])}</li>'
                   for x in reversed(narrate.progress(job)["feed"]))
    # job["status"] stays "running" forever, so "finished" means every step is done and the report is written
    done = _current(st) is None and bool(job.get("report_path"))
    live = "" if done or job.get("status") != "running" else '<meta http-equiv="refresh" content="3">'
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"{live}<title>{_MARK} {e(job['job_id'])}</title><style>{_CSS}</style></head><body><main>"
            f"<h1>Cyphex scan {e(job['job_id'])}</h1><div class=\"mut\">{e(banner(job))}</div>"
            f"<div class=\"mut\">{e(str(job.get('repo_path', '')))} · {'refreshes every 3 s' if live else 'finished'} · read-only, this machine only</div>"
            f"<h2>Steps</h2><ol>{steps}</ol>"
            f"<h2>Agents</h2><div class=\"chips\">{chips or '<span class=mut>none deployed (inline mode or not started)</span>'}</div>"
            f"<h2>Findings ({len(fs)})</h2><table><tr><th>id</th><th>severity</th><th>proof</th><th>fix</th><th>where</th></tr>{rows}</table>"
            f"<h2>What happened (newest first)</h2><ul>{feed or '<li class=mut>nothing yet</li>'}</ul></main></body></html>")


def index() -> str:
    e = html.escape
    rows = "".join(f'<li class="ev"><a href="/status/{e(r["job_id"])}">{e(r["job_id"])}</a> · {e(r["at"])} · '
                   f'{e(str(r["repo"]))} · {r["findings"]} findings</li>' for r in ledger.history(30))
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{_MARK}</title><style>{_CSS}</style></head>'
            f"<body><main><h1>{_MARK}</h1><h2>Recent scans</h2><ul>{rows or '<li class=mut>no scans yet</li>'}</ul></main></body></html>")


# ---------------------------------------------------------------- the server

class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
        data = body.encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                     ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        # A web page on the internet can point its own hostname at 127.0.0.1 and read this: only answer to our own names.
        if (self.headers.get("Host") or "").rsplit(":", 1)[0] not in ("127.0.0.1", "localhost"):
            return self._send(403, "forbidden", "text/plain")
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, index())
        m = re.fullmatch(r"/status/([0-9a-f]{12})", path)
        if not m:
            return self._send(404, "not found", "text/plain")
        try:
            return self._send(200, page(ledger.load_job(m.group(1))))
        except KeyError:
            return self._send(404, "no such job", "text/plain")

    def log_message(self, *a):  # stdout belongs to the MCP protocol in stdio mode: never print
        pass


_port: int | None = None
_lock = threading.Lock()


def ensure_server() -> int:
    """Start the page once per process on 127.0.0.1:CYPHEX_STATUS_PORT (default 8777; 0 turns it off).
    Returns the port, or 0 if there is no page. If the port is taken by another Cyphex process (Claude
    Desktop and Claude Code can each launch one) the page is already up, and it reads the same jobs folder."""
    global _port
    with _lock:
        if _port is not None:
            return _port
        want = int(os.environ.get("CYPHEX_STATUS_PORT", "8777") or 0)
        _port = 0
        if want:
            try:
                srv = ThreadingHTTPServer(("127.0.0.1", want), _Handler)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                _port = want
            except OSError:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{want}/", timeout=1) as r:
                        _port = want if _MARK.encode() in r.read(2000) else 0
                except Exception:
                    _port = 0
        return _port


def url(job_id: str) -> str:
    p = ensure_server()
    return f"http://127.0.0.1:{p}/status/{job_id}" if p else ""
