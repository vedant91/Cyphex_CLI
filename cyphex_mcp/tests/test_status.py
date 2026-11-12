"""Checks for the status banner and the live status page.

Run: python -m cyphex_mcp.tests.test_status  (stdlib only, plus the mcp SDK for the one end-to-end check)
"""
import asyncio
import http.client
import json
import os
import tempfile
import threading
from http.server import ThreadingHTTPServer

from cyphex_mcp import ledger, status

os.environ["CYPHEX_STATUS_PORT"] = "0"  # tests never open the real page port


def _job(**over):
    j = {"job_id": "0123456789ab", "created_at": "2026-11-10T11:00:00+00:00", "status": "running", "repo_path": "/x",
         "decisions": {"sandbox": "create"}, "steps": [], "roster": {}, "findings": {}}
    j.update(over)
    return j


def _step(role, summary=None, agent="cyphex-x"):
    return {"role": role, "agent": agent, "at": "2026-11-10T11:01:02+00:00", "summary": summary or {}}


def _agent(role, reported):
    return {"role": role, "deployed": True, "reported": reported}


def test_banner_on_a_new_scan_points_at_step_one():
    b = status.banner(_job())
    assert "step 1 of 8, map the app (waiting)" in b and "0 findings" in b and "sandbox: create" in b


def test_banner_follows_the_agents_that_are_still_working():
    j = _job(steps=[_step("recon"), _step("deep_sast")],
             roster={"cyphex-recon": _agent("recon", 1), "cyphex-sqli": _agent("deep_sast", 1), "cyphex-xss": _agent("deep_sast", 0)})
    b = status.banner(j)
    assert "step 2 of 8, read the code, one agent per bug class (running)" in b and "agents 2/3 reported" in b


def test_banner_skips_the_attack_step_when_there_is_no_sandbox():
    j = _job(decisions={"sandbox": "skip"}, steps=[_step("recon"), _step("deep_sast")])
    st = dict(status.stages(j))
    assert st["Attack the running app"] == "skipped"
    assert "step 4 of 8" in status.banner(j)  # moves on to the review board, not back to the skipped step


def test_banner_does_not_stall_on_a_step_that_never_reported():
    # the attack step was blocked, but later steps did happen: the banner must follow the furthest step
    j = _job(steps=[_step("recon"), _step("deep_sast"), _step("council", {"finding": "a"})])
    assert "step 5 of 8" in status.banner(j)


def test_banner_counts_confirmed_proven_and_fixed():
    fs = {"a": {"id": "a", "council": {"verdict": "confirmed"}},
          "b": {"id": "b", "dast": {"proven": True}, "patch": {"verify": {"verdict": "PASS"}}},
          "c": {"id": "c"}}
    b = status.banner(_job(findings=fs))
    assert "3 findings (2 confirmed, 1 proven by attack, 1 verified fixed)" in b


def test_page_escapes_everything_an_agent_can_write():
    evil = "<script>alert(1)</script>"
    j = _job(findings={evil: {"id": evil, "severity": "high", "file": "<img src=x onerror=1>", "line": 1}},
             roster={"cyphex-<u>zz</u>": _agent("deep_sast", 0)}, repo_path="<i>repo</i>")
    page = status.page(j)
    # the page uses <b> itself, so the payloads use tags it never emits
    assert "<script>alert(1)" not in page and "<img src=x" not in page and "<i>repo" not in page and "<u>zz" not in page
    assert "&lt;script&gt;alert(1)" in page and "&lt;u&gt;zz" in page


def test_page_refreshes_only_while_the_job_runs():
    assert 'http-equiv="refresh"' in status.page(_job())
    assert 'http-equiv="refresh"' not in status.page(_job(status="done"))
    # job["status"] is never set to done, so "finished" is: every step done and the report written
    steps = [_step(r) for r in ("recon", "deep_sast", "deep_dast", "council")] + [
        _step("patch_crew", {"finding": "a"}), _step("patch_crew", {"finding": "a", "reviewer": "x"})]
    fs = {"a": {"id": "a", "patch": {"verify": {"verdict": "PASS"}}}}
    all_done = _job(steps=steps, findings=fs, agent_security={"checked": 1})  # the audit is recorded on the job, not as a step
    assert 'http-equiv="refresh"' in status.page(all_done)  # steps done but no report yet: still live
    assert 'http-equiv="refresh"' not in status.page({**all_done, "report_path": "/x/cyphex-report.html"})


def test_with_banner_goes_first_and_leaves_everything_else_alone():
    os.environ["CYPHEX_DATA_DIR"] = tempfile.mkdtemp()
    status._port = None  # re-read CYPHEX_STATUS_PORT=0: no page in tests
    j = ledger.new_job("node", {"event": "push"}, "/x")

    def fn(job_id: str):
        return {"answer": 1}

    out = status.with_banner({"answer": 1}, fn, (j["job_id"],), {})
    assert list(out)[0] == "status_line" and out["answer"] == 1 and j["job_id"] in out["status_line"]
    assert "status_url" not in out  # the page is off in tests
    assert status.with_banner({"answer": 1}, fn, (), {"job_id": j["job_id"]})["status_line"]
    # not a scan result, not a dict, unknown job, hostile id, banner already there: all returned unchanged
    assert status.with_banner({"answer": 1}, fn, (), {}) == {"answer": 1}
    assert status.with_banner("text", fn, (j["job_id"],), {}) == "text"
    assert status.with_banner({"answer": 1}, fn, ("ffffffffffff",), {}) == {"answer": 1}
    assert status.with_banner({"answer": 1}, fn, ("../../etc/passwd",), {}) == {"answer": 1}
    assert status.with_banner({"status_line": "mine"}, fn, (j["job_id"],), {}) == {"status_line": "mine"}


def _get(port, path, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("GET", path, skip_host=True)
    c.putheader("Host", host or f"127.0.0.1:{port}")
    c.endheaders()
    r = c.getresponse()
    return r.status, r.read().decode(), dict(r.getheaders())


def test_the_page_server_is_read_only_and_refuses_strangers():
    os.environ["CYPHEX_DATA_DIR"] = tempfile.mkdtemp()
    j = ledger.new_job("node", {"event": "push"}, "/x")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), status._Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        code, body, hdr = _get(port, f"/status/{j['job_id']}")
        assert code == 200 and j["job_id"] in body and "default-src 'none'" in hdr["Content-Security-Policy"]
        assert _get(port, "/")[0] == 200
        assert _get(port, f"/status/{j['job_id']}", host="evil.example")[0] == 403  # DNS-rebinding guard
        assert _get(port, f"/status/{j['job_id']}", host=f"localhost:{port}")[0] == 200
        assert _get(port, "/status/ffffffffffff")[0] == 404  # valid shape, no such job
        assert _get(port, "/status/../../etc/passwd")[0] == 404  # only 12 hex characters are ever looked up
        assert _get(port, "/anything-else")[0] == 404
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", f"/status/{j['job_id']}", body="x")
        assert c.getresponse().status in (501, 405)  # no write verbs
    finally:
        srv.shutdown()


def test_ensure_server_can_be_turned_off_and_never_raises():
    os.environ["CYPHEX_STATUS_PORT"] = "0"
    status._port = None
    assert status.ensure_server() == 0 and status.url("0123456789ab") == ""


def test_a_real_tool_call_carries_the_status_line_and_keeps_its_schema():
    try:
        from cyphex_mcp.server import build_server
    except ImportError:
        return  # the mcp SDK is not installed: nothing to check end to end
    os.environ["CYPHEX_DATA_DIR"] = tempfile.mkdtemp()
    status._port = None
    j = ledger.new_job("node", {"event": "push"}, "/x")
    mcp = build_server()

    async def go():
        tools = {t.name: t for t in await mcp.list_tools()}
        assert "job_id" in tools["get_progress"].inputSchema["properties"]  # the wrapper did not hide the arguments
        res = await mcp.call_tool("get_progress", {"job_id": j["job_id"]})
        content = res[0] if isinstance(res, tuple) else res
        text = content[0].text if isinstance(content, list) else str(content)
        return json.loads(text)

    out = asyncio.run(go())
    assert list(out)[0] == "status_line" and "say" in out  # the banner is added, the original result is intact


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} checks passed")
