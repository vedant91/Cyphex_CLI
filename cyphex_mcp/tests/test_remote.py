"""Checks for how the server behaves over HTTP (remote mode), where a friend connects from another machine.

Remote mode cannot write agent files or read the caller's disk, so the flow must steer the caller to what works
instead of dead ends. These drive the real FastMCP server in-process, the way a client does.

Run: python -m cyphex_mcp.tests.test_remote  (needs the mcp SDK; skipped without it)
"""
import asyncio
import json
import os
import tempfile

SHAPE_KEYS = {"webhook", "sandbox", "sandbox_url", "agents", "human_words"}
ANSWERS = {"webhook": "no", "sandbox": "skip", "agents": "deploy-same", "human_words": "no webhook, read the code, run the team"}


def _server(remote: bool):
    os.environ["CYPHEX_DATA_DIR"] = tempfile.mkdtemp()
    os.environ["CYPHEX_STATUS_PORT"] = "0"
    if remote:
        os.environ["CYPHEX_MCP_TRANSPORT"] = "streamable-http"
    else:
        os.environ.pop("CYPHEX_MCP_TRANSPORT", None)
    from cyphex_mcp.server import build_server
    return build_server()


def _run(mcp, steps):
    """steps: list of (tool, args). Returns the parsed JSON result of each."""
    async def go():
        out = []
        for name, args in steps:
            res = await mcp.call_tool(name, args)
            content = res[0] if isinstance(res, tuple) else res
            out.append(json.loads(content[0].text))
        return out
    return asyncio.run(go())


def _have_mcp():
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


def test_a_rejected_answer_shows_the_exact_shape_to_send():
    if not _have_mcp():
        return
    a, b = _run(_server(True), [
        ("start_scan", {"repo_path": "/friend/project"}),
        ("start_scan", {"repo_path": "/friend/project", "human_answers": {"webhook": "no", "sandbox": "skip", "agents": "inline"}})])
    assert a["status"] == "needs_human_answers" and set(a["call_again_with"]["human_answers"]) == SHAPE_KEYS
    assert b["status"] == "needs_human_answers"  # human_words was left out
    assert "INSIDE the human_answers" in b["problems"][0] and set(b["call_again_with"]["human_answers"]) == SHAPE_KEYS


def test_over_http_the_agents_question_does_not_promise_files_and_deploy_is_not_the_next_step():
    if not _have_mcp():
        return
    ask, ok = _run(_server(True), [
        ("start_scan", {}),
        ("start_scan", {"repo_path": "/friend/project", "human_answers": ANSWERS})])
    q = next(x for x in ask["ask_the_human"] if x["id"] == "agents")
    assert "cannot write agent files" in q["question"] and ".claude/agents" not in q["question"]
    assert "do NOT call it" in ok["agents_next"] and "get_agent_prompt" in ok["agents_next"] and "get_orchestration_plan" in ok["agents_next"]
    assert "deployed" not in ok["say"]


def test_over_http_the_dead_end_names_the_way_out_and_the_prompt_works():
    if not _have_mcp():
        return
    mcp = _server(True)
    ok, = _run(mcp, [("start_scan", {"repo_path": "/friend/project", "human_answers": ANSWERS})])
    jid = ok["job_id"]
    dep, plan, prompt = _run(mcp, [
        ("deploy_agents", {"project_path": "/friend/project", "job_id": jid, "human_words": "yes"}),
        ("get_orchestration_plan", {"job_id": jid}),
        ("get_agent_prompt", {"name": "cyphex-recon", "job_id": jid, "repo_path": "/friend/project"})])
    assert "get_orchestration_plan" in dep["error"] and "get_agent_prompt" in dep["error"]
    assert plan["stages"] and plan["stages"][0]["agents"] == ["cyphex-recon"]
    assert "/friend/project" in prompt["prompt"] and prompt["name"] == "cyphex-recon"  # the caller's own path reaches the agent


def test_locally_nothing_changes():
    if not _have_mcp():
        return
    mcp = _server(False)
    ask, ok = _run(mcp, [("start_scan", {}), ("start_scan", {"human_answers": ANSWERS})])
    q = next(x for x in ask["ask_the_human"] if x["id"] == "agents")
    assert ".claude/agents" in q["question"]
    assert ok["agents_next"].startswith("Call deploy_agents(") and "deployed" in ok["say"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} checks passed")
