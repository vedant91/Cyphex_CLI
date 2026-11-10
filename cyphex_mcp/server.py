"""Cyphex MCP server — the thin tool surface.

Every tool is a few lines: it either returns a playbook for the host agent to
run, or calls a deterministic helper in core.py. No model and no target runs
here. Launch with `cyphex-mcp` (stdio); a client like Claude Code adds it with
`claude mcp add cyphex -- cyphex-mcp`.

The `mcp` SDK is imported lazily inside main() so this module — and the whole
core — imports and self-tests without the dependency installed.
"""
from __future__ import annotations

import hmac
import os
import sys

from . import agent_security, agents, core, dast, genome_bridge, ledger, narrate, report, verify


class _Bearer:
    """ASGI gate for the HTTP transport: every request needs `Authorization: Bearer <token>`.
    Plain ASGI rather than a Starlette middleware class so streaming responses pass through."""

    def __init__(self, app, token: str):
        self.app, self.want = app, f"Bearer {token}"

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            got = dict(scope["headers"]).get(b"authorization", b"").decode()
            if not hmac.compare_digest(got, self.want):
                await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                return
        await self.app(scope, receive, send)


def build_server():
    """Construct the FastMCP server. Imported here so `import cyphex_mcp.server`
    never requires the SDK; only actually running the server does."""
    from mcp.server.fastmcp import FastMCP

    # stdio (default) is what `claude mcp add cyphex -- cyphex-mcp` launches
    # locally. The demo Docker image sets CYPHEX_MCP_TRANSPORT=streamable-http
    # so the container is reachable from outside itself — stdio has no meaning
    # across a container boundary, there's no parent process to pipe to.
    mcp = FastMCP("cyphex", host="0.0.0.0", port=int(os.environ.get("CYPHEX_MCP_PORT", "8765")), instructions=(
        "Cyphex scans a project for security problems with a team of agents. When the person asks for a security scan, do the "
        "whole job without being told the steps: "
        "1) Call start_scan with repo_path set to the project root. It stops and returns questions; ask the person those in plain "
        "words, wait for their answer, never answer for them, then call start_scan again with human_answers. "
        "2) If they chose the agent team, call deploy_agents (project_path is the folder that holds .claude), then get_orchestration_plan. "
        "3) Run the plan stage by stage. Stages that list several agents are launched together in one message so they run in parallel. "
        "Build or use the test environment only after the person said yes to it. "
        "4) Keep the person informed in plain English the whole time: before each stage say which agents are starting and what each "
        "looks for (the plan's `say_before`), and whenever a tool result has a `say` field, tell the person that sentence right away. "
        "Never wait to be asked what is happening; if they ask for status, call get_progress. "
        "5) Afterwards call verify_patch for each fix, build_genome, then get_report with out_path set to cyphex-report.html in the "
        "project root. Finish by telling the person the verdict, where the report is, which findings were proven by a real attack and "
        "which come only from reading code, and anything that could not be verified."))
    # Over HTTP the caller is a different machine: repo_path would name a path on THIS
    # server, not theirs, and a caller-chosen out_path would let them write files here.
    # So remote mode ignores both and returns the report inline instead.
    remote = os.environ.get("CYPHEX_MCP_TRANSPORT", "stdio") != "stdio"

    @mcp.tool()
    def start_scan(stack: str = "node", port: int = 3000,
                    security_tier: str = "auto", repo_path: str = "",
                    event: str = "manual", repo: str = "", ref: str = "",
                    commit: str = "", pr: int = 0, job_id: str = "",
                    human_answers: dict | None = None,
                    writable_paths: list[str] | None = None) -> dict:
        """Begin a scan of the whole codebase. THE FIRST CALL ALWAYS STOPS: it
        returns three questions (GitHub webhook? where tests run? deploy the agent team?) that you must put to the
        person at the keyboard and wait for. Never answer them yourself. Call again
        with human_answers={"webhook": "yes|no", "sandbox": "existing|create|skip",
        "sandbox_url": "<only if existing>", "human_words": "<what they said>"}.
        Then it returns a job_id, how to get a running app to test (their URL, or a
        local Docker recipe), and the roles to run, starting with sandbox_security.
        Report every role's output with submit_result. repo_path lets the MCP check
        that cited files and lines are real. event/repo/ref/commit/pr record what
        triggered the scan; pass job_id to adopt a job the GitHub webhook queued."""
        repo_path = "" if remote else repo_path  # remote: file:line and patch-apply checks become "not measured"
        trigger = {"event": event, "repo": repo, "ref": ref, "commit": commit, **({"pr": pr} if pr else {})}
        attended = not job_id and os.environ.get("CYPHEX_UNATTENDED") != "1"
        if job_id:  # queued by the webhook, so a person already set this up
            decisions = {"webhook": "yes", "sandbox": "create", "sandbox_url": "", "agents": "deploy-same", "human_words": "job queued by the GitHub webhook (the CI runner builds the sandbox)"}
        elif not attended:  # CI has no one to ask, and the report says so
            decisions = {"webhook": "no", "sandbox": "create", "sandbox_url": "", "agents": os.environ.get("CYPHEX_AGENTS", "deploy-same"), "human_words": "unattended run (CYPHEX_UNATTENDED=1)"}
        else:
            decisions, problems = core.validate_human_answers(human_answers)
            if decisions is None:
                return {"status": "needs_human_answers",
                        "do_this": "STOP. Ask the person these questions in plain words and wait for their reply. "
                                   "Do not choose for them. Then call start_scan again with human_answers.",
                        "ask_the_human": core.SETUP_QUESTIONS, "problems": problems}
        if job_id:
            job = ledger.load_job(job_id)
            job.update(status="running", stack=stack, repo_path=repo_path or job["repo_path"], decisions=decisions)
            ledger.save_job(job)
        else:
            job = ledger.new_job(stack, trigger, repo_path)
            job["decisions"] = decisions
            ledger.save_job(job)
        out = {"job_id": job["job_id"], "decisions_recorded": decisions}
        order = ["sandbox_security", "recon", "deep_sast", "deep_dast", "council", "patch_crew"]
        if decisions["sandbox"] == "create":
            out["sandbox"] = core.sandbox_recipe(stack, job["job_id"], port, security_tier, None, writable_paths)
            if attended:
                out["before_you_build"] = ("Tell the person you are about to run `docker compose up` on their machine, what it "
                                           "will create, and wait for a yes. Tear it down when the scan ends.")
        elif decisions["sandbox"] == "existing":
            out["test_this_url"] = decisions["sandbox_url"]
            out["note"] = "Probe only this URL. It is the one the person gave you."
        elif decisions["sandbox"] == "skip":
            order.remove("deep_dast")
            out["note"] = "No running app: skip deep_dast. Findings stay 'confirmed' (code reading), never 'proven'."
        out["say"] = ("The scan is set up. " + {"create": "A Docker sandbox will be built so the app can be attacked safely. ",
                      "existing": f"The app at {decisions['sandbox_url']} will be attacked. ", "skip": "No app will be attacked, so findings come from reading the code. "}[decisions["sandbox"]]
                      + ("Next the agent team is deployed." if decisions["agents"].startswith("deploy") else "Next each role is played in turn."))
        out["run_in_order"] = order
        out["then"] = ["verify_patch for each patch", "build_genome", "get_report"]
        if decisions["agents"].startswith("deploy"):
            out["agents_next"] = ("Call deploy_agents(project_path=<the folder that holds .claude>, models='" +
                                  ("mixed" if decisions["agents"] == "deploy-mixed" else "single") +
                                  "', job_id=...), then get_orchestration_plan(job_id) and launch each stage with your Agent tool. "
                                  "Stages with several agents go out together in one message. Specialists, reviewers and the prober run as "
                                  "separate agents; you only orchestrate and call verify_patch, build_genome and get_report.")
        else:
            out["agents_next"] = "No agents were chosen: play each role yourself in turn with get_playbook. Reviewers will not be independent."
        if decisions["webhook"] == "yes" and not job_id:
            out["webhook_setup"] = {
                "run_receiver": "python -m cyphex_mcp.webhook   (listens on 127.0.0.1:3005)",
                "github_settings": "Repo → Settings → Webhooks → Add webhook",
                "payload_url": "https://<your public host>/github   (GitHub cannot reach localhost: use a tunnel such as Cloudflare Tunnel, ngrok or Tailscale Funnel, or run the receiver on a server)",
                "content_type": "application/json",
                "secret": ledger.webhook_secret(create=True),
                "events": "Push and Pull requests",
                "note": "The receiver only queues the job. A CI runner or an open Claude session still has to run the agents.",
            }
        return out

    @mcp.tool()
    def get_playbook(name: str) -> dict:
        """Return a deep-agent playbook (role + output schema), guardrails first.
        Names: recon, deep_sast, deep_dast, council, patch_crew."""
        try:
            return core.get_playbook(name)
        except KeyError:
            return {"error": f"unknown playbook {name!r}",
                    "available": list(core.PLAYBOOKS)}

    @mcp.tool()
    def sandbox_recipe(stack: str, job_id: str, port: int = 3000,
                        security_tier: str = "auto",
                        writable_paths: list[str] | None = None) -> dict:
        """Local, egress-free Docker sandbox recipe for the host agent to build.
        security_tier: auto (default, picks gVisor if present) | gvisor |
        hardened-docker. writable_paths: directories the app must write to (for
        example ["/app/uploads"]), mounted as tmpfs because the root filesystem
        is read-only. See get_playbook('sandbox_security') for the checklist."""
        return core.sandbox_recipe(stack, job_id, port, security_tier, None, writable_paths)

    @mcp.tool()
    def submit_result(job_id: str, role: str, payload: dict, agent: str = "", model: str = "") -> dict:
        """Report what an agent did. role: recon | deep_sast | deep_dast |
        council | patch_crew; payload: the JSON that role's playbook asks for.
        Pass your own agent name (and model if you know it): the report scores each
        agent separately. The MCP grades it with deterministic checks (cited
        file:line is real, proof carries evidence, council ballots tallied, patch
        reviewed) and adds it to the scan report. Returns the trust grade and which
        checks failed. A council agent submits ONE ballot over all findings:
        {"reviewer": name, "ballot": {finding_id: {"vote": "confirm|reject", "reason": ...}}}.
        A patcher submits {"finding_id", "diff"}; each reviewer then submits
        {"finding_id", "review": {"reviewer", "approved", "note"}}."""
        return ledger.submit_result(job_id, role, payload, agent, model)

    @mcp.tool()
    def dast_recipe(job_id: str, target_url: str = "") -> dict:
        """The command for the deterministic live-attack stage. It runs Nuclei (a standard
        third-party scanner) from inside the sandbox against the target; no model writes attack
        requests, so this stage is never blocked by a safety classifier. Run the command, then
        pass its JSONL output to submit_dast. If target_url is empty it is read from the job."""
        job = ledger.load_job(job_id)
        d = job.get("decisions") or {}
        url = target_url or d.get("sandbox_url") or ("http://target:3000" if d.get("sandbox") == "create" else "")
        if not url:
            return {"error": "no target to attack; the person chose 'skip' for the sandbox, so findings stay 'confirmed by code reading'."}
        return dast.recipe(url, f"cyphex-sandbox-{job_id}.yml" if d.get("sandbox") == "create" else "")

    @mcp.tool()
    def submit_dast(job_id: str, nuclei_jsonl: str) -> dict:
        """Ingest the live-attack scanner's output. The MCP parses the Nuclei JSONL itself and
        marks each matching finding proven (measured by Cyphex, not reported by a model). Pass the
        full stdout from the dast_recipe command."""
        job = ledger.load_job(job_id)
        res = dast.ingest(job, nuclei_jsonl)
        job["dast_scan"] = {"hits": res["hits"], "unmatched": len(res["unmatched"]), "at": ledger._now()}
        ledger.save_job(job)
        out = ledger.submit_result(job_id, "deep_dast", {"confirmations": res["confirmations"]}, "cyphex-nuclei", "nuclei")
        extra = f" Nuclei also flagged {len(res['unmatched'])} issue(s) not tied to a code finding." if res["unmatched"] else ""
        out["say"] = (f"The scanner finished: {res['matched']} finding(s) proven by a real request against the running app." + extra
                      if res["hits"] else "The scanner ran but reported nothing, so no finding was proven by a live attack.")
        return out

    @mcp.tool()
    def get_finding(job_id: str, finding_id: str) -> dict:
        """One finding in full: where, why, who found it, the attack evidence, the
        review votes and the fix with its diff. Reviewers and the patcher read this."""
        f = ledger.load_job(job_id)["findings"].get(finding_id)
        if f is None:
            return {"error": f"no finding {finding_id!r} on job {job_id}"}
        return {**{k: f.get(k) for k in ("id", "cwe", "file", "line", "severity", "why", "snippet", "found_by", "also_found_by", "dast", "council")},
                "patch": ({"diff": f["patch"]["diff"], "reviews": f["patch"].get("reviews", []), "verify": (f["patch"].get("verify") or {}).get("verdict")} if f.get("patch") else None)}

    @mcp.tool()
    def deploy_agents(project_path: str, models: str = "single", human_words: str = "", job_id: str = "") -> dict:
        """Write the Cyphex agents (route mapper, ten bug-class specialists, prober, four
        independent reviewers, patcher, two fix reviewers, agent-security auditor) into
        <project_path>/.claude/agents/ as Claude Code subagents, each with its own
        tool allowlist and guardrails. models: 'single' (all on the session's model) or
        'mixed' (reviewers on different Claude models). This writes files into the
        person's project, so human_words must quote their yes. Never overwrites an
        agent file you did not get from Cyphex. Claude Code loads agent files at the
        start of a session: if the Agent tool does not know them yet, run /agents or restart."""
        if remote:
            return {"error": "deploy_agents writes files on the server's disk, so it is disabled over HTTP. Run the MCP locally."}
        if os.environ.get("CYPHEX_UNATTENDED") != "1" and len(human_words.strip()) < 3:
            return {"status": "needs_human_yes", "do_this": f"STOP. Tell the person you are about to write about 20 small agent files into {project_path}/.claude/agents/, "
                                                           "that they can delete them any time with remove_agents, and wait for their yes. Then call again with human_words."}
        res = agents.deploy(project_path, models)
        if job_id:
            job = ledger.load_job(job_id)
            for a in agents.roster(models):
                job.setdefault("roster", {})[a["name"]] = {"role": a["role"], "model": a["model"], "tools": a["tools"], "deployed": True,
                                                            "reported": job.get("roster", {}).get(a["name"], {}).get("reported", 0)}
            job.setdefault("decisions", {})["deploy_words"] = human_words[:300]
            ledger.save_job(job)
        return {**res, "next": "get_orchestration_plan(job_id)"}

    @mcp.tool()
    def remove_agents(project_path: str) -> dict:
        """Delete the agent files Cyphex wrote into <project_path>/.claude/agents/. Only
        files that carry the Cyphex marker are removed."""
        return agents.remove(project_path) if not remote else {"error": "disabled over HTTP"}

    @mcp.tool()
    def get_orchestration_plan(job_id: str) -> dict:
        """The run as stages of agents to launch: who, in what order, which stages go out
        together in one message, and which model each runs on."""
        job = ledger.load_job(job_id)
        d = job.get("decisions") or {}
        target = d.get("sandbox_url") or ("http://target:3000" if d.get("sandbox") == "create" else "")
        return agents.plan(job_id, job.get("repo_path", ""), target, d.get("sandbox", ""), "mixed" if d.get("agents") == "deploy-mixed" else "single")

    @mcp.tool()
    def get_agent_prompt(name: str, job_id: str = "", repo_path: str = "", target_url: str = "") -> dict:
        """The full instructions of one Cyphex agent. Use as the prompt of a general-purpose
        subagent when Claude Code has not loaded the deployed agent files yet."""
        a = next((x for x in agents.roster("single") if x["name"] == name), None)
        if a is None:
            return {"error": f"no agent {name!r}", "available": [x["name"] for x in agents.roster("single")]}
        ctx = f"\n\nYour inputs: job_id={job_id} repo_path={repo_path}" + (f" target_url={target_url}" if target_url else "")
        return {"name": name, "tools_it_should_use": a["tools"], "prompt": a["body"] + ctx}

    @mcp.tool()
    def audit_agent_config(project_path: str, job_id: str = "", agent: str = "") -> dict:
        """Agent security: audit how AI agents are set up in a project (.mcp.json, .claude
        settings and agent files, CLAUDE.md) for settings that make a hijacked agent
        dangerous. Reads files only. With job_id the result goes into the scan report."""
        res = agent_security.audit_config(project_path)
        if job_id:
            job = ledger.load_job(job_id)
            sec = job.setdefault("agent_security", {"canary": {}, "config_audit": None, "guard_log": []})
            sec["config_audit"] = res
            who = agent or "cyphex-agentsec"
            r = job.setdefault("roster", {}).setdefault(who, {"role": "agent_security", "model": "", "tools": [], "deployed": False, "reported": 0})
            r["reported"] += 1
            r["last_at"] = ledger._now()
            job["steps"].append({"role": "agent_security", "agent": who, "model": r.get("model", ""), "at": ledger._now(), "checks": [],
                                 "trust": "high", "summary": {"issues": len(res["findings"]), "checked": len(res["checked"])}, "payload": {"project_path": project_path}})
            ledger.save_job(job)
        return res

    @mcp.tool()
    def plant_canary(job_id: str) -> dict:
        """Agent-security test: returns an instruction to plant in a SCRATCH COPY of the code
        (never the real repo) and the token to look for. An agent that does what the planted
        text says has been taken over by something it only read. submit_result checks for it."""
        job = ledger.load_job(job_id)
        c = agent_security.canary()
        job["canary"] = {"token": c["token"], "file": c["suggested_file"]}
        job.setdefault("agent_security", {"canary": {}, "config_audit": None, "guard_log": []})
        ledger.save_job(job)
        return c

    @mcp.tool()
    def verify_patch(job_id: str, finding_id: str, replay: dict | None = None) -> dict:
        """Verify Gate for a patch already submitted with role='patch_crew'.
        Checks the diff applies, compiles, adds no suppression comments and stays
        inside the severity blast radius. Pass replay={"fired": false, "evidence":
        "..."} after you applied the diff in your sandbox, rebuilt, and re-ran the
        exploit. Returns PASS, FAIL (roll the patch back) or UNVERIFIABLE (a check
        could not run, never counted as fixed)."""
        v = verify.verify_patch(job_id, finding_id, replay)
        if "verdict" in v:
            v["say"] = narrate.verify_line(finding_id, v["verdict"], [c["name"].replace("_", " ") for c in v.get("checks", []) if c.get("ok") is not True])
        return v

    @mcp.tool()
    def build_genome(job_id: str) -> dict:
        """Build and self-evaluate the runtime genome from the recon inventory on
        this job. Needs numpy, scikit-learn and joblib; says so if they are
        missing. Returns the signed bundle path plus block and false-block rates
        measured on attack strings the model never trained on."""
        g = genome_bridge.build_genome(job_id)
        g["say"] = narrate.genome_line(g)
        return g

    @mcp.tool()
    def get_progress(job_id: str) -> dict:
        """What has happened so far and who is still working, in plain English. Call it when the
        person asks what is going on, and tell them the `say` line and the latest feed entries."""
        return narrate.progress(ledger.load_job(job_id))

    @mcp.tool()
    def get_report(job_id: str, out_path: str = "") -> dict:
        """Write the scan report as one self-contained HTML file (about two
        pages): what each agent did and how far to trust it, every finding with
        its evidence, what was patched and verified, and the genome. Over HTTP the
        file stays on the server, so the HTML comes back in `html`: save it locally."""
        path = report.write_report(job_id, None if remote else (out_path or None))
        job = ledger.load_job(job_id)
        s = report._stats(job)
        verdict = (f"{len(s['real'])} real findings, {s['proven']} proven, "
                   f"{len(s['verified'])} fixed and verified, {len(s['open'])} still open")
        ledger.append_log(job, path, verdict)
        g = job.get("genome") or {}
        out = {"report": path, "verdict": verdict, "run_folder": str(ledger.data_dir() / job_id),
               "security_log": str(ledger.base_dir() / "SECURITY_LOG.md"),
               "genome_files": g.get("files", [])}
        if remote:
            out["html"] = open(path).read()
        return out

    @mcp.tool()
    def get_history(limit: int = 20) -> dict:
        """Past scans on this machine, newest first: repo, date, findings, proven,
        fixed and where each report is. This is the local security folder's index."""
        return {"folder": str(ledger.base_dir()), "runs": ledger.history(limit)}

    @mcp.tool()
    def get_job(job_id: str) -> dict:
        """Where a scan stands: trigger, which roles have reported, and each
        finding's proof level and patch status."""
        job = ledger.load_job(job_id)
        return {"job_id": job_id, "status": job["status"], "trigger": job["trigger"],
                "reported": [s["role"] for s in job["steps"]],
                "agents": {n: r.get("reported", 0) for n, r in job.get("roster", {}).items()},
                "findings": {k: {"proof": ledger.proof_level(f), "patch": ledger.patch_status(f)}
                             for k, f in job["findings"].items()}}

    @mcp.tool()
    def guard_decide(tool: str, args: str, tainted: bool = False, job_id: str = "") -> dict:
        """Agent-security gate: score a proposed tool call allow / ask / block. Pass job_id
        and the decision is logged into the scan report."""
        res = core.guard_decide(tool, args, tainted)
        if job_id:
            job = ledger.load_job(job_id)
            sec = job.setdefault("agent_security", {"canary": {}, "config_audit": None, "guard_log": []})
            sec["guard_log"].append({"at": ledger._now(), "tool": tool, "args": args[:120], "tainted": tainted, **res})
            ledger.save_job(job)
        return res

    @mcp.tool()
    def publish_genome(target: str, out_dir: str) -> dict:
        """Emit the edge-deploy artifacts (decide() wrapper, compose, manifest)
        for a trained genome. The user drops their signed genome files in beside
        them and ships the folder to their Docker sidecar / Cloudflare / AWS."""
        written = core.emit_deploy_bundle(out_dir, target)
        return {"written": written,
                "next": "place genome.pkl, genome.pkl.hmac and hmac.key here, "
                        "then deploy the folder"}

    return mcp


def main():
    transport = os.environ.get("CYPHEX_MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        return build_server().run(transport="stdio")
    token = os.environ.get("CYPHEX_MCP_TOKEN", "")
    if not token:  # an HTTP port with every tool and no login must never start by accident
        sys.exit("CYPHEX_MCP_TOKEN is required when CYPHEX_MCP_TRANSPORT is not stdio")
    import uvicorn
    uvicorn.run(_Bearer(build_server().streamable_http_app(), token), host="0.0.0.0",
                port=int(os.environ.get("CYPHEX_MCP_PORT", "8765")), log_level="info")


if __name__ == "__main__":
    main()
