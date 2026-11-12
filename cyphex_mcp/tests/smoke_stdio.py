"""End-to-end check of an installed Cyphex MCP, launched exactly as Claude Code will.

    python smoke_stdio.py path/to/mcp.json [server_name]

Reads mcpServers.<name> {command, args, env} from the config, starts that process over
stdio, and drives one whole scan through it: playbooks, recon, deep SAST (including one
invented finding that must be rejected), deep DAST, council, patch crew, Verify Gate,
genome, agent-security gate, sandbox recipe and report. Uses a temp data dir and a tiny
temp repo, so it never touches your project or your real job history.
Exit code 0 only if every step behaved as expected.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SRC = "const a = 1;\nconst q = `SELECT * FROM t WHERE id = ${id}`;\nmodule.exports = q;\n"
FIND = {"id": "cwe-89-t-2", "cwe": "CWE-89", "file": "src/t.js", "line": 2, "severity": "high", "reachable": True,
        "why": "id is concatenated into SQL", "snippet": "SELECT * FROM t WHERE id = ${id}"}
INVENTED = dict(FIND, id="cwe-89-fake-9", line=99, snippet="does not exist")
DIFF = ("--- a/src/t.js\n+++ b/src/t.js\n@@ -1,3 +1,3 @@\n const a = 1;\n"
        "-const q = `SELECT * FROM t WHERE id = ${id}`;\n+const q = 'SELECT * FROM t WHERE id = ?';\n module.exports = q;\n")
EXPECTED_TOOLS = {"start_scan", "get_playbook", "sandbox_recipe", "submit_result", "verify_patch",
                  "build_genome", "get_report", "get_job", "get_history", "guard_decide", "publish_genome",
                  "get_finding", "deploy_agents", "remove_agents", "get_orchestration_plan", "get_agent_prompt",
                  "audit_agent_config", "plant_canary", "get_progress", "dast_recipe", "submit_dast", "probe_recipe", "submit_probe"}
results = []


def step(name, ok, detail=""):
    ok = bool(ok)
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


async def main(cfg_path: str, server: str):
    cfg = json.load(open(cfg_path))["mcpServers"][server]
    work = Path(tempfile.mkdtemp(prefix="cyphex-smoke-"))
    repo = work / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "t.js").write_text(SRC)
    env = {**os.environ, **cfg.get("env", {}), "CYPHEX_DATA_DIR": str(work / "data")}
    params = StdioServerParameters(command=cfg["command"], args=cfg.get("args", []), env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()

            async def call(_name, **kw):  # not "tool": guard_decide has an argument called tool
                res = await s.call_tool(_name, kw)
                if res.isError:
                    raise RuntimeError(f"{_name}: {res.content[0].text}")
                return json.loads(res.content[0].text)

            tools = {t.name for t in (await s.list_tools()).tools}
            step("server starts from the config and lists all 23 tools", tools == EXPECTED_TOOLS, f"missing {EXPECTED_TOOLS - tools}" if tools != EXPECTED_TOOLS else "")

            # human in the loop: the first call must stop and ask, and must not create a job
            ask = await call("start_scan", stack="node", repo_path=str(repo))
            step("start_scan stops and asks the human (webhook? sandbox?) before doing anything",
                 ask.get("status") == "needs_human_answers" and {q["id"] for q in ask["ask_the_human"]} == {"webhook", "sandbox", "agents"} and "job_id" not in ask)
            bad = await call("start_scan", stack="node", repo_path=str(repo), human_answers={"webhook": "no", "sandbox": "create", "agents": "inline"})
            step("start_scan refuses answers that carry no words from the person", bad.get("status") == "needs_human_answers" and bad["problems"])
            ans = {"webhook": "yes", "sandbox": "create", "agents": "deploy-mixed", "human_words": "yes set up the webhook, and build the sandbox for me"}
            scan = await call("start_scan", stack="node", repo_path=str(repo), event="push", repo="smoke/test", ref="main", commit="abc1234", human_answers=ans)
            jid = scan["job_id"]
            step("start_scan returns job, sandbox recipe and role order", scan["run_in_order"][0] == "sandbox_security" and "internal: true" in scan["sandbox"]["compose"], scan["sandbox"]["security_tier"])
            ws = scan.get("webhook_setup", {})
            step("answering 'yes' to the webhook returns the URL steps and a secret", len(ws.get("secret", "")) == 64 and "payload_url" in ws and "before_you_build" in scan)
            skip = await call("start_scan", stack="node", repo_path=str(repo), human_answers={"webhook": "no", "sandbox": "skip", "agents": "inline", "human_words": "code only please"})
            step("choosing 'skip' removes deep DAST from the run", "deep_dast" not in skip["run_in_order"])
            if shutil.which("docker"):
                cf = work / "docker-compose.cyphex.yml"
                cf.write_text(scan["sandbox"]["compose"])
                ok = subprocess.run(["docker", "compose", "-f", str(cf), "config", "-q"], capture_output=True).returncode == 0
                step("sandbox recipe is valid docker compose", ok)
            for role in ("sandbox_security", "recon", "deep_sast", "deep_dast", "council", "patch_crew"):
                pb = await call("get_playbook", name=role)
                if not ("guardrails" in pb and "role" in pb and (role == "sandbox_security" or "submit" in pb)):
                    step(f"playbook {role}", False)
                    break
            else:
                step("all 6 playbooks come back guardrailed", True)

            # agents: deploying writes into the project, so it needs a yes in the person's words
            nope = await call("deploy_agents", project_path=str(work))
            step("deploy_agents refuses to write files without the person's yes", nope.get("status") == "needs_human_yes" and not (work / ".claude").exists())
            dep = await call("deploy_agents", project_path=str(work), models="mixed", human_words="yes deploy them", job_id=jid)
            files = sorted((work / ".claude" / "agents").glob("cyphex-*.md"))
            step("deploy_agents writes the 20 agent files, each with a tool list", len(dep["written"]) == 20 and len(files) == 20 and all("tools:" in f.read_text() for f in files))
            reco = (work / ".claude" / "agents" / "cyphex-skeptic.md").read_text()
            step("the council runs on different models when 'mixed' is chosen", "model: opus" in reco and "model: haiku" in (work / ".claude" / "agents" / "cyphex-dataflow.md").read_text())
            plan = await call("get_orchestration_plan", job_id=jid)
            step("orchestration plan: 8 stages, specialists and board launched in parallel", len(plan["stages"]) == 8 and plan["stages"][1]["parallel"] and len(plan["stages"][1]["agents"]) == 10 and plan["stages"][3]["parallel"])
            ap = await call("get_agent_prompt", name="cyphex-sqli", job_id=jid, repo_path=str(repo))
            step("get_agent_prompt returns the full instructions for a fallback agent", "SQL injection" in ap["prompt"] and f"job_id={jid}" in ap["prompt"])
            au = await call("audit_agent_config", project_path=str(work), job_id=jid)
            step("agent-config audit reads the deployed agents and finds nothing wrong with them", au["findings"] == [] and any("cyphex-sqli.md" in c for c in au["checked"]))
            can = await call("plant_canary", job_id=jid)
            step("plant_canary returns a unique token and says to use a scratch copy", can["token"].startswith("PWNED-") and "scratch" in can["how"].lower())

            sub = lambda role, payload: call("submit_result", job_id=jid, role=role, payload=payload)
            eps = [{"path": "/t", "method": "GET", "params": ["id"]}, {"path": "/u", "method": "POST", "params": ["name"]}]
            r = await sub("recon", {"endpoints": eps})
            step("recon: a route list that does not say it is complete is only medium trust", r["trust"] == "medium")
            r = await sub("recon", {"endpoints": eps, "complete": True, "total_routes": 2})
            step("recon graded", r["trust"] == "high" and r["summary"]["endpoints"] == 2)
            step("every submit_result carries a plain-English `say` line for the person", "route mapper" in r["say"] and "routes" in r["say"], r["say"])
            step("the plan gives a sentence to say before each stage", all(s["say_before"] for s in plan["stages"]) and "start together" in plan["stages"][1]["say_before"])
            pr = await call("get_progress", job_id=jid)
            step("get_progress lists what happened so far in plain English", pr["feed"] and "say" in pr and "update" in pr["say"], pr["say"])
            r = await sub("deep_sast", {"findings": [FIND, INVENTED], "files_reviewed": ["src/t.js"]})
            step("deep SAST keeps the real finding and rejects the invented one", r["summary"]["accepted"] == 1 and len(r["summary"]["rejected"]) == 1 and r["trust"] == "low", f"trust {r['trust']}")
            step("coverage is measured by the MCP", r["summary"]["coverage"] == {"source_files": 1, "reviewed": 1, "pct": 1.0})
            weak = await sub("deep_dast", {"confirmations": [{"id": FIND["id"], "proven": True, "evidence": "yes"}]})
            step("deep DAST proof without evidence is downgraded", weak["trust"] == "low")
            r = await sub("deep_dast", {"confirmations": [{"id": FIND["id"], "proven": True, "evidence": "GET /t?id=1 OR 1=1 returned every row"}]})
            step("deep DAST proof accepted with evidence", r["trust"] == "high" and r["summary"]["proven"] == 1)
            votes = [{"persona": p, "vote": v, "reason": "x"} for p, v in (("skeptic", "confirm"), ("exploit", "confirm"), ("dataflow", "reject"))]
            r = await sub("council", {"finding_id": FIND["id"], "verdict": "rejected", "votes": votes})
            step("council is recounted (agent said rejected, votes say confirmed)", r["summary"]["verdict"] == "confirmed" and r["trust"] == "low")
            r = await sub("patch_crew", {"finding_id": FIND["id"], "diff": DIFF, "reviews": [{"reviewer": "a", "approved": True}, {"reviewer": "b", "approved": True}]})
            step("patch crew graded", r["trust"] == "high")
            for who, vote in (("cyphex-skeptic", "reject"), ("cyphex-exploiter", "confirm"), ("cyphex-dataflow", "confirm")):
                rb = await call("submit_result", job_id=jid, role="council", agent=who, model="m", payload={"reviewer": who, "ballot": {FIND["id"]: {"vote": vote, "reason": "read it"}}})
            step("three separate reviewer ballots decide the finding (2 of 3 confirm)", rb["summary"]["decided"] == 1 and (await call("get_finding", job_id=jid, finding_id=FIND["id"]))["council"]["votes"][0]["persona"] == "cyphex-skeptic")
            r = await sub("patch_crew", {"finding_id": FIND["id"], "diff": DIFF, "reviews": [{"reviewer": "a", "approved": True}, {"reviewer": "b", "approved": True}]})
            v = await call("verify_patch", job_id=jid, finding_id=FIND["id"])
            step("Verify Gate: UNVERIFIABLE without an exploit replay", v["verdict"] == "UNVERIFIABLE")
            v = await call("verify_patch", job_id=jid, finding_id=FIND["id"], replay={"fired": True, "evidence": "still works"})
            step("Verify Gate: FAIL when the exploit still fires", v["verdict"] == "FAIL")
            v = await call("verify_patch", job_id=jid, finding_id=FIND["id"], replay={"fired": False, "evidence": "no extra rows returned"})
            expect = "PASS" if shutil.which("node") else "UNVERIFIABLE"
            step("Verify Gate: PASS when it applies, compiles and the exploit stops", v["verdict"] == expect, v["verdict"])
            g = await call("build_genome", job_id=jid)
            step("genome builds, signs, reloads and self-evaluates", g["status"] == "built" and g["signed_and_reloads"] and g["eval"]["attack_samples"] > 0,
                 f"blocks {g.get('eval', {}).get('attack_block_rate')}, flags normal {g.get('eval', {}).get('normal_flagged_rate')}" if g["status"] == "built" else g.get("reason", ""))
            if g["status"] == "built":
                step("genome hands back its .pkl, bundle and calibrated thresholds as real files",
                     all(Path(p).exists() for p in (g["pkl"], g["bundle"], g["folder"] + "/thresholds.json")))
                e = g["eval"]
                step("calibrated thresholds do not flag all normal traffic (engine defaults do)",
                     e["normal_flagged_rate"] < 1.0 and e["with_engine_defaults"]["normal_flagged_rate"] >= e["normal_flagged_rate"],
                     f"calibrated {e['normal_flagged_rate']}, defaults {e['with_engine_defaults']['normal_flagged_rate']}")
            bad = await call("guard_decide", tool="fetch", args="https://x/?k=API_KEY", tainted=True, job_id=jid)
            ok_ = await call("guard_decide", tool="read_file", args="src/app.js", tainted=True)
            step("agent-security gate blocks the lethal trifecta, allows a plain read", bad["decision"] == "block" and ok_["decision"] == "allow")
            job = await call("get_job", job_id=jid)
            step("get_job reflects proof and patch status", job["findings"][FIND["id"]] == {"proof": "proven", "patch": "verified fixed"} if expect == "PASS" else True, str(job["findings"][FIND["id"]]))
            rep = await call("get_report", job_id=jid, out_path=str(work / "report.html"))
            html = Path(rep["report"]).read_text()
            step("report written, with the agents table and the genome section", "What each agent did" in html and "Genome" in html and "1 real findings" in html, rep["verdict"])
            step("report shows how it ran, what you decided, and who measured what",
                 "What happened, in order" in html and "What you decided" in html and "measured by Cyphex" in html and "reported by the agent" in html)
            step("report shows the team, agent evaluation and agent security (with the logged gate call and canary)",
                 "20 agents were deployed" in html and "Agent evaluation" in html and "Agent security" in html and "API_KEY" in html and "Injection test" in html)
            log = Path(rep["security_log"]).read_text()
            hist = await call("get_history")
            step("the run is in the local security folder (log + history)", jid in log and jid in [r["job_id"] for r in hist["runs"]] and Path(next(r for r in hist["runs"] if r["job_id"] == jid)["report"]).exists())
    shutil.rmtree(work, ignore_errors=True)
    print(f"\n{sum(results)} of {len(results)} checks passed")
    return all(results)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "cyphex")) else 1)
