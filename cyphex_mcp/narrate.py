"""Plain-English narration of a running scan.

An MCP server cannot talk to the person directly, only the host agent can. So every tool result that
matters carries a `say` sentence, and the server instructions tell the host to print it to the person as
it happens: which stage is starting, which agents are working on what, what just came back, what is
still pending. The same sentences are replayed in the report ("What happened, in order"), so the live
session and the document tell one story.

Everything here is derived from the job record, so it works after a restart and costs nothing to store.
"""
from __future__ import annotations

# what each agent is looking for, in words a non-specialist understands
NAMES = {
    "recon": ("route mapper", "lists every page and API route the app exposes"),
    "sqli": ("SQL injection agent", "checks where user input ends up inside a database query"),
    "xss": ("cross-site scripting agent", "checks where user input is written back into web pages"),
    "cmdi": ("command injection agent", "checks where user input reaches a shell command"),
    "path": ("file access agent", "checks where user input chooses which file the app opens"),
    "auth": ("login and access agent", "checks who can reach each route and whether the app verifies it"),
    "ssrf": ("outbound request agent", "checks where the app fetches a web address that a user supplied"),
    "config": ("secrets and settings agent", "looks for hardcoded secrets, debug routes and loose settings"),
    "supply": ("dependency agent", "looks at the libraries the app installs"),
    "logic": ("business logic agent", "looks for ways to cheat the app's own rules, such as prices or roles"),
    "ai": ("AI features agent", "checks how the app's own AI features handle user text"),
    "prober": ("prober", "runs a standard scanner against the running app to see which findings actually work"),
    "nuclei": ("scanner", "runs a standard scanner against the running app"),
    "probe": ("targeted prober", "fires known payloads at each finding route and parameter it flagged"),
    "skeptic": ("skeptic reviewer", "tries to show each finding is a false alarm"),
    "exploiter": ("exploit reviewer", "works out whether an attacker could really use each finding"),
    "dataflow": ("data-flow reviewer", "follows the input from entry to use to see if anything stops it"),
    "defender": ("defender reviewer", "asks what already protects the app and how bad it is if that fails"),
    "patcher": ("patch writer", "writes the smallest fix for each confirmed finding"),
    "reviewer-correct": ("fix reviewer (correctness)", "checks that each fix really closes the hole"),
    "reviewer-scope": ("fix reviewer (scope)", "checks that each fix changes only what it should"),
    "agentsec": ("agent security auditor", "checks the agents' own settings and permissions"),
}
STAGE_LABEL = {"recon": "Mapping the app", "deep_sast": "Deep SAST (reading the code)", "deep_dast": "Deep DAST (attacking the running app)",
               "council": "Review board (second opinions)", "patch_crew": "Fixing", "agent_security": "Agent security check"}
_NEXT = {"recon": "Next the bug-class agents read the code.",
         "deep_sast": "Next the prober attacks the running app, or the review board votes if there is no app.",
         "deep_dast": "Next the review board votes on every finding.",
         "council": "Next the patch writer fixes the confirmed findings.",
         "patch_crew": "Next each fix is checked, then the runtime shield is built.",
         "agent_security": "Next the report is written."}


def cap(s: str) -> str:
    return s[:1].upper() + s[1:]  # str.capitalize() would lower-case "SQL"


def who(agent: str) -> str:
    k = (agent or "").replace("cyphex-", "")
    return f"the {NAMES[k][0]}" if k in NAMES else (f"the {k} agent" if k else "an agent")


def stage_say(stage: int, name: str, agents: list[str], parallel: bool) -> str:
    """The sentence to print BEFORE launching a stage."""
    lines = [f"{cap(who(a)[4:])} {NAMES.get(a.replace('cyphex-', ''), ('', ''))[1]}." for a in agents]
    head = f"Step {stage} of 8, {name}. " + (f"{len(agents)} agents start together and work separately." if parallel and len(agents) > 1
                                             else f"{cap(who(agents[0]))} starts now.")
    return head + " " + " ".join(lines)


def _waiting(job: dict, step: dict) -> list[str]:
    role = step["role"]
    pend = [n for n, r in (job.get("roster") or {}).items() if r.get("deployed") and r.get("role") == role and not r.get("reported")]
    if role == "patch_crew":  # the patch writer and its reviewers run in different steps, so only reviewers wait on reviewers
        return [n for n in pend if "reviewer" in n] if "reviewer" in step["agent"] else []
    return pend


def _list(names: list[str]) -> str:
    w = [who(n) for n in names]
    return ", ".join(w[:3]) + (f" and {len(w) - 3} more" if len(w) > 3 else "")


def step_line(s: dict) -> str:
    """One sentence for something an agent just reported."""
    sm, r, a = s["summary"], s["role"], cap(who(s["agent"]))
    if r == "recon":
        return f"{a} listed {sm.get('endpoints', 0)} routes" + (" and says that is all of them." if sm.get("complete") else ", a sample of the app.")
    if r == "deep_sast":
        n, bad = sm.get("accepted", 0), len(sm.get("rejected", []))
        return (f"{a} finished reading the code and reported {n} problem{'s' if n != 1 else ''}"
                + (f", throwing out {bad} whose line numbers did not check out" if bad else "") + ".")
    if r == "deep_dast":
        return f"{a} attacked the running app for {sm.get('tested', 0)} finding(s) and proved {sm.get('proven', 0)}."
    if r == "council":
        if "reviewer" in sm:
            return f"{a} voted on every finding ({sm.get('ballots_in')} vote{'s' if sm.get('ballots_in') != 1 else ''} in so far)."
        return f"The board looked at {sm.get('finding')}: {sm.get('tally')} agreed, so it is {sm.get('verdict')}."
    if r == "agent_security":
        return f"{a} checked {sm.get('checked', 0)} agent file(s) and found {sm.get('issues', 0)} problem(s)."
    if "reviewer" in sm:
        return f"{a} {'approved' if sm.get('approved') else 'rejected'} the fix for {sm.get('finding')}."
    return f"{a} wrote a fix for {sm.get('finding')}."


def say(job: dict, step: dict) -> dict:
    """What to tell the person after submit_result: what came back, what is still pending."""
    wait = _waiting(job, step)
    if wait:
        tail = f"Still working: {_list(wait)}."
    elif step["role"] == "council" and step["summary"].get("ballots_in", 4) < 3:
        tail = "Waiting for more votes."
    else:
        tail = _NEXT.get(step["role"], "")
    return {"say": step_line(step) + (" " + tail if tail else ""), "waiting": [n.replace("cyphex-", "") for n in wait]}


def verify_line(finding: str, verdict: str, unmeasured: list[str]) -> str:
    return {"PASS": f"The fix for {finding} passed every check, including the attack no longer working.",
            "FAIL": f"The fix for {finding} failed a check and should be rolled back."}.get(
        verdict, f"The fix for {finding} could not be fully checked ({', '.join(unmeasured) or 'a check could not run'}), so it is not counted as fixed.")


def genome_line(g: dict) -> str:
    if g.get("status") != "built":
        return "The runtime shield could not be built on this machine: " + str(g.get("reason", "a package is missing")) + "."
    e = g.get("eval") or {}
    return (f"The runtime shield is built from {g.get('endpoints_profiled', 0)} routes. On attacks it never saw it blocked "
            f"{round(100 * (e.get('attack_block_rate') or 0))}% and wrongly flagged {round(100 * (e.get('normal_flagged_rate') or 0))}% of normal requests.")


def feed(job: dict) -> list[dict]:
    """Everything that happened so far, oldest first, as sentences."""
    ev = [{"at": s["at"], "role": s["role"], "agent": s["agent"], "say": step_line(s)} for s in job.get("steps", [])]
    for f in job.get("findings", {}).values():
        v = (f.get("patch") or {}).get("verify")
        if v:
            bad = [c["name"].replace("_", " ") for c in v.get("checks", []) if c.get("ok") is not True]
            ev.append({"at": v.get("at", ""), "role": "verify", "agent": "cyphex", "say": verify_line(f["id"], v["verdict"], bad)})
    g = job.get("genome")
    if g:
        ev.append({"at": g.get("at", ""), "role": "genome", "agent": "cyphex", "say": genome_line(g)})
    return sorted(ev, key=lambda e: e["at"])


def progress(job: dict) -> dict:
    pending: dict[str, list[str]] = {}
    for n, r in (job.get("roster") or {}).items():
        if r.get("deployed") and not r.get("reported"):
            pending.setdefault(STAGE_LABEL.get(r.get("role"), r.get("role")), []).append(n.replace("cyphex-", ""))
    f = feed(job)
    real = [x for x in job.get("findings", {}).values() if (x.get("council") or {}).get("verdict") != "rejected"]
    head = (f"So far: {len(f)} update(s), {len(real)} finding(s) not dismissed. " +
            (("Waiting on: " + "; ".join(f"{k}: {', '.join(v)}" for k, v in pending.items()) + ".") if pending else "No agent is pending."))
    return {"say": head, "feed": [{"time": e["at"][11:19], "say": e["say"]} for e in f], "waiting": pending}
