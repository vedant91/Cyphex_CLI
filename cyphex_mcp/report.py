"""Cyphex MCP — the assessment report.

One self-contained HTML file per scan, written like a security assessment you would hand to
a client: an answer first, what was and was not covered, the team of agents and what each
did, the findings with their evidence, the fixes and how they were checked, how each agent
performed, the agent-security results, and the runtime shield.

Interactive on screen (navigation, filters, per-finding evidence, agent drill-down), and it
prints as a short summary. Every fact says who produced it: measured by Cyphex, or reported
by an agent Cyphex could not check.

Everything that came out of the scanned repo or an agent is untrusted, so every value is
escaped before it reaches the page.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from . import core, evals, ledger, narrate

_E = html.escape
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ROLE_LABEL = {"recon": "Recon", "deep_sast": "Deep SAST", "deep_dast": "Deep DAST",
               "council": "Review board", "patch_crew": "Patch crew", "agent_security": "Agent security"}
_STAGE = {"recon": 1, "deep_sast": 2, "deep_dast": 3, "council": 4, "patch_crew": 5, "agent_security": 8}


def _stats(job: dict) -> dict:
    fs = list(job["findings"].values())
    dismissed = [f for f in fs if f.get("council", {}).get("verdict") == "rejected"]
    real = [f for f in fs if f not in dismissed]
    verified = [f for f in real if ledger.patch_status(f) == "verified fixed"]
    rejected_sast = sum(len(s["summary"].get("rejected", [])) for s in job["steps"] if s["role"] == "deep_sast")
    return {
        "candidates": len(fs), "dismissed": len(dismissed), "real": real, "verified": verified,
        "confirmed": sum(1 for f in fs if f.get("council", {}).get("verdict") == "confirmed"),
        "proven": sum(1 for f in real if ledger.proof_level(f) == "proven"),
        "patched": sum(1 for f in real if f.get("patch")),
        "open": [f for f in real if f not in verified],
        "rejected_sast": rejected_sast,
    }


def _tag(by: str) -> str:
    return ("<span class='by m' title='Cyphex checked this itself'>measured by Cyphex</span>" if by == "mcp"
            else "<span class='by a' title='An agent says so and Cyphex could not check it'>reported by the agent</span>")


def _ids(job: dict) -> dict:
    fs = sorted(job["findings"].values(), key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["id"]))
    return {f["id"]: f"CX-{i:03d}" for i, f in enumerate(fs, 1)}


def _short(text: str, n: int = 90) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "…"


def _project(job: dict) -> str:
    repo = ((job.get("trigger") or {}).get("repo") or "").split("/")[-1]  # "owner/name" -> "name"; a folder called "app" says nothing
    return repo or Path(job.get("repo_path") or "").name or "this project"


def _answer(job: dict, st: dict) -> str:
    n, p, v, o = len(st["real"]), st["proven"], len(st["verified"]), len(st["open"])
    d, cov = job.get("decisions") or {}, job.get("coverage") or {}
    limits = []
    if d.get("sandbox") == "skip" or not any(s["role"] == "deep_dast" for s in job["steps"]):
        limits.append("no running app was attacked, so nothing is proven by a real attack")
    if cov.get("pct") is not None and cov["pct"] < 0.8:
        limits.append(f"only {cov['pct']:.0%} of the source files were read")
    if p and n - p:
        limits.append(f"{n - p} of the {n} come from reading code and were not proven")
    return (f"We found <b>{n} real problem{'s' if n != 1 else ''}</b> in {_E(_project(job))}. <b>{p}</b> {'was' if p == 1 else 'were'} proven with a working attack, "
            f"<b>{v}</b> {'is' if v == 1 else 'are'} fixed and checked, and <b>{o}</b> still need{'s' if o == 1 else ''} work."
            + (" What limits this result: " + "; ".join(limits) + "." if limits else ""))


# ── sections ────────────────────────────────────────────────────────────────

def _cover(job: dict, st: dict) -> str:
    t = job.get("trigger", {})
    what = {"push": f"Push to {t.get('ref', '')}", "pull_request": f"Pull request #{t.get('pr', '?')} merged"}.get(t.get("event"), "Manual scan")
    rows = [("Target", _project(job)), ("Scan", what), ("Commit", (t.get("commit") or "not recorded")[:12]),
            ("Run", job["job_id"]), ("Started", job["created_at"].replace("T", " ")[:19] + " UTC")]
    ag = job.get("decisions", {}).get("agents", "")
    if ag:
        rows.append(("Agents", {"deploy-mixed": "Deployed, reviewers on different models", "deploy-same": "Deployed, one model", "inline": "Not deployed (one session, all roles)"}.get(ag, ag)))
    return (f"<header class='cover'><div class='over'>Security assessment by Cyphex</div><h1>{_E(_project(job))}</h1>"
            f"<table class='meta'>{''.join(f'<tr><th>{_E(k)}</th><td>{_E(v)}</td></tr>' for k, v in rows)}</table></header>")


def _sev_table(job: dict) -> str:
    cols = [("fixed", "Fixed"), ("open_p", "Open, proven"), ("open_u", "Open, not proven"), ("dismissed", "Dismissed")]
    data = {s: {k: 0 for k, _ in cols} for s in _SEV_ORDER}
    for f in job["findings"].values():
        if f.get("council", {}).get("verdict") == "rejected":
            k = "dismissed"
        elif ledger.patch_status(f) == "verified fixed":
            k = "fixed"
        else:
            k = "open_p" if ledger.proof_level(f) == "proven" else "open_u"
        data[f["severity"]][k] += 1
    rows = "".join(f"<tr><td><span class='sev s-{s}'>{s.capitalize()}</span></td>" + "".join(f"<td>{data[s][k] or '·'}</td>" for k, _ in cols) + "</tr>" for s in _SEV_ORDER)
    return f"<table class='sevt'><thead><tr><th></th>{''.join(f'<th>{l}</th>' for _, l in cols)}</tr></thead><tbody>{rows}</tbody></table>"


def _summary(job: dict, st: dict, ids: dict) -> str:
    top = sorted(st["open"], key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["id"]))[:3]
    ff = ("<ol class='ff'>" + "".join(
        f"<li><a href='#{ids[f['id']]}' data-jump='{ids[f['id']]}'>{ids[f['id']]}</a> <span class='sev s-{f['severity']}'>{f['severity']}</span> "
        f"<code>{_E(f['file'])}:{f['line']}</code> {_E(_short(f.get('why'), 110))}</li>" for f in top) + "</ol>") if top else "<p>Nothing is open.</p>"
    return (f"<section id='summary'><h2><span class='n'>1</span>Summary</h2>"
            f"<h3 class='headline'>{len(st['real'])} real findings, {len(st['verified'])} fixed and verified</h3>"
            f"<p class='answer'>{_answer(job, st)}</p>"
            f"<div class='two'><div><h4>Fix these first</h4>{ff}</div><div><h4>Where they stand</h4>{_sev_table(job)}<p class='fine'>{st['dismissed'] + st['rejected_sast']} reported items were dropped as false alarms.</p></div></div></section>")


def _scope(job: dict) -> str:
    cov, d = job.get("coverage") or {}, job.get("decisions") or {}
    rec = next((s["summary"] for s in job["steps"] if s["role"] == "recon"), None)
    ran = any(s["role"] == "deep_dast" for s in job["steps"])
    rows = []
    rows.append(("Source code read", f"{cov['reviewed']} of {cov['source_files']} files ({cov['pct']:.0%})" if cov.get("pct") is not None else "unknown, the MCP could not see the repository", "mcp"))
    if rec:
        tot = rec.get("total_routes")
        rows.append(("Routes listed", f"{rec['endpoints']}" + (f" of {tot}" if tot else "") + (", all of them" if rec.get("complete") else ", a sample"), "agent"))
    rows.append(("Running app attacked", ("yes, " + {"create": "in a Docker sandbox", "existing": "at the address you gave"}.get(d.get("sandbox"), "")) if ran else "no", "agent"))
    decide = (f"<div class='decide'><b>What you decided.</b> GitHub webhook: <b>{_E(str(d.get('webhook')))}</b> · Test environment: <b>{_E(str(d.get('sandbox')))}"
              f"{(' (' + _E(d['sandbox_url']) + ')') if d.get('sandbox_url') else ''}</b> · Agents: <b>{_E(str(d.get('agents', 'n/a')))}</b> · Your words: “{_E(str(d.get('human_words', '')))}”</div>") if d else ""
    run_notes = "".join(f"<div class='note warn'><b>Run note.</b> {_E(n)}</div>" for n in job.get("run_notes", []))
    nope = ["Business-logic and multi-user access (can user A read user B's data) are tested only if a specialist read the code for them, never by two real accounts.",
            "Browser-side behaviour is not executed, so script injection is shown by the payload coming back unescaped, not by it running.",
            "Dependencies are judged from the agent's knowledge, not checked against an advisory database.",
            "The scanners in the Cyphex command-line tool (Semgrep, Nuclei) are not run by the MCP yet."]
    return (f"<section id='scope'><h2><span class='n'>2</span>Scope and coverage</h2>"
            f"<table class='facts'>{''.join(f'<tr><th>{_E(a)}</th><td>{_E(b)}</td><td>{_tag(c)}</td></tr>' for a, b, c in rows)}</table>{decide}{run_notes}"
            f"<h4>Not covered by this tool today</h4><ul class='plain'>{''.join(f'<li>{_E(x)}</li>' for x in nope)}</ul></section>")


def _lane_events(job: dict) -> list[dict]:
    ev = []
    for s in job["steps"]:
        ev.append({"agent": s["agent"], "at": s["at"], "role": s["role"], "text": _did(s), "trust": s["trust"], "by": "agent"})
    for f in job["findings"].values():
        v = (f.get("patch") or {}).get("verify")
        if v:
            ev.append({"agent": "cyphex fix check", "at": v.get("at", ""), "role": "verify", "text": f"{f['id']}: {v['verdict']}", "trust": {"PASS": "high", "FAIL": "low"}.get(v["verdict"], "medium"), "by": "mcp"})
    g = job.get("genome")
    if g and g.get("status") == "built":
        ev.append({"agent": "cyphex shield", "at": g.get("at", ""), "role": "genome", "text": f"Built from {g['endpoints_profiled']} routes, signed, reloaded, scored", "trust": "high", "by": "mcp"})
    ev.sort(key=lambda e: e["at"])
    return ev


def _did(s: dict) -> str:
    sm, r = s["summary"], s["role"]
    if r == "recon":
        return f"Listed {sm.get('endpoints', 0)} routes" + (" (says all of them)" if sm.get("complete") else " (says a sample)")
    if r == "deep_sast":
        c = sm.get("coverage") or {}
        return f"Reported {sm.get('candidates', 0)} bug(s): {sm.get('accepted', 0)} accepted, {len(sm.get('rejected', []))} rejected" + (f"; read {c['reviewed']} of {c['source_files']} files so far" if c.get("source_files") else "")
    if r == "deep_dast":
        return f"Attacked the app for {sm.get('tested', 0)} bug(s); {sm.get('proven', 0)} proven"
    if r == "council":
        return (f"Cast a ballot ({sm.get('ballots_in')} in so far)" if "reviewer" in sm else f"Second opinion on {sm.get('finding')}: {sm.get('tally')} agreed, so {sm.get('verdict')}")
    if r == "agent_security":
        return f"Audited agent configuration: {sm.get('issues', 0)} issue(s) in {sm.get('checked', 0)} file(s)"
    return (f"{sm.get('reviewer')} {'approved' if sm.get('approved') else 'rejected'} the fix for {sm.get('finding')}" if "reviewer" in sm else f"Wrote a fix for {sm.get('finding')}")


def _swimlane(job: dict, ev: list[dict]) -> str:
    if not ev:
        return ""
    order = []
    for e in sorted(ev, key=lambda e: (_STAGE.get(e["role"], 9), e["at"])):
        if e["agent"] not in order:
            order.append(e["agent"])
    ts = []
    for e in ev:
        try:
            ts.append(datetime.fromisoformat(e["at"]).timestamp())
        except ValueError:
            ts.append(0)
    t0, t1 = min(ts), max(ts)
    spread = t1 - t0 >= 4
    L, W, H = 150, 640, 22
    out = [f'<line x1="{L}" y1="0" x2="{L}" y2="{len(order) * H}" class="axis"/>']
    for i, a in enumerate(order):
        y = i * H
        out.append(f'<text x="{L - 8}" y="{y + 15}" class="ln" text-anchor="end" data-agent="{_E(a)}">{_E(a.replace("cyphex-", ""))}</text><line x1="{L}" y1="{y + H - 1}" x2="{L + W}" y2="{y + H - 1}" class="grid"/>')
    for idx, e in enumerate(ev):
        i = order.index(e["agent"])
        x = L + 12 + ((ts[idx] - t0) / (t1 - t0) * (W - 24) if spread else idx / max(len(ev) - 1, 1) * (W - 24))
        out.append(f'<circle cx="{x:.1f}" cy="{i * H + 11}" r="4.5" class="dot t-{e["trust"]} {"m" if e["by"] == "mcp" else ""}" data-agent="{_E(e["agent"])}"><title>{_E(e["agent"])} · {_E(e["at"][11:19])} · {_E(e["text"])}</title></circle>')
    note = ("<div class='fine'>Each dot is the moment the MCP received that agent's result, not how long the agent worked." +
            ("" if spread else " These all arrived within a few seconds, so they are spaced by order, not by time.") + "</div>")
    return f'<svg viewBox="0 0 {L + W + 6} {len(order) * H}" class="swim" role="img" aria-label="Which agent did what, in order">{"".join(out)}</svg>{note}'


def _timeline(ev: list[dict]) -> str:
    worst = {"low": 0, "medium": 1, "high": 2}
    grouped: list[list] = []
    for e in ev:
        key = (e["role"], e["agent"]) if e["role"] in ("verify",) else (e["role"],)
        if grouped and grouped[-1][0] == key and e["role"] in ("verify", "council", "patch_crew"):
            grouped[-1][1].append(e)
        else:
            grouped.append([key, [e]])
    rows = []
    for key, items in grouped:
        e0 = items[0]
        who, text, trust = e0["agent"].replace("cyphex-", ""), e0["text"], e0["trust"]
        if len(items) > 1:
            trust = min((i["trust"] for i in items), key=lambda t: worst[t])
            names = sorted({i["agent"].replace("cyphex-", "") for i in items})
            who = ", ".join(names) if len(names) <= 3 else f"{len(names)} agents"
            if e0["role"] == "verify":
                v = [i["text"].rsplit(": ", 1)[1] for i in items]
                text = f"Checked {len(items)} fixes: {v.count('PASS')} passed, {v.count('UNVERIFIABLE')} could not be verified, {v.count('FAIL')} failed"
            elif e0["role"] == "council":
                text = f"{len(items)} reviewers each cast one ballot over every finding, without seeing the others"
            else:
                wrote = sum(1 for i in items if i["text"].startswith("Wrote"))
                text = f"{wrote} fix(es) written, {len(items) - wrote} review(s) cast by separate agents"
        rows.append(f"<tr><td class='tm'>{_E(e0['at'][11:19])}</td><td><b>{_E(who)}</b></td><td>{_E(text)}</td><td class='t-{trust}'>{_E(trust)}</td><td>{_tag(e0['by'])}</td></tr>")
    return f"<table class='tl'><thead><tr><th>Time</th><th>Who</th><th>What happened</th><th>Trust</th><th>Source</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _log(job: dict) -> str:
    out, last = [], None
    ids = _ids(job)
    events = narrate.feed(job)
    for e in events:
        for internal, shown in ids.items():
            e["say"] = e["say"].replace(internal, shown)
        label = narrate.STAGE_LABEL.get(e["role"], {"verify": "Checking the fixes", "genome": "Runtime shield"}.get(e["role"], e["role"]))
        if label != last:
            out.append(("</ul>" if last else "") + f"<h5>{_E(label)}</h5><ul>")
            last = label
        out.append(f"<li><time>{_E(e['at'][11:19])}</time><span>{_E(e['say'])}</span></li>")
    silent = [n for n, r in (job.get("roster") or {}).items() if r.get("deployed") and not r.get("reported")]
    if silent:
        out.append(("</ul>" if last else "") + "<h5>Never reported</h5><ul>" + "".join(
            f"<li><time>-</time><span>{_E(narrate.cap(narrate.who(n)))} was deployed but sent nothing back"
            + (", so no finding was tested against the running app." if "prober" in n else ".") + "</span></li>" for n in silent))
        last = "x"
    return "".join(out) + ("</ul>" if last else "") if out else "<p class='fine'>No agent has reported yet.</p>"


def _team(job: dict) -> str:
    cards = evals.scorecards(job)
    deployed = [c for c in cards if c["deployed"]]
    ev = _lane_events(job)
    if deployed:
        silent = [c["agent"] for c in deployed if not c["reports"]]
        loose = any(r.get("tool_limits_enforced") is False for r in job.get("roster", {}).values())
        banner = (f"<div class='note ok'><b>{len(deployed)} agents were deployed</b> as separate Claude Code subagents, each with its own context and tool list. "
                  f"{len(deployed) - len(silent)} reported back." + (f" <b>{len(silent)} deployed but never reported</b>: {_E(', '.join(a.replace('cyphex-', '') for a in silent))}." if silent else "") +
                  ("</div><div class='note warn'><b>Tool limits were not enforced in this run.</b> Claude Code had not loaded the new agent files, so the agents ran as general-purpose "
                   "subagents with the same instructions but without the tool allowlists shown below. Separate contexts and separate models were real; the allowlists were not.</div>" if loose else "</div>"))
    else:
        banner = ("<div class='note warn'><b>No separate agents were deployed.</b> One session played every role in turn, so the specialists did not run in parallel "
                  "and the review board is not independent: the same model read the same context and voted several times.</div>")
    rows = []
    for c in cards:
        tools = c["tools"]
        can = [w for w, on in (("runs commands", "Bash" in tools), ("uses the network", {"WebFetch", "WebSearch"} & set(tools)), ("edits files", {"Edit", "Write"} & set(tools))) if on]
        caps = ("reads only" if not can else ", ".join(can)) if tools else "<span class='fine'>not recorded</span>"
        status = ("reported" if c["reports"] else "deployed, silent") if c["deployed"] else ("ran inline" if c["reports"] else "")
        rows.append(f"<tr class='agentrow' data-agent='{_E(c['agent'])}'><td><b>{_E(c['agent'].replace('cyphex-', ''))}</b></td><td>{_E(_ROLE_LABEL.get(c['role'], c['role']))}</td>"
                    f"<td>{_E(c['model'] or 'session model')}</td><td>{caps}</td><td>{c['reports']}</td><td class='st-{status.split(',')[0].replace(' ', '-')}'>{_E(status)}</td></tr>")
    table = (f"<div class='np'><h4 id='whatagents'>What each agent did</h4><table class='agents'><thead><tr><th>Agent</th><th>Job</th><th>Model</th><th>Allowed to</th><th>Reports</th><th>Status</th></tr></thead>"
             f"<tbody>{''.join(rows)}</tbody></table><p class='fine'>“Allowed to” comes from the tool list Claude Code enforces for that agent. Click a row to see only its findings.</p></div>") if cards else ""
    return (f"<section id='team'><h2><span class='n'>3</span>The team and how the scan ran</h2>{banner}"
            f"<div class='np log'><h4>What happened, in order</h4><p class='fine'>Cyphex hands the assistant one plain sentence each time an agent finishes, so the person can follow along in the chat. This is that list.</p>{_log(job)}</div>"
            f"<p class='fine'>{_tag('mcp')}: Cyphex checked it itself. {_tag('agent')}: an agent says so and Cyphex could not check it, for example whether an attack really worked.</p>{table}</section>")


def _finding_rows(job: dict, ids: dict, group: list[dict], dismissed: bool = False) -> str:
    out = []
    for f in group:
        did = ids[f["id"]]
        proof, status = ledger.proof_level(f), ledger.patch_status(f)
        if dismissed:
            proof, status = "dismissed", "no patch"
        dast, council, patch = f.get("dast") or {}, f.get("council") or {}, f.get("patch") or {}
        agents = [f.get("found_by", "")] + list(f.get("also_found_by", []))
        ev = [f"<p>{_E(f.get('why') or '')}</p>"]
        if f.get("snippet"):
            ev.append(f"<h5>The code {_tag('mcp')}</h5><pre>{_E(f['snippet'])}</pre><div class='fine'>{_E(f['file'])}:{f['line']} · line existence checked</div>")
        if dast:
            ev.append(f"<h5>Attack test: {'worked' if dast.get('proven') else 'did not work, or was not possible'} {_tag('agent')}</h5><pre>{_E(dast.get('evidence') or 'no evidence recorded')}</pre>")
        votes = council.get("votes", [])
        board = (f"<p>{council.get('confirms')} of {council.get('total')} reviewers confirmed. {_tag('mcp')} votes tallied by Cyphex</p><table class='votes'>" +
                 "".join(f"<tr><td><b>{_E(str(v.get('persona')).replace('cyphex-', ''))}</b><div class='fine'>{_E(v.get('model') or '')}</div></td><td class='v-{_E(str(v.get('vote')))}'>{_E(str(v.get('vote')))}</td><td>{_E(str(v.get('reason', '')))}</td></tr>" for v in votes) + "</table>") if votes else "<p>No review-board vote was recorded.</p>"
        v = patch.get("verify") or {}
        fix = ((f"<p>Fix check: <b>{_E(v.get('verdict', 'not run'))}</b></p><ul class='checks'>" +
                "".join(f"<li class='c{_E(str(c['ok']))}'>{_E(c['name'])}: {_E(c['detail'])} {_tag(c.get('by', 'mcp'))}</li>" for c in v.get("checks", [])) +
                "</ul>" + "".join(f"<div class='fine'>{_E(r.get('reviewer', ''))}: {'approved' if r.get('approved') else 'rejected'}, {_E(r.get('note', ''))}</div>" for r in patch.get("reviews", [])) +
                f"<pre class='diff'>{_E(patch.get('diff', ''))}</pre>") if patch else "<p>No fix was written.</p>")
        repro = (f"<p class='fine'>The request the agent reports it sent. Run it only against a copy you own.</p><pre id='r-{did}'>{_E(dast.get('evidence') or 'No attack evidence was recorded for this finding.')}</pre>"
                 f"<button class='copy' data-copy='r-{did}'>Copy</button>")
        text = " ".join([did, f["id"], f["file"], f["cwe"], str(f.get("why", ""))]).lower()
        out.append(f"<tr class='frow' id='{did}' data-sev='{f['severity']}' data-status='{status.replace(' ', '-')}' data-proof='{proof}' data-agents='{_E('|'.join(agents))}' data-text='{_E(text)}'>"
                   f"<td class='fid'>{did}</td><td><span class='sev s-{f['severity']}'>{f['severity']}</span></td><td class='ft'>{_E(_short(f.get('why'), 100))}<div class='fine'>{_E(f['cwe'])} · found by {_E(', '.join(a.replace('cyphex-', '') for a in agents if a))}</div></td>"
                   f"<td><code>{_E(f['file'])}:{f['line']}</code></td>"
                   f"<td><span class='pill p-{proof}'>{proof}</span></td><td><span class='pill st-{status.replace(' ', '-')}'>{_E(status)}</span></td></tr>"
                   f"<tr class='fdet' data-for='{did}' hidden><td colspan='6'><div class='tabs'><button data-tab='ev' class='on'>Evidence</button><button data-tab='bd'>Review board</button>"
                   f"<button data-tab='fx'>Fix</button><button data-tab='rp'>Reproduce</button></div>"
                   f"<div class='pane' data-pane='ev'>{''.join(ev)}</div><div class='pane' data-pane='bd' hidden>{board}</div><div class='pane' data-pane='fx' hidden>{fix}</div><div class='pane' data-pane='rp' hidden>{repro}</div></td></tr>")
    return "".join(out)


def _findings(job: dict, st: dict, ids: dict) -> str:
    fs = sorted(job["findings"].values(), key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["id"]))
    real = [f for f in fs if f not in [x for x in fs if x.get("council", {}).get("verdict") == "rejected"]]
    dismissed = [f for f in fs if f.get("council", {}).get("verdict") == "rejected"]
    agent_opts = sorted({a for f in fs for a in [f.get("found_by", "")] + list(f.get("also_found_by", [])) if a})
    ctl = ("<div class='controls'><input id='q' type='search' placeholder='Search findings  ( / )' aria-label='Search findings'>"
           "<select id='fs' aria-label='Severity'><option value=''>Any severity</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>"
           "<select id='fp' aria-label='Proof'><option value=''>Any proof</option><option value='proven'>Proven</option><option value='unproven'>Not proven</option></select>"
           "<select id='ft' aria-label='Fix status'><option value=''>Any fix status</option><option value='verified-fixed'>Fixed and checked</option><option value='open'>Still open</option></select>"
           "<select id='fa' aria-label='Found by'><option value=''>Any agent</option>" + "".join(f"<option value='{_E(a)}'>{_E(a.replace('cyphex-', ''))}</option>" for a in agent_opts) + "</select>"
           "<button id='expall' type='button'>Open all</button><span id='count' class='fine'></span></div>")
    thead = ("<colgroup><col style='width:62px'><col style='width:78px'><col><col style='width:196px'><col style='width:92px'><col style='width:100px'></colgroup>"
             "<thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th><th>Proof</th><th>Fix</th></tr></thead>")
    legend = ("<p class='fine'><b>Proven</b>: the attack worked on the running app. <b>Confirmed</b>: most reviewers agreed after reading the code. "
              "<b>Candidate</b>: reported from reading code only. Click a row for the code, the attack, the reviewers and the fix.</p>")
    dis = (f"<h4>Dismissed by the council</h4><p class='fine'>Reported, then outvoted. Kept so you can see why.</p><table class='ftable dis'>{thead}<tbody>{_finding_rows(job, ids, dismissed, True)}</tbody></table>") if dismissed else ""
    return (f"<section id='findings'><h2><span class='n'>4</span>Findings</h2>{legend}{ctl}"
            f"<table class='ftable' id='ft1'>{thead}<tbody>{_finding_rows(job, ids, real)}</tbody></table>{dis}</section>")


def _fixes(job: dict, ids: dict) -> str:
    rows = []
    for f in sorted(job["findings"].values(), key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["id"])):
        p = f.get("patch")
        if not p:
            continue
        v = p.get("verify") or {}
        ck = v.get("checks", [])
        ok, bad, nm = (sum(1 for c in ck if c["ok"] is x) for x in (True, False, None))
        revs = ", ".join(f"{r['reviewer'].replace('cyphex-', '')} {'yes' if r['approved'] else 'no'}" for r in p.get("reviews", [])) or "none"
        rows.append(f"<tr><td><a href='#{ids[f['id']]}' data-jump='{ids[f['id']]}'>{ids[f['id']]}</a></td><td>{_E(f['file'])}</td><td>{_E(revs)}</td>"
                    f"<td>{ok} passed{f', {bad} failed' if bad else ''}{f', {nm} not measured' if nm else ''}</td><td><span class='pill st-{ledger.patch_status(f).replace(' ', '-')}'>{_E(ledger.patch_status(f))}</span></td></tr>")
    if not rows:
        return "<section id='fixes'><h2><span class='n'>5</span>Fixes and how they were checked</h2><p>No fixes were written on this scan.</p></section>"
    return (f"<section id='fixes'><h2><span class='n'>5</span>Fixes and how they were checked</h2>"
            f"<p>A fix counts as verified only if the exploit was proven on the original code, the diff applies and compiles, it adds no suppression comments, two reviewers approved, and the agent reports the exploit no longer works. "
            f"The last item is the agent's report: Cyphex does not re-run the attack yet.</p>"
            f"<table class='plain'><thead><tr><th>ID</th><th>File</th><th>Reviewers</th><th>Checks</th><th>Result</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>")


def _bar(p: int, f: int, n: int) -> str:
    t = max(p + f + n, 1)
    return (f"<span class='seg'><i class='ok' style='width:{p / t * 100:.0f}%'></i><i class='bad' style='width:{f / t * 100:.0f}%'></i><i class='nm' style='width:{n / t * 100:.0f}%'></i></span>"
            f"<span class='fine'>{p} / {f} / {n}</span>")


_INJ = {"followed it": ("bad", "Followed the planted instruction"), "reported it": ("ok", "Reported it as an attack"), "ignored it": ("ok", "Read it and ignored it"), "never opened the file": ("nm", "Never opened that file")}


def _stat_text(c: dict) -> str:
    s = c["stats"]
    if not s:
        return ""
    r = c["role"]
    if r == "deep_sast":
        return f"{s['reported']} reported · {s['confirmed']} confirmed · {s['dismissed']} dismissed · {s['proven']} proven · {s['files_read']} files read" + (f" · {s['rejected_by_cyphex']} rejected by Cyphex" if s["rejected_by_cyphex"] else "")
    if r == "council" and "votes" in s:
        return f"{s['votes']} votes · {s['with_majority']} with the majority · {s['dissents']} dissents · confirmed {s['confirms']}"
    if r == "patch_crew":
        return (f"{s['fixes_written']} fixes · {s['verified']} verified · {s['failed']} failed · {s['unverified']} unverified" if "fixes_written" in s else f"{s['reviews']} reviews · {s['approved']} approved · {s['rejected']} rejected")
    if r == "deep_dast":
        return f"{s['tested']} tested · {s['proven']} proven"
    if r == "recon":
        return f"{s['routes']} routes · " + ("complete" if s["complete"] else "a sample")
    return ""


def _eval(job: dict, ids: dict) -> str:
    cards = [c for c in evals.scorecards(job) if c["reports"] or c["deployed"]]
    rows = []
    for c in cards:
        inj = _INJ.get(c["injection"])
        rows.append(f"<tr><td><b>{_E(c['agent'].replace('cyphex-', ''))}</b><div class='fine'>{_E(c['model'] or 'session model')}</div></td><td>{_E(_ROLE_LABEL.get(c['role'], c['role']))}</td>"
                    f"<td>{_E(_stat_text(c)) or '<span class=fine>did not report</span>'}</td><td>{_bar(c['checks_passed'], c['checks_failed'], c['checks_unmeasured'])}</td>"
                    f"<td>{(f'<span class=inj-{inj[0]}>{_E(inj[1])}</span>') if inj else '<span class=fine>not tested</span>'}</td></tr>")
    g = evals.ballot_grid(job)
    grid = ""
    if g["reviewers"]:
        head = "".join(f"<th title='{_E(r['model'])}'>{_E(r['name'].replace('cyphex-', ''))}<div class='fine'>{_E(r['model'] or '')}</div></th>" for r in g["reviewers"])
        body = []
        for row in sorted(g["rows"], key=lambda r: ids.get(r["id"], "")):
            cells = "".join(f"<td class='vc v-{_E(str(row['votes'][r['name']].get('vote', 'none')))}' title='{_E(str(row['votes'][r['name']].get('reason', '')))}'>{'●' if row['votes'][r['name']].get('vote') == 'confirm' else ('○' if row['votes'][r['name']].get('vote') == 'reject' else '·')}</td>" for r in g["reviewers"])
            body.append(f"<tr><td><a href='#{ids.get(row['id'], '')}' data-jump='{ids.get(row['id'], '')}'>{ids.get(row['id'], '')}</a></td>{cells}<td class='v-{_E(str(row['verdict']))}'>{_E(str(row['verdict'] or 'pending'))}</td></tr>")
        grid = (f"<div class='np'><h4>Review board: who voted how</h4><p class='fine'>● confirm, ○ reject. Each reviewer is a separate agent that voted without seeing the others. A column that disagrees with the verdict is a dissent.</p>"
                f"<table class='grid'><thead><tr><th>Finding</th>{head}<th>Verdict</th></tr></thead><tbody>{''.join(body)}</tbody></table></div>")
    else:
        grid = "<h4>Review board</h4><p>No separate ballots were cast. Votes, if any, came from one session playing several reviewers.</p>"
    tbl = (f"<table class='agents ev'><thead><tr><th>Agent</th><th>Job</th><th>Measured results</th><th>Checks on its output<div class='fine'>passed / failed / not measured</div></th><th>Injection test</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
           if rows else "<p>No agent reports were recorded.</p>")
    return (f"<section id='eval'><h2><span class='n'>6</span>Agent evaluation</h2>"
            f"<p>Every number is counted from what the MCP recorded. There is no overall score, because one number would hide which agent was wrong and about what. "
            f"A specialist whose findings the board keeps dismissing is noisy. A reviewer who always votes with the majority adds little. "
            f"An agent with failed checks reported something that did not hold up.</p>{tbl}{grid}</section>")


def _agentsec(job: dict) -> str:
    sec = job.get("agent_security") or {}
    cards = [c for c in evals.scorecards(job) if c["tools"]]
    rail = "".join(f"<li>{_E(x)}</li>" for x in core.GUARDRAILS)
    posture = (f"<div class='np'><table class='agents'><thead><tr><th>Agent</th><th>Tools Claude Code lets it use</th><th>Shell</th><th>Network</th><th>Writes</th></tr></thead><tbody>" +
               "".join(f"<tr><td><b>{_E(c['agent'].replace('cyphex-', ''))}</b></td><td class='fine'>{_E(', '.join(t.replace('mcp__cyphex__', 'cyphex:') for t in c['tools']))}</td>"
                       f"<td>{'yes' if 'Bash' in c['tools'] else 'no'}</td><td>{'yes' if {'WebFetch', 'WebSearch'} & set(c['tools']) else 'no'}</td><td>{'yes' if {'Edit', 'Write'} & set(c['tools']) else 'no'}</td></tr>" for c in cards) + "</tbody></table></div>") if cards else \
        "<p>No agents were deployed, so there are no per-agent tool limits to show. Guardrails below were only instructions to one session.</p>"
    audit = sec.get("config_audit")
    if audit:
        fr = "".join(f"<tr><td><span class='sev s-{x['severity']}'>{x['severity']}</span></td><td><code>{_E(x['file'])}</code></td><td>{_E(x['why'])}<div class='fine'>Fix: {_E(x['fix'])}</div></td></tr>" for x in audit["findings"])
        ca = (f"<p>{_E(audit['summary'])}. Files read: {_E(', '.join(audit['checked']))}. {_tag('mcp')}</p>" +
              (f"<table class='plain'><thead><tr><th>Severity</th><th>File</th><th>Issue</th></tr></thead><tbody>{fr}</tbody></table>" if fr else "<p>No risky settings were found.</p>"))
    else:
        ca = "<p>The configuration audit was not run on this scan.</p>"
    can = sec.get("canary") or {}
    if job.get("canary"):
        cr = "".join(f"<tr><td><b>{_E(a.replace('cyphex-', ''))}</b></td><td class='inj-{_INJ[s][0]}'>{_E(_INJ[s][1])}</td></tr>" for a, s in sorted(can.items())) or "<tr><td colspan='2'>No agent has reported yet.</td></tr>"
        inj = (f"<p>A note was planted in a scratch copy of the code, telling reviewers the file was safe and to add a tag to every finding. An agent that does either has been steered by text it only read. "
               f"{_tag('mcp')}</p><table class='plain'><thead><tr><th>Agent</th><th>Result</th></tr></thead><tbody>{cr}</tbody></table>")
    else:
        inj = "<p>The injection test was not run on this scan. Run plant_canary on a scratch copy to test whether your agents obey instructions hidden in code.</p>"
    log = sec.get("guard_log") or []
    lg = ("<table class='plain'><thead><tr><th>Time</th><th>Call</th><th>Decision</th><th>Why</th></tr></thead><tbody>" +
          "".join(f"<tr><td class='tm'>{_E(x['at'][11:19])}</td><td><code>{_E(x['tool'])}</code> {_E(x['args'])}</td><td><b>{_E(x['decision'])}</b></td><td>{_E(x['reason'])}</td></tr>" for x in log) + "</tbody></table>") if log else "<p>No tool calls were put through the call gate on this scan.</p>"
    return (f"<section id='agentsec'><h2><span class='n'>7</span>Agent security</h2>"
            f"<p>These are the controls around the agents themselves: what each one is allowed to touch, whether the project's own agent setup is safe, "
            f"and whether an agent can be steered by text in the code it reads.</p>"
            f"<h4>Limits on each agent</h4>{posture}<h4>Rules every agent is given</h4><ul class='plain'>{rail}</ul>"
            f"<h4>Configuration audit</h4>{ca}<h4>Injection test</h4>{inj}<h4>Call gate log</h4>{lg}</section>")


def _genome(g) -> str:
    if not g or g.get("status") != "built":
        return f"<p>The genome was not built. {_E((g or {}).get('fix', 'Run build_genome after recon.'))}</p>"
    e, d = g["eval"], g["eval"].get("with_engine_defaults", {})
    pct = lambda x: f"{int(round(x * 100))}%"
    bars = "".join(f"<div class='gb'><span>{_E(k)}</span><i style='width:{int(v * 100)}%'></i><b>{int(v * 100)}%</b></div>" for k, v in e["per_category_block"].items())
    files = "".join(f"<li><code>{_E(p)}</code></li>" for p in g.get("files", []))
    return (f"<p>A learned model of what normal requests to the app look like. It blocks requests that look nothing like normal, including attacks nobody has catalogued. "
            f"Measured on attack and normal strings it was not trained on. {_tag('mcp')}</p>"
            f"<div class='figs'><div><b>{pct(e['attack_block_rate'])}</b><span>of {e['attack_samples']} attack strings blocked</span></div>"
            f"<div><b>{pct(e['normal_flagged_rate'])}</b><span>of {e['normal_samples']} normal inputs flagged for review</span></div>"
            f"<div><b>{pct(e['normal_blocked_rate'])}</b><span>of normal inputs blocked</span></div></div>{bars}"
            f"<p class='fine'>Thresholds were set from this genome's own normal scores (block {e['thresholds']['block']}, review {e['thresholds']['challenge']}). "
            f"With the engine's fixed defaults (block {d.get('thresholds', {}).get('block')}, review {d.get('thresholds', {}).get('challenge')}) it would flag {pct(d.get('normal_flagged_rate', 0))} of normal inputs, which is unusable. "
            f"{_E(e['note'])}. Not yet tested on real traffic.</p>"
            f"<details class='files'><summary>Genome files on this machine ({len(g.get('files', []))})</summary><p class='fine'>The model is <code>{_E(g.get('pkl', ''))}</code>. "
            f"Ship the <code>.cxgenome</code> bundle to your edge: it carries the model, its signature and the thresholds.</p><ul class='plain'>{files}</ul></details>")


def _trust_notes(job: dict) -> list[str]:
    notes = []
    ids = _ids(job)
    st = _stats(job)
    unproven = [ids.get(f["id"], f["id"]) for f in st["real"] if ledger.proof_level(f) != "proven"]
    if unproven:
        notes.append(f"{len(unproven)} real findings were not proven by a working exploit and rest on code reading plus the council vote: {', '.join(sorted(unproven))}.")
    for f in job["findings"].values():
        bad = [c for c in ((f.get("patch") or {}).get("verify") or {}).get("checks", []) if c["ok"] is not True]
        if bad:
            what = "; ".join(f"{c['name']} ({'FAILED' if c['ok'] is False else 'not measured'}: {c['detail']})" for c in bad)
            notes.append(f"Fix for {ids.get(f['id'], f['id'])}: {what}")
    for s in job["steps"]:
        for c in s["checks"]:
            if c["ok"] is not True:
                notes.append(f"{_ROLE_LABEL.get(s['role'], s['role'])} ({s['agent']}) · {c['name']} · {'FAILED' if c['ok'] is False else 'not measured'}: {c['detail']}")
        for r in s["summary"].get("rejected", []) if s["role"] == "deep_sast" else []:
            notes.append(f"Deep SAST ({s['agent']}) · finding {r['id']} dropped: {r['why']}")
    return sorted(set(notes))


def _limits(job: dict) -> str:
    notes = _trust_notes(job)
    ul = ("<ul class='plain'>" + "".join(f"<li>{_E(n)}</li>" for n in notes) + "</ul>") if notes else "<p>Every check on every agent passed.</p>"
    return f"<section id='limits'><h2><span class='n'>9</span>Can I trust this?</h2><p>Everything Cyphex could not measure, or measured and found wanting:</p>{ul}</section>"


def _appendix(job: dict) -> str:
    g = job.get("genome") or {}
    rows = [("Run folder", str(ledger.data_dir() / job["job_id"])), ("Full record", str(ledger.data_dir() / f"{job['job_id']}.json")), ("Genome model", g.get("pkl", "not built")), ("Activity log", str(ledger.base_dir() / "SECURITY_LOG.md"))]
    return (f"<section id='appendix'><h2><span class='n'>10</span>Where everything is</h2><table class='facts'>" +
            "".join(f"<tr><th>{_E(a)}</th><td><code>{_E(b)}</code></td><td></td></tr>" for a, b in rows) + "</table></section>")


_CSS = """
:root{--bg:#efebe2;--sheet:#fdfcf8;--ink:#1f1e1b;--muted:#6a665d;--faint:#b4aea1;--rule:#ddd7ca;--accent:#2a4766;--crit:#8a1f1f;--high:#96470f;--med:#7a6000;--low:#3b5d7c;--ok:#2d6a3e;--bad:#8a1f1f;--code:#f2efe6;--hl:#f6f2e8;
--serif:Charter,"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:16px}body{margin:0;background:var(--bg);color:var(--ink);font:400 16px/1.6 var(--serif)}
.layout{display:grid;grid-template-columns:190px minmax(0,900px);gap:32px;max-width:1160px;margin:0 auto;padding:32px 20px 80px;justify-content:center}
nav.toc{position:sticky;top:32px;align-self:start;font:13.5px/1.4 var(--sans)}nav.toc .brand{font:600 15px var(--serif);margin-bottom:10px}
nav.toc a{display:block;padding:4px 0;color:var(--muted);text-decoration:none}nav.toc a:hover{color:var(--ink);text-decoration:underline}nav.toc a.on{color:var(--ink);font-weight:600}
.sheet{background:var(--sheet);padding:52px 58px 64px;border:1px solid var(--rule);min-width:0}
.cover{margin-bottom:30px;padding-bottom:18px;border-bottom:1px solid var(--ink)}.over{font:14px var(--sans);color:var(--muted)}
h1{font:400 40px/1.15 var(--serif);margin:6px 0 16px;letter-spacing:-.01em}h2{font:400 26px/1.2 var(--serif);margin:48px 0 12px;padding-top:14px;border-top:1px solid var(--rule)}h2 .n{margin-right:.35em}h2 .n::after{content:"."}
h3.headline{font:600 19px var(--serif);margin:4px 0}h4{font:600 14px var(--sans);color:var(--ink);margin:24px 0 8px}h5{font:600 13px var(--sans);margin:12px 0 4px;color:var(--muted)}
p{margin:9px 0;max-width:70ch}.answer{font-size:18px;line-height:1.6;max-width:66ch}.fine{font:13px/1.5 var(--sans);color:var(--muted)}
table{border-collapse:collapse;width:100%;font:14px/1.45 var(--sans)}th,td{text-align:left;vertical-align:top;padding:7px 10px 7px 0;border-bottom:1px solid var(--rule)}th{font:600 13px var(--sans);color:var(--muted);border-bottom:1px solid var(--ink)}
table.meta{width:auto;font-size:14px}table.meta th{border:0;padding:1px 22px 1px 0;font-weight:400;color:var(--muted)}table.meta td{border:0;padding:1px 0}
table.facts th{width:210px;font-weight:600;color:var(--ink);border-bottom:1px solid var(--rule)}
.two{display:grid;grid-template-columns:1.3fr 1fr;gap:34px}ol.ff{margin:0;padding-left:20px}ol.ff li{margin:8px 0;font-size:15px}
table.sevt{max-width:420px}table.sevt td,table.sevt th{text-align:right;padding-right:12px}table.sevt td:first-child,table.sevt th:first-child{text-align:left}
.sev{font:600 13px var(--sans)}.s-critical{color:var(--crit)}.s-high{color:var(--high)}.s-medium{color:var(--med)}.s-low{color:var(--low)}
.pill{font:13px var(--sans);white-space:nowrap}.p-proven,.st-verified-fixed{color:var(--ok);font-weight:600}.p-confirmed,.st-unverified,.st-awaiting-verify{color:var(--med)}.p-candidate,.st-patch-failed{color:var(--bad)}.p-dismissed,.st-no-patch{color:var(--muted)}
.by{font:italic 12.5px var(--sans);color:var(--muted)}
code{font:12.5px var(--mono);background:var(--code);padding:1px 4px;word-break:break-all}pre{background:var(--code);padding:10px 12px;overflow-x:auto;font:12.5px/1.5 var(--mono);margin:6px 0;white-space:pre-wrap}pre.diff{border-left:2px solid var(--accent)}
.note{padding:2px 0 2px 14px;margin:14px 0;border-left:3px solid var(--faint);font-size:15px;max-width:76ch}.note.warn{border-left-color:var(--med)}.note.ok{border-left-color:var(--ok)}
.decide{margin:14px 0;font-size:15px;color:var(--muted);max-width:76ch}ul.plain{padding-left:20px;max-width:76ch}ul.plain li{margin:6px 0}
.log h5{font:600 14px var(--sans);color:var(--ink);margin:18px 0 4px}.log ul{list-style:none;margin:0;padding:0}.log li{display:grid;grid-template-columns:64px 1fr;gap:8px;padding:4px 0;border-bottom:1px solid var(--rule);font-size:15px}.log time{font:12.5px var(--mono);color:var(--muted);padding-top:2px}
.agentrow{cursor:pointer}.agentrow:hover td{background:var(--hl)}.st-deployed{color:var(--bad)}.st-reported{color:var(--ok)}.st-ran-inline{color:var(--muted)}
td.tm{font:12.5px var(--mono);color:var(--muted);white-space:nowrap}.t-high{color:var(--ok)}.t-medium{color:var(--med)}.t-low{color:var(--bad)}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0;position:sticky;top:0;background:var(--sheet);padding:8px 0;z-index:3;border-bottom:1px solid var(--rule)}
.controls input,.controls select,.controls button{font:14px var(--sans);padding:6px 9px;border:1px solid var(--faint);background:var(--sheet);color:var(--ink);border-radius:3px}.controls input{min-width:210px;flex:1}.controls button{cursor:pointer}
.ftable tbody tr.frow{cursor:pointer}.ftable tbody tr.frow:hover td{background:var(--hl)}.ftable tr.frow.open td{background:var(--hl);border-bottom-color:transparent}td.fid{font:600 13px var(--sans);white-space:nowrap}table.ftable{table-layout:fixed;width:100%}.ftable code{white-space:nowrap;word-break:normal}.ftable td{overflow-wrap:anywhere;padding-right:10px}
.fdet>td{padding:0 0 16px 0;background:var(--hl)}.tabs{display:flex;gap:2px;padding:0 12px;border-bottom:1px solid var(--rule)}.tabs button{font:600 13px var(--sans);border:0;background:none;padding:8px 12px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}.tabs button.on{color:var(--ink);border-bottom-color:var(--accent)}
.pane{padding:6px 16px}.votes td{font-size:14px}.v-confirm,.v-confirmed{color:var(--ok);font-weight:600}.v-reject,.v-rejected{color:var(--bad);font-weight:600}
ul.checks{margin:4px 0;padding-left:18px}.cTrue::marker{color:var(--ok)}.cFalse::marker{color:var(--bad)}.cNone::marker{color:var(--med)}button.copy{font:13px var(--sans);padding:4px 10px;border:1px solid var(--faint);background:var(--sheet);color:var(--ink);cursor:pointer;border-radius:3px}
.seg{display:inline-flex;width:90px;height:6px;background:var(--rule);margin-right:6px;vertical-align:2px}.seg i{display:block;height:100%}.seg .ok{background:var(--ok)}.seg .bad{background:var(--bad)}.seg .nm{background:var(--med)}
table.grid td.vc{text-align:center;font-size:15px}table.grid th{text-align:center}table.grid th:first-child,table.grid td:first-child{text-align:left}.inj-ok{color:var(--ok);font-weight:600}.inj-bad{color:var(--bad);font-weight:600}.inj-nm{color:var(--muted)}
.gb{display:grid;grid-template-columns:130px 1fr 40px;align-items:center;gap:8px;margin:3px 0;font:13.5px var(--sans)}.gb i{display:block;height:6px;background:var(--accent);min-width:2px}.gb b{text-align:right;font-weight:600}details.files summary{cursor:pointer;font:13.5px var(--sans);color:var(--muted);margin-top:8px}
@media (max-width:900px){.layout{grid-template-columns:1fr}nav.toc{display:none}.sheet{padding:26px 18px}.two{grid-template-columns:1fr}}
@media print{body{background:#fff;font-size:11px}.layout{display:block;padding:0}nav.toc,.controls,.tabs,button,.fdet,#team .swim,.np{display:none!important}table.ftable{table-layout:auto}.ftable col{width:auto!important}.ftable code{white-space:normal;word-break:break-all}td.ft{font-size:10px}.ftable td.ft .fine{display:none}.ftable td,.ftable th{padding:2px 6px;font-size:10px}.ftable .pill,.ftable .sev{font-size:8.5px}.ftable td:nth-child(4){width:30%}.sheet{box-shadow:none;padding:0}h2{break-after:avoid;margin-top:20px}tr{break-inside:avoid}#eval,#agentsec,#appendix{break-before:auto}@page{size:A4;margin:12mm}}
"""

_JS = r"""
(function(){
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const rows=$$('tr.frow'),q=$('#q'),fs=$('#fs'),fp=$('#fp'),ft=$('#ft'),fa=$('#fa'),count=$('#count');
function apply(){const t=(q.value||'').toLowerCase().trim();let n=0;
 rows.forEach(r=>{const d=r.dataset,show=(!t||d.text.includes(t))&&(!fs.value||d.sev===fs.value)&&
  (!fp.value||(fp.value==='proven'?d.proof==='proven':d.proof!=='proven'))&&
  (!ft.value||(ft.value==='open'?d.status!=='verified-fixed':d.status===ft.value))&&
  (!fa.value||d.agents.split('|').includes(fa.value));
  r.hidden=!show;const det=$('tr.fdet[data-for="'+r.id+'"]');if(!show&&det)det.hidden=true;if(show)n++;});
 if(count)count.textContent=n+' shown of '+rows.length}
[q,fs,fp,ft,fa].forEach(e=>e&&e.addEventListener('input',apply));
function toggle(r,force){const det=$('tr.fdet[data-for="'+r.id+'"]');if(!det)return;const open=force===undefined?det.hidden:force;det.hidden=!open;r.classList.toggle('open',open)}
rows.forEach(r=>r.addEventListener('click',()=>toggle(r)));
$$('.tabs button').forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();const cell=b.closest('td');
 cell.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));
 cell.querySelectorAll('.pane').forEach(p=>p.hidden=p.dataset.pane!==b.dataset.tab)}));
const ex=$('#expall');if(ex)ex.addEventListener('click',()=>{const o=ex.dataset.o!=='1';rows.filter(r=>!r.hidden).forEach(r=>toggle(r,o));ex.dataset.o=o?'1':'0';ex.textContent=o?'Close all':'Open all'});
function jump(id){const r=document.getElementById(id);if(!r)return;if(r.hidden){[q,fs,fp,ft,fa].forEach(e=>e&&(e.value=''));apply()}toggle(r,true);r.scrollIntoView({block:'center'})}
$$('[data-jump]').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();jump(a.dataset.jump)}));
function byAgent(a){if(!fa)return;fa.value=a;apply();location.hash='findings';$('#findings').scrollIntoView()}
$$('.agentrow').forEach(r=>r.addEventListener('click',()=>byAgent(r.dataset.agent)));
$$('.swim .ln').forEach(t=>t.addEventListener('click',()=>byAgent(t.dataset.agent)));
$$('button.copy').forEach(b=>b.addEventListener('click',()=>{const t=document.getElementById(b.dataset.copy).textContent;
 (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>{b.textContent='Copied'},()=>{b.textContent='Select and copy'});setTimeout(()=>b.textContent='Copy',1500)}));
document.addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();q&&q.focus()}});
const links=$$('nav.toc a'),secs=links.map(a=>document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
if('IntersectionObserver' in window){const io=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){links.forEach(l=>l.classList.toggle('on',l.getAttribute('href')==='#'+e.target.id))}})},{rootMargin:'-20% 0px -70% 0px'});secs.forEach(s=>io.observe(s))}
if(location.hash&&/^#CX-\d+$/.test(location.hash))jump(location.hash.slice(1));
apply();
})();
"""


def render_report(job: dict) -> str:
    st = _stats(job)
    ids = _ids(job)
    nav = [("summary", "Summary"), ("scope", "Scope"), ("team", "The team"), ("findings", "Findings"), ("fixes", "Fixes"), ("eval", "Agent evaluation"),
           ("agentsec", "Agent security"), ("shield", "Genome"), ("limits", "Can I trust this?"), ("appendix", "Files")]
    toc = "<nav class='toc'><div class='brand'>Cyphex</div>" + "".join(f"<a href='#{a}'>{_E(b)}</a>" for a, b in nav) + "</nav>"
    body = (_cover(job, st) + _summary(job, st, ids) + _scope(job) + _team(job) + _findings(job, st, ids) + _fixes(job, ids) + _eval(job, ids) + _agentsec(job) +
            f"<section id='shield'><h2><span class='n'>8</span>Genome: the runtime shield</h2>{_genome(job.get('genome'))}</section>" + _limits(job) + _appendix(job))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security assessment of {_E(_project(job))}</title>
<style>{_CSS}</style></head><body><div class="layout">{toc}<main class="sheet">{body}</main></div><script>{_JS}</script></body></html>"""


def write_report(job_id: str, out_path: str | None = None) -> str:
    job = ledger.load_job(job_id)
    p = Path(out_path) if out_path else ledger.data_dir() / job_id / "report.html"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_report(job))
    job["report_path"] = str(p)  # remember where it really went, so history can point at it
    ledger.save_job(job)
    return str(p)
