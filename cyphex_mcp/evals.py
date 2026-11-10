"""Cyphex MCP — per-agent evaluation.

Every number here is counted from what the MCP recorded. There is no composite score: a
single number would hide which agent was wrong and about what. The columns that matter:

  specialists   findings reported, how many the review board later confirmed or dismissed,
                how many an attack proved, files actually read, findings the MCP rejected
                outright (a line that does not exist)
  reviewers     ballots cast, how often the vote matched the final verdict, dissents
  patcher       fixes written and how each ended (verified, failed, could not verify)
  prober        findings tested and proven
  everyone      checks passed / failed / not measured on what it submitted, and whether it
                obeyed an instruction planted in the code (the injection test)
"""
from __future__ import annotations

from . import ledger


def _steps(job: dict, agent: str) -> list[dict]:
    return [s for s in job["steps"] if s["agent"] == agent]


def scorecards(job: dict) -> list[dict]:
    names = list(job.get("roster", {}))
    names += [s["agent"] for s in job["steps"] if s["agent"] not in names]
    canary = (job.get("agent_security") or {}).get("canary", {})
    rows = []
    for n in names:
        info = job.get("roster", {}).get(n, {})
        st = _steps(job, n)
        allc = [c for s in st for c in s["checks"]]
        role = info.get("role") or (st[0]["role"] if st else "")
        row = {"agent": n, "role": role, "model": info.get("model", "") or (st[-1].get("model", "") if st else ""),
               "tools": info.get("tools", []), "deployed": bool(info.get("deployed")), "reports": len(st),
               "checks_passed": sum(1 for c in allc if c["ok"] is True), "checks_failed": sum(1 for c in allc if c["ok"] is False),
               "checks_unmeasured": sum(1 for c in allc if c["ok"] is None), "trust": ledger.trust_of(allc) if allc else "none",
               "injection": canary.get(n), "stats": {}}
        mine = [f for f in job["findings"].values() if f.get("found_by") == n]
        if role == "deep_sast":
            decided = [f for f in mine if f.get("council")]
            row["stats"] = {
                "reported": len(mine) + sum(1 for f in job["findings"].values() if n in f.get("also_found_by", [])),
                "own": len(mine),
                "confirmed": sum(1 for f in decided if f["council"]["verdict"] == "confirmed"),
                "dismissed": sum(1 for f in decided if f["council"]["verdict"] == "rejected"),
                "proven": sum(1 for f in mine if (f.get("dast") or {}).get("proven")),
                "files_read": len(job.get("agent_files", {}).get(n, [])),
                "rejected_by_cyphex": sum(len(s["summary"].get("rejected", [])) for s in st),
            }
        elif role == "council":
            b = job.get("ballots", {}).get(n)
            if b:
                votes = b["votes"]
                agree = sum(1 for fid, v in votes.items() if job["findings"].get(fid, {}).get("council", {}).get("verdict") == ("confirmed" if v["vote"] == "confirm" else "rejected"))
                row["stats"] = {"votes": len(votes), "with_majority": agree, "dissents": len(votes) - agree, "confirms": sum(1 for v in votes.values() if v["vote"] == "confirm")}
        elif role == "patch_crew":
            wrote = [s for s in st if "diff" in s["payload"]]
            rev = [s for s in st if "review" in s["payload"]]
            if wrote:
                ends = [ledger.patch_status(job["findings"][s["payload"]["finding_id"]]) for s in wrote if s["payload"].get("finding_id") in job["findings"]]
                row["stats"] = {"fixes_written": len(wrote), "verified": ends.count("verified fixed"), "failed": ends.count("patch failed"), "unverified": ends.count("unverified") + ends.count("awaiting verify")}
            elif rev:
                row["stats"] = {"reviews": len(rev), "approved": sum(1 for s in rev if s["payload"]["review"].get("approved") is True), "rejected": sum(1 for s in rev if s["payload"]["review"].get("approved") is False)}
        elif role == "deep_dast":
            row["stats"] = {"tested": sum(s["summary"].get("tested", 0) for s in st), "proven": sum(s["summary"].get("proven", 0) for s in st)}
        elif role == "recon":
            row["stats"] = {"routes": sum(s["summary"].get("endpoints", 0) for s in st), "complete": any(s["summary"].get("complete") for s in st)}
        rows.append(row)
    return rows


def ballot_grid(job: dict) -> dict:
    """Who voted what on which finding, for the report's review-board table."""
    ballots = job.get("ballots", {})
    return {"reviewers": [{"name": r, "model": b.get("model", "")} for r, b in ballots.items()],
            "rows": [{"id": f["id"], "verdict": (f.get("council") or {}).get("verdict"),
                      "votes": {r: (b["votes"].get(f["id"]) or {}) for r, b in ballots.items()}}
                     for f in job["findings"].values()]} if ballots else {"reviewers": [], "rows": []}
