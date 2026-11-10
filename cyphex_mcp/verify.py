"""Cyphex MCP — Verify Gate.

A patch counts as fixed only if every check that can run passes AND the exploit
that worked before no longer fires on the rebuilt target. Same rules and verdicts
as the engine's gate (README "The Verify Gate"), in stdlib so the MCP carries no
heavy dependency:

  PASS          every check ran and passed
  FAIL          a check ran and failed (the host agent rolls the patch back)
  UNVERIFIABLE  nothing failed but a check could not run (no repo visible, no
                compiler installed, no exploit replay submitted) — never a PASS

The MCP never edits the repo. It applies the diff in memory, compiles the result
in a temp dir, and reports; the host agent applies the diff in its own sandbox,
rebuilds, replays the exploit and passes the outcome in as `replay`.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import ledger
from .ledger import check

BLAST_RADIUS = {"critical": 80, "high": 60, "medium": 40, "low": 30}  # max changed lines
MAX_DELETED = 0.70  # fraction of a file's non-blank lines a patch may remove
_SUPPRESS = re.compile(r"nosemgrep|eslint-disable|#\s*noqa|@ts-ignore|@ts-expect-error|noinspection|pragma:\s*no cover")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_diff(diff: str) -> dict[str, list[dict]]:
    """Unified diff -> {path: [hunk]}. Hunk ends are found by line counts, not by
    looking for the next header, so a removed line that starts with '-- ' cannot
    be mistaken for a new file header."""
    files: dict[str, list[dict]] = {}
    lines = diff.splitlines()
    i, path = 0, None
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("+++ "):
            path = re.sub(r"^b/", "", ln[4:].split("\t")[0].strip())
            files.setdefault(path, [])
        elif (m := _HUNK.match(ln)) and path:
            old_n, new_n = int(m.group(2) or 1), int(m.group(4) or 1)
            hunk = {"old_start": int(m.group(1)), "lines": []}
            i += 1
            while i < len(lines) and (old_n > 0 or new_n > 0):
                t, text = lines[i][:1], lines[i][1:]
                if t == " ":
                    old_n, new_n = old_n - 1, new_n - 1
                elif t == "-":
                    old_n -= 1
                elif t == "+":
                    new_n -= 1
                elif t != "\\":
                    break
                if t in " -+":
                    hunk["lines"].append((t, text))
                i += 1
            files[path].append(hunk)
            continue
        i += 1
    return files


def apply_hunks(orig: list[str], hunks: list[dict]) -> list[str]:
    """Strict apply: context and removed lines must match exactly or it raises."""
    out, pos = [], 0
    for n, h in enumerate(hunks, 1):
        start = max(h["old_start"] - 1, 0)
        if start < pos:
            raise ValueError(f"hunk {n} overlaps the previous one")
        out.extend(orig[pos:start])
        pos = start
        for tag, text in h["lines"]:
            if tag in " -":
                if pos >= len(orig) or orig[pos].rstrip("\r") != text.rstrip("\r"):
                    raise ValueError(f"hunk {n} does not match the file near line {pos + 1}")
                if tag == " ":
                    out.append(orig[pos])
                pos += 1
            else:
                out.append(text)
    out.extend(orig[pos:])
    return out


def _compile(rel: str, content: str):
    """True/False if a compiler ran, None if this file type or tool is unavailable."""
    suffix = Path(rel).suffix
    if suffix in (".js", ".mjs", ".cjs") and shutil.which("node"):
        cmd = ["node", "--check"]
    elif suffix == ".py":
        cmd = ["python3", "-m", "py_compile"]
    else:
        return None, f"no compiler for {suffix or 'this file'}"
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / Path(rel).name
        p.write_text(content)
        r = subprocess.run(cmd + [str(p)], capture_output=True, text=True, timeout=20)
    return r.returncode == 0, (r.stderr.strip().splitlines() or ["ok"])[-1][:200]


def verify_patch(job_id: str, finding_id: str, replay: dict | None = None) -> dict:
    job = ledger.load_job(job_id)
    f = job["findings"].get(finding_id)
    if f is None or not f.get("patch"):
        raise KeyError(f"finding {finding_id!r} has no patch submitted; call submit_result(role='patch_crew') first")
    diff = f["patch"]["diff"]
    checks: list[dict] = []
    files = parse_diff(diff)
    repo = Path(job["repo_path"]) if job.get("repo_path") and Path(job["repo_path"]).is_dir() else None

    revs = f["patch"].get("reviews") or []
    yes = sum(1 for r in revs if r.get("approved") is True)
    no = sum(1 for r in revs if r.get("approved") is False)
    checks.append(check("reviewed_by_two", False if no else (True if yes >= 2 else None),
                        f"{no} reviewer(s) rejected it" if no else (f"{yes} reviewers approved" if yes >= 2 else f"only {yes} of the 2 reviewers have approved so far")))
    changed = sum(1 for h in sum(files.values(), []) for t, _ in h["lines"] if t in "+-")
    limit = BLAST_RADIUS.get(f["severity"], 30)
    checks.append(check("blast_radius", changed <= limit, f"{changed} changed lines, limit {limit} for {f['severity']}"))
    added = [text for h in sum(files.values(), []) for t, text in h["lines"] if t == "+"]
    bad = [a.strip() for a in added if _SUPPRESS.search(a)]
    checks.append(check("no_suppression_comments", not bad, f"added suppression: {bad[:2]}" if bad else "none added"))

    if repo is None:
        for name in ("applies_cleanly", "compiles", "not_mostly_deleted"):
            checks.append(check(name, None, "repo not visible to the MCP"))
    else:
        new_files, apply_err = {}, ""
        for rel, hunks in files.items():
            p = (repo / rel).resolve()
            if rel.startswith("/") or ".." in Path(rel).parts or not p.is_file():
                apply_err = f"{rel}: not a file inside the repo"
                break
            try:
                new_files[rel] = (p.read_text().splitlines(), apply_hunks(p.read_text().splitlines(), hunks))
            except ValueError as e:
                apply_err = f"{rel}: {e}"
                break
        checks.append(check("applies_cleanly", not apply_err and bool(new_files), apply_err or f"{len(new_files)} file(s) apply"))
        if apply_err or not new_files:
            checks += [check("compiles", None, "patch did not apply"), check("not_mostly_deleted", None, "patch did not apply")]
        else:
            results = {rel: _compile(rel, "\n".join(new) + "\n") for rel, (_, new) in new_files.items()}
            ran = [r for r, _ in results.values() if r is not None]
            checks.append(check("compiles", None if not ran else all(ran),
                                "; ".join(f"{k}: {d}" for k, (_, d) in results.items())))
            worst = 0.0
            for rel, (old, new) in new_files.items():
                nonblank = sum(1 for x in old if x.strip()) or 1
                removed = sum(1 for x in old if x.strip()) - sum(1 for x in new if x.strip() and x in set(old))
                worst = max(worst, max(removed, 0) / nonblank)
            checks.append(check("not_mostly_deleted", worst <= MAX_DELETED, f"{worst:.0%} of non-blank lines removed, limit 70%"))

    # "Does not fire now" only means something if it DID fire before. A finding that was never
    # proven on the original code can be reviewed, but cannot be called verified fixed.
    proven_before = bool((f.get("dast") or {}).get("proven"))
    checks.append(check("exploit_fired_before", True if proven_before else None,
                        "exploit was proven on the original code" if proven_before else
                        "the exploit was never proven on the original code, so a clean replay shows nothing", by="agent"))
    if replay is None:
        checks.append(check("exploit_no_longer_fires", None, "no exploit replay submitted", by="agent"))
    else:
        checks.append(check("exploit_no_longer_fires", replay.get("fired") is False,
                            "reported by the agent, not re-run by Cyphex: " + (str(replay.get("evidence", ""))[:200] or "replay result"), by="agent"))

    verdict = "FAIL" if any(c["ok"] is False for c in checks) else \
        "UNVERIFIABLE" if any(c["ok"] is None for c in checks) else "PASS"
    result = {"verdict": verdict, "checks": checks, "finding_id": finding_id, "at": ledger._now()}
    f["patch"]["verify"] = result
    ledger.save_job(job)
    return result
