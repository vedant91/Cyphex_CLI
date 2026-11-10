"""Deterministic live-attack stage.

The attack stage does NOT ask a model to author exploits. It runs Nuclei — a standard third-party
scanner with its own template database — from inside the sandbox, and this module parses what Nuclei
reports. No Claude model writes attack payloads, so the work is a tool run, not model-authored
offensive content. The proof is measured by the scanner, which is also more credible than a model's
word. Findings a scanner cannot reach stay "confirmed by code reading"; the report already says which
is which.

`recipe()` returns the exact command for the host to run; `ingest()` turns the scanner's JSONL into
the same confirmations shape the deep_dast grader already expects, matched to findings by route.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

_SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# the same safe, generic tag set the CLI uses: detection/misconfig, not CVE fingerprint floods
_TAGS = "exposure,misconfig,default-login,sqli,xss,lfi,ssrf,rce,redirect"
_FLAGS = ["-jsonl", "-silent", "-duc", "-ni", "-rate-limit", "30", "-timeout", "8", "-retries", "0", "-no-color"]


def recipe(target_url: str, compose_file: str = "", attacker_service: str = "attacker") -> dict:
    """The command the host runs to attack the sandbox. It runs a scanner; it authors nothing."""
    args = ["nuclei", "-u", target_url, "-severity", "critical,high,medium,low", "-tags", _TAGS, *_FLAGS]
    inner = " ".join(args)
    cmd = f"docker compose -f {compose_file} exec -T {attacker_service} {inner}" if compose_file else inner
    return {
        "command": cmd,
        "tool": "nuclei",
        "why_deterministic": ("This stage runs Nuclei, a standard scanner, from inside the sandbox. No model writes "
                              "attack requests, so there is nothing for a safety classifier to flag. Nuclei needs to be "
                              "installed in the attacker image (add `RUN go install .../nuclei@latest` or copy the binary)."),
        "then": "Pass the scanner's full JSONL output to submit_dast(job_id, nuclei_jsonl). The MCP parses it and marks proof itself.",
        "say": "The live-attack stage runs Nuclei (a standard scanner) against the app in the sandbox. No model writes the attacks, so this stage is not blocked.",
    }


def _path(url: str) -> str:
    try:
        return urlparse(url).path or ""
    except ValueError:
        return ""


def parse(jsonl: str) -> list[dict]:
    """Nuclei -jsonl output -> one dict per real hit (Info severity dropped, as the CLI does)."""
    hits = []
    for line in (jsonl or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        info = r.get("info") or {}
        sev = str(info.get("severity", "")).lower()
        if sev == "info" or not sev:
            continue
        raw = (info.get("classification") or {}).get("cwe-id") or []
        cwe = raw[0] if isinstance(raw, list) and raw else (raw if isinstance(raw, str) else "")
        if cwe and not str(cwe).upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        url = r.get("matched-at") or r.get("host") or ""
        extracted = r.get("extracted-results")
        matcher = r.get("matcher-name") or (extracted[0] if isinstance(extracted, list) and extracted else "")
        hits.append({
            "template": r.get("template-id", ""),
            "name": info.get("name", r.get("template-id", "")),
            "severity": sev,
            "cwe": str(cwe).upper(),
            "url": url,
            "path": _path(url),
            "curl": r.get("curl-command", ""),
            "matcher": matcher,
        })
    return hits


def _routes(finding: dict) -> set[str]:
    """Route paths a finding talks about, so a scanner hit on that path can be tied to it."""
    text = " ".join(str(finding.get(k, "")) for k in ("why", "snippet", "file"))
    return set(re.findall(r"/[A-Za-z0-9_./:-]{2,}", text))


def ingest(job: dict, jsonl: str) -> dict:
    """Turn scanner output into deep_dast confirmations, matched to findings by route.

    Returns {confirmations, hits, matched, unmatched}. confirmations is the exact shape
    _grade_dast expects: [{id, proven, evidence}]. Only hits that land on a known route
    become proof for that finding; the rest are reported as extra scanner findings.
    """
    hits = parse(jsonl)
    findings = list(job.get("findings", {}).values())
    routes = {f["id"]: _routes(f) for f in findings}
    conf, used = {}, set()
    for h in hits:
        p = h["path"]
        if not p or p == "/":
            continue
        for fid, rs in routes.items():
            if any(p == r or p.startswith(r + "/") for r in rs):
                used.add(id(h))
                ev = f"nuclei {h['template']} ({h['severity']}) hit {h['url']}" + (f" — {h['curl']}" if h["curl"] else "")
                prev = conf.get(fid)
                if not prev or _SEV.get(h["severity"], 0) > prev[1]:  # keep the worst hit's evidence
                    conf[fid] = (ev, _SEV.get(h["severity"], 0))
    confirmations = [{"id": fid, "proven": True, "evidence": ev} for fid, (ev, _) in conf.items()]
    unmatched = [h for h in hits if id(h) not in used]
    return {"confirmations": confirmations, "hits": hits, "matched": len(confirmations), "unmatched": unmatched}
