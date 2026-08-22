"""
CYPHEX — Verify Gate Maintainability Panel

The Verify Gate (backend/patch/verifier.py) is the single most important
guarantee in CYPHEX: a patch only counts as "fixed" if a re-scan/exploit
replay proves it. Every verdict it produces is durably recorded by
PatchManifest into <sandbox>/.cyphex/patches.json — but that state is
scattered one file per scan_id under backend/sandboxes/, with no command
that ever shows it back to a maintainer. A gate can go silently degraded
(e.g. `tsc` missing → every TS patch reads UNVERIFIABLE forever) and
nothing surfaces it outside of a single live scan's terminal output.

This module aggregates that scattered state into one maintainer-facing
health report: what the gate is configured to check, whether the tooling
each check depends on is actually present, how it has performed across
every scan CYPHEX has ever run, and what to do about it. Read-only — it
never mutates a manifest, only reads.
"""

import glob
import json
import os
from collections import Counter
from typing import Optional

from backend.patch.verifier import SUPPRESSION_PATTERNS

# backend/patch/verify_health.py -> backend/patch -> backend -> repo root
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANDBOX_ROOT = os.path.join(_REPO_ROOT, "backend", "sandboxes")

# Mirrors the severity-scaled caps applied at call sites (cli_engine.py) —
# verifier.py itself only knows the single cap it's handed per call.
SEVERITY_BLAST_CAPS = {"Critical": 80, "High": 60, "Medium": 40, "Low": 30}

# Evidence keys verifier.py writes when a check is UNVERIFIABLE (couldn't run)
# vs. genuinely FAILED (ran and found a problem) — kept separate so the panel
# can tell a maintainer "your tooling is missing" apart from "a patch was bad".
UNVERIFIABLE_REASONS = {"build_unverifiable", "rescan_unverifiable", "replay_unverifiable"}
FAILURE_REASONS = {"build_error", "suppression", "blast_radius", "structure", "rescan", "replay", "liveness"}


def _check_binary(name: str):
    """Delegate to cyphex.doctor's binary probe — same check `cyphex doctor` uses."""
    from cyphex.doctor import _check_binary as _cb
    return _cb(name)


def run_gate_selftest(timeout: float = 8.0) -> dict:
    """
    Live functional self-test — proves each Verify Gate check actually
    WORKS, not just that its binary/module is present. probe_toolchain()
    (and the doctor._check_binary it delegates to) only proves presence: a
    binary resolves on PATH, a module imports, `--version` doesn't crash.
    That is not the same guarantee — a tool can be "installed" and still be
    silently broken for what the gate needs it to do (a CLI flag renamed
    after an upgrade, run_static_analysis() raising on its first real call,
    an outbound network/firewall block). This drives each real check path
    against a tiny synthetic fixture and reports pass/fail + timing, which
    is the only way to actually catch that class of failure ahead of a
    maintainer discovering it as a wall of UNVERIFIABLE verdicts.
    """
    import subprocess
    import tempfile
    import time as _time

    results = {}

    # ── py_compile: proves the build check both accepts good code and
    #    rejects bad code, not just that the stdlib module imports. ──
    t0 = _time.time()
    try:
        import py_compile
        with tempfile.TemporaryDirectory() as td:
            good = os.path.join(td, "good.py")
            with open(good, "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            py_compile.compile(good, doraise=True)

            bad = os.path.join(td, "bad.py")
            with open(bad, "w", encoding="utf-8") as f:
                f.write("def f(:\n")
            caught = False
            try:
                py_compile.compile(bad, doraise=True)
            except py_compile.PyCompileError:
                caught = True
        results["py_compile"] = {
            "ok": caught,
            "detail": "compiles valid code, rejects invalid syntax" if caught
                      else "did not reject invalid syntax — build check may be broken",
            "duration_ms": round((_time.time() - t0) * 1000),
        }
    except Exception as e:
        results["py_compile"] = {"ok": False, "detail": f"self-test crashed: {e}",
                                  "duration_ms": round((_time.time() - t0) * 1000)}

    # ── tsc: only meaningful if tsc is actually on PATH. ──
    t0 = _time.time()
    tsc_ok, _ = _check_binary("tsc")
    if not tsc_ok:
        results["tsc"] = {"ok": None, "detail": "tsc not installed — self-test skipped", "duration_ms": 0}
    else:
        try:
            # tsc resolves to a tsc.cmd shim on Windows — non-shell
            # subprocess can't launch a bare "tsc" there even though
            # _check_binary() above already confirmed it's on PATH. Same
            # bug (and same fix) as backend/patch/applier.py's real check.
            from backend.platform_compat import resolve_binary_cmd
            tsc_cmd = resolve_binary_cmd("tsc")
            with tempfile.TemporaryDirectory() as td:
                bad_ts = os.path.join(td, "bad.ts")
                with open(bad_ts, "w", encoding="utf-8") as f:
                    f.write("const x: number = 'not a number';\n")
                proc = subprocess.run(
                    [tsc_cmd, "--noEmit", "--strict", bad_ts],
                    capture_output=True, text=True, timeout=timeout, cwd=td,
                )
                caught = proc.returncode != 0
            results["tsc"] = {
                "ok": caught,
                "detail": "correctly flags a known type error" if caught
                          else "did not flag a known type error — TS build check may be broken",
                "duration_ms": round((_time.time() - t0) * 1000),
            }
        except (FileNotFoundError, OSError) as e:
            # Distinguish "couldn't even launch tsc" from "tsc ran and
            # something else went wrong" — the former reads to a maintainer
            # as a subprocess-invocation bug, not a broken TypeScript
            # install, and misreporting it as "crashed" sent Windows
            # maintainers chasing a nonexistent TS problem before this fix.
            results["tsc"] = {"ok": False,
                               "detail": f"tsc found but could not be launched via subprocess ({e}) "
                                         "— this is a platform invocation issue, not a TypeScript problem",
                               "duration_ms": round((_time.time() - t0) * 1000)}
        except Exception as e:
            results["tsc"] = {"ok": False, "detail": f"self-test crashed: {e}",
                               "duration_ms": round((_time.time() - t0) * 1000)}

    # ── static_scanner: run the REAL scanner against a known-vulnerable
    #    fixture — proves both that it imports AND that a scan actually
    #    finds what it should (the thing _rescan_file depends on). ──
    t0 = _time.time()
    try:
        import cyphex.scanner as _scanner
        with tempfile.TemporaryDirectory() as td:
            vuln_file = os.path.join(td, "vuln.py")
            with open(vuln_file, "w", encoding="utf-8") as f:
                f.write(
                    "def get_user(conn, user_id):\n"
                    "    cur = conn.cursor()\n"
                    "    return cur.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
                )
            findings = _scanner.run_static_analysis(td)
            found = bool(findings)
        results["static_scanner"] = {
            "ok": found,
            "detail": f"detected {len(findings) if findings else 0} finding(s) in a known-vulnerable fixture"
                      if found else "found nothing in a known-vulnerable fixture — rescan matching may be broken",
            "duration_ms": round((_time.time() - t0) * 1000),
        }
    except Exception as e:
        results["static_scanner"] = {"ok": False, "detail": f"self-test crashed: {e}",
                                      "duration_ms": round((_time.time() - t0) * 1000)}

    # ── httpx: proves the client actually constructs and that the
    #    connection-error path (what exploit-replay depends on when a
    #    target is unreachable) doesn't hang or crash. ──
    t0 = _time.time()
    try:
        import httpx
        try:
            httpx.get("http://127.0.0.1:1", timeout=0.5)
        except Exception:
            pass  # a refused/failed connection IS the expected, healthy outcome here
        results["httpx"] = {
            "ok": True,
            "detail": "client constructs and handles a closed-port connection cleanly "
                      "(exploit-replay error path verified)",
            "duration_ms": round((_time.time() - t0) * 1000),
        }
    except Exception as e:
        results["httpx"] = {"ok": False, "detail": f"self-test crashed: {e}",
                             "duration_ms": round((_time.time() - t0) * 1000)}

    return results


def probe_toolchain() -> dict:
    """
    Live-check every external dependency a Verify Gate check needs to run at
    all. This is what actually explains a run of UNVERIFIABLE verdicts —
    verifier.py returns None (never a silent PASS) whenever one of these is
    missing, but until now nothing told a maintainer *why*.
    """
    node_ok, node_v = _check_binary("node")
    tsc_ok, tsc_v = _check_binary("tsc")

    try:
        import cyphex.scanner  # noqa: F401
        scanner_ok, scanner_v = True, "importable"
    except Exception as e:
        scanner_ok, scanner_v = False, f"import failed: {e}"

    try:
        import httpx  # noqa: F401
        httpx_ok, httpx_v = True, "installed"
    except Exception:
        httpx_ok, httpx_v = False, "not installed"

    return {
        "node":           {"ok": node_ok,    "version": node_v,    "gates": "JS/JSX build check"},
        "tsc":             {"ok": tsc_ok,     "version": tsc_v,     "gates": "TS/TSX build check"},
        "py_compile":      {"ok": True,       "version": "stdlib",  "gates": "Python build check"},
        "static_scanner":  {"ok": scanner_ok, "version": scanner_v, "gates": "static re-scan (finding_gone)"},
        "httpx":           {"ok": httpx_ok,   "version": httpx_v,   "gates": "dynamic exploit replay"},
    }


def discover_manifests(target_dir: Optional[str] = None) -> list:
    """
    Find every .cyphex/patches.json the Verify Gate has ever written.

    target_dir: check just this one directory (e.g. a specific scan's
    sandbox, or a repo you know was scanned in place). Omit to sweep every
    sandbox CYPHEX has run under backend/sandboxes/ — the common case for a
    maintainer asking "how healthy is verification across everything CYPHEX
    has done so far".
    """
    if target_dir:
        p = os.path.join(target_dir, ".cyphex", "patches.json")
        return [p] if os.path.isfile(p) else []

    if not os.path.isdir(SANDBOX_ROOT):
        return []
    paths = glob.glob(os.path.join(SANDBOX_ROOT, "*", ".cyphex", "patches.json"))
    return sorted(paths, key=os.path.getmtime, reverse=True)


def _load_entries(manifest_paths: list) -> list:
    """
    Read every manifest as raw JSON rather than through PatchManifest,
    because two schemas exist on disk: the current flat
    {"file:line:cwe": {...}} map PatchManifest writes now, and an older
    {"version": 1, "updated_at": ..., "patches": [...]} wrapper from earlier
    CYPHEX builds. PatchManifest itself has no migration path for the old
    shape — pointing it at one leaves self.entries holding the wrapper dict
    itself, so iterating .values() yields an int/str/list instead of an
    entry dict and crashes the first .get() call downstream. Normalizing
    both shapes here means old scan history is reported, not silently
    dropped or crashed on.
    """
    entries = []
    for p in manifest_paths:
        source_dir = os.path.dirname(os.path.dirname(p))  # strip "/.cyphex/patches.json"
        scan_name = os.path.basename(source_dir)
        try:
            with open(p, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            continue

        if isinstance(raw, dict) and isinstance(raw.get("patches"), list):
            # Legacy schema: entries live in a "patches" list, keyed file field is "rel_path".
            for e in raw["patches"]:
                if not isinstance(e, dict):
                    continue
                e = dict(e)
                e.setdefault("file", e.get("rel_path", "?"))
                e["_scan_dir"] = scan_name
                e["_legacy_schema"] = True
                entries.append(e)
            continue

        if isinstance(raw, dict):
            # Current schema: flat map of "file:line:cwe" -> entry dict.
            for e in raw.values():
                if not isinstance(e, dict):
                    continue
                e = dict(e)
                e["_scan_dir"] = scan_name
                entries.append(e)

    return entries


def _build_next_steps(toolchain: dict, reason_tally: Counter, manifests_found: int,
                       legacy_count: int = 0) -> list:
    steps = []
    if legacy_count:
        steps.append(f"{legacy_count} patch record(s) come from a pre-v1 manifest schema "
                      "({\"version\", \"patches\": [...]}) that PatchManifest can't load directly — "
                      "reported here by reading the raw JSON, but is_already_patched()'s cache lookup "
                      "won't see them. Migrate old backend/sandboxes/*/.cyphex/patches.json files to "
                      "the current flat-map schema, or accept the cache miss on re-scans of those targets.")
    if not toolchain["tsc"]["ok"]:
        steps.append("Install TypeScript (`npm install -g typescript`) — TS/TSX patches currently "
                      "verify as UNVERIFIABLE, not PASS, because the build check can't run.")
    if not toolchain["node"]["ok"]:
        steps.append("Install Node.js — JS/JSX build checks can't run without it.")
    if not toolchain["static_scanner"]["ok"]:
        steps.append(f"`cyphex.scanner` won't import ({toolchain['static_scanner']['version']}) — "
                      "every static re-scan check is UNVERIFIABLE until this is fixed.")
    if not toolchain["httpx"]["ok"]:
        steps.append("`pip install httpx` — dynamic exploit-replay verification is fully disabled without it.")

    if reason_tally.get("blast_radius", 0):
        steps.append(f"{reason_tally['blast_radius']} patch(es) exceeded the blast-radius cap and were "
                      "rolled back — review those CWEs for an oversized fix strategy.")
    if reason_tally.get("structure", 0):
        steps.append(f"{reason_tally['structure']} patch(es) deleted a route/function/class declaration "
                      "and were rolled back — check backend/patch/structure.py's false-negative rate.")
    if reason_tally.get("suppression", 0):
        steps.append(f"{reason_tally['suppression']} patch(es) added a scanner-suppression comment and "
                      "were rejected — a model is trying to game the scanner instead of fixing the bug.")

    if not manifests_found:
        steps.append("No .cyphex/patches.json manifest found yet — run a scan with patching enabled "
                      "(`cyphex scan <target>`) to generate Verify Gate history.")
    if not steps:
        steps.append("Verify Gate is fully operable and no failure pattern stands out — nothing to action.")
    return steps


def _build_cwe_breakdown(entries: list, top_n: int = 8) -> list:
    """Per-CWE verdict tally + durability rate, most-attempted CWE first."""
    by_cwe = {}
    for e in entries:
        by_cwe.setdefault(e.get("cwe") or "?", Counter())[e.get("verdict", "?")] += 1
    rows = []
    for cwe, counts in by_cwe.items():
        total = sum(counts.values())
        passed = counts.get("PASS", 0)
        rows.append({
            "cwe": cwe, "total": total, "pass": passed,
            "fail": counts.get("FAIL", 0), "unverifiable": counts.get("UNVERIFIABLE", 0),
            "durability_rate": (passed / total * 100.0) if total else 0.0,
        })
    rows.sort(key=lambda r: -r["total"])
    return rows[:top_n]


def _build_scan_trend(manifest_paths: list, entries: list, limit: int = 10) -> list:
    """
    Durability rate per scan, oldest of the last `limit` scans first (a
    left-to-right trend line). Scan order comes from manifest_paths (already
    mtime-sorted newest-first by discover_manifests) rather than from
    entries' own patched_at sort, since entries from many scans interleave
    once flattened and can't reconstruct a clean per-scan chronology on
    their own.
    """
    scan_order, seen = [], set()
    for p in manifest_paths:
        name = os.path.basename(os.path.dirname(os.path.dirname(p)))
        if name not in seen:
            seen.add(name)
            scan_order.append(name)

    by_scan = {}
    for e in entries:
        by_scan.setdefault(e.get("_scan_dir", "?"), Counter())[e.get("verdict", "?")] += 1

    rows = []
    for name in reversed(scan_order[:limit]):
        counts = by_scan.get(name, Counter())
        total = sum(counts.values())
        passed = counts.get("PASS", 0)
        rows.append({"scan": name, "total": total,
                      "durability_rate": (passed / total * 100.0) if total else 0.0})
    return rows


def compute_gate_exit_code(report: dict, min_durability: float = 70.0) -> int:
    """
    CI-friendly verdict for `cyphex verify --ci`:
      0 = healthy    — durability at/above threshold, no bare FAILs
      1 = degraded   — durability below threshold, or at least one FAIL verdict
      2 = unusable   — no scan history yet, or a required check (py_compile,
                        static_scanner) can't run at all
    Mirrors the exact thresholds render_verify_health() uses for its GATE
    HEALTHY/DEGRADED/UNUSED lamp, so the terminal panel and a CI gate can
    never disagree about gate health.
    """
    if not report["manifests_found"]:
        return 2
    toolchain = report["config"]["toolchain"]
    if not toolchain["static_scanner"]["ok"] or not toolchain["py_compile"]["ok"]:
        return 2
    if report["durability_rate"] < min_durability:
        return 1
    if report["verdicts"].get("FAIL", 0) > 0:
        return 1
    return 0


def get_verify_health(target_dir: Optional[str] = None, limit: int = 8,
                       include_selftest: bool = False) -> dict:
    """
    Build the full maintainer health report for the Verify Gate.

    Returns a dict of:
      config       — blast-radius caps, tracked suppression patterns, live toolchain probe
      manifests_found / total_patches — how much history was found and aggregated
      verdicts     — {"PASS": n, "FAIL": n, "UNVERIFIABLE": n}
      durability_rate — % of all recorded patches that are durably PASS-verified
      reason_tally — evidence-key counts across every entry (why things failed/couldn't be checked)
      cwe_breakdown — per-CWE verdict tally + durability rate, most-attempted first
      trend        — durability rate per scan, oldest-of-the-recent-N first
      recent       — the `limit` most recent patch attempts, newest first
      next_steps   — concrete, actionable maintainer guidance derived from the above
      selftest     — present only when include_selftest=True: live functional
                      self-test results (see run_gate_selftest())
    """
    manifest_paths = discover_manifests(target_dir)
    entries = _load_entries(manifest_paths)

    verdicts = Counter(e.get("verdict", "?") for e in entries)
    reason_tally = Counter()
    for e in entries:
        for reason in (e.get("evidence") or {}):
            reason_tally[reason] += 1

    entries.sort(key=lambda e: e.get("patched_at", ""), reverse=True)
    total = len(entries)
    verified = verdicts.get("PASS", 0)
    durability_rate = (verified / total * 100.0) if total else 0.0
    legacy_count = sum(1 for e in entries if e.get("_legacy_schema"))

    toolchain = probe_toolchain()

    report = {
        "config": {
            "blast_radius_caps": SEVERITY_BLAST_CAPS,
            "suppression_patterns_tracked": len(SUPPRESSION_PATTERNS),
            "toolchain": toolchain,
        },
        "manifests_found": len(manifest_paths),
        "total_patches": total,
        "verdicts": dict(verdicts),
        "durability_rate": durability_rate,
        "reason_tally": dict(reason_tally),
        "cwe_breakdown": _build_cwe_breakdown(entries),
        "trend": _build_scan_trend(manifest_paths, entries),
        "recent": entries[:limit],
        "next_steps": _build_next_steps(toolchain, reason_tally, len(manifest_paths), legacy_count),
    }
    if include_selftest:
        report["selftest"] = run_gate_selftest()
    return report


def print_plain(report: dict) -> None:
    """Dependency-free fallback report (used when terminal_ui/Rich is unavailable)."""
    total = report["total_patches"]
    print(f"\n  CYPHEX Verify Gate — Maintainability Panel")
    print(f"  {report['manifests_found']} scan manifest(s)  |  {total} patch attempt(s) recorded\n")

    print("  Configuration:")
    caps = report["config"]["blast_radius_caps"]
    print("    blast-radius cap   " + "  ".join(f"{sev} {n}" for sev, n in caps.items()))
    print(f"    suppression guards {report['config']['suppression_patterns_tracked']} patterns tracked")
    print("    toolchain readiness:")
    for name, info in report["config"]["toolchain"].items():
        mark = "OK" if info["ok"] else "MISSING"
        print(f"      [{mark:<7}] {name:<15} {info['version'][:40]:<42} gates: {info['gates']}")

    if report.get("selftest"):
        print("\n  Live self-test (functional, not just presence):")
        for name, info in report["selftest"].items():
            mark = "OK" if info["ok"] else ("SKIP" if info["ok"] is None else "FAIL")
            print(f"      [{mark:<5}] {name:<15} {info['detail'][:70]:<72} {info['duration_ms']}ms")

    print("\n  Status:")
    if total:
        v = report["verdicts"]
        print(f"    {report['durability_rate']:.1f}% durable-verified")
        print(f"    PASS {v.get('PASS', 0)}   FAIL {v.get('FAIL', 0)}   "
              f"UNVERIFIABLE {v.get('UNVERIFIABLE', 0)}")
        if report["reason_tally"]:
            print("    why (evidence key -> count):")
            for reason, n in sorted(report["reason_tally"].items(), key=lambda kv: -kv[1])[:8]:
                print(f"      {reason:<22}{n}")
        if report.get("cwe_breakdown"):
            print("    by CWE:")
            for row in report["cwe_breakdown"]:
                print(f"      {row['cwe']:<10}{row['durability_rate']:5.1f}% durable   "
                      f"(PASS {row['pass']} / FAIL {row['fail']} / UNVERIFIABLE {row['unverifiable']})")
        if report.get("trend"):
            print("    trend (oldest -> newest scan):")
            print("      " + "  ".join(f"{r['durability_rate']:.0f}%" for r in report["trend"]))
        if report["recent"]:
            print("    recent verifications:")
            for e in report["recent"][:6]:
                print(f"      {e.get('verdict', '?'):<13}{e.get('cwe', '?'):<9}"
                      f"{e.get('file', '?')}:{e.get('line', '?')}")
    else:
        print("    no patch history yet — run a scan with patching enabled")

    print("\n  Next steps:")
    for step in report["next_steps"]:
        print(f"    -> {step}")
    print()
